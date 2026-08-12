package caddyauth

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type regressionWritingAuthenticator struct {
	authed bool
	write  func(http.ResponseWriter)
}

func (a regressionWritingAuthenticator) Authenticate(w http.ResponseWriter, _ *http.Request) (User, bool, error) {
	if a.write != nil {
		a.write(w)
	}
	return User{ID: "user"}, a.authed, nil
}

func runRegressionAuth(t *testing.T, providers map[string]Authenticator) (*httptest.ResponseRecorder, error) {
	t.Helper()
	auth := Authentication{Providers: providers, logger: zap.NewNop()}
	req, _ := newRequestWithReplacer()
	rec := httptest.NewRecorder()
	err := auth.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	return rec, err
}

func TestAuthenticationProvidersIsolateFailedResponses(t *testing.T) {
	providers := map[string]Authenticator{
		"failed": regressionWritingAuthenticator{write: func(w http.ResponseWriter) {
			w.Header().Set("Location", "/login")
			w.Header().Set("X-Failed", "must-not-leak")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("failed body"))
		}},
		"success": regressionWritingAuthenticator{authed: true, write: func(w http.ResponseWriter) {
			w.Header().Set("Set-Cookie", "session=public; Path=/")
		}},
	}

	for i := 0; i < 200; i++ {
		rec, err := runRegressionAuth(t, providers)
		if err != nil {
			t.Fatalf("iteration %d: ServeHTTP() error = %v", i, err)
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("iteration %d: status = %d, want 204", i, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "" {
			t.Fatalf("iteration %d: failed Location leaked: %q", i, got)
		}
		if got := rec.Header().Get("X-Failed"); got != "" {
			t.Fatalf("iteration %d: failed header leaked: %q", i, got)
		}
		if got := rec.Header().Get("Set-Cookie"); got != "session=public; Path=/" {
			t.Fatalf("iteration %d: successful provider cookie = %q", i, got)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("iteration %d: failed body leaked: %q", i, rec.Body.String())
		}
	}
}

func TestAuthenticationRedirectChallengeTakesPrecedence(t *testing.T) {
	providers := map[string]Authenticator{
		"plain": regressionWritingAuthenticator{write: func(w http.ResponseWriter) {
			w.Header().Set("WWW-Authenticate", `Basic realm="public"`)
			w.WriteHeader(http.StatusUnauthorized)
		}},
		"redirect": regressionWritingAuthenticator{write: func(w http.ResponseWriter) {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusTemporaryRedirect)
			_, _ = w.Write([]byte("redirect"))
		}},
	}

	for i := 0; i < 100; i++ {
		rec, err := runRegressionAuth(t, providers)
		if err != nil {
			t.Fatalf("iteration %d: expected redirect response, got %v", i, err)
		}
		if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "/login" {
			t.Fatalf("iteration %d: status=%d Location=%q", i, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestAuthenticationHeaderOnlyChallengeReturnsUnauthorized(t *testing.T) {
	providers := map[string]Authenticator{
		"basic": regressionWritingAuthenticator{write: func(w http.ResponseWriter) {
			w.Header().Set("WWW-Authenticate", `Basic realm="public"`)
		}},
		"silent": regressionWritingAuthenticator{},
	}

	rec, err := runRegressionAuth(t, providers)
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %v, want 401 HandlerError", err)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="public"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

type regressionCapabilityWriter struct {
	http.ResponseWriter
	flushed bool
}

func (w *regressionCapabilityWriter) Flush() { w.flushed = true }

func (w *regressionCapabilityWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	client, server := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func (w *regressionCapabilityWriter) Push(string, *http.PushOptions) error { return nil }

func (w *regressionCapabilityWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w.ResponseWriter, r)
}

type regressionReader struct{ io.Reader }

func TestAuthenticationMultipleProvidersPreserveWriterCapabilities(t *testing.T) {
	const bodySize = 2 << 20
	var flusher, hijacker, pusher, readerFrom bool
	probe := regressionWritingAuthenticator{write: func(w http.ResponseWriter) {
		_, flusher = w.(http.Flusher)
		_, hijacker = w.(http.Hijacker)
		_, pusher = w.(http.Pusher)
		rf, ok := w.(io.ReaderFrom)
		readerFrom = ok
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush() error = %v", err)
		}
		w.Header().Set("Location", "/large-login")
		w.WriteHeader(http.StatusTemporaryRedirect)
		if ok {
			_, _ = rf.ReadFrom(regressionReader{Reader: strings.NewReader(strings.Repeat("x", bodySize))})
		}
	}}

	auth := Authentication{
		Providers: map[string]Authenticator{
			"probe": probe,
			"other": regressionWritingAuthenticator{},
		},
		logger: zap.NewNop(),
	}
	req, _ := newRequestWithReplacer()
	recorder := httptest.NewRecorder()
	realWriter := &regressionCapabilityWriter{ResponseWriter: recorder}
	err := auth.ServeHTTP(realWriter, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	for name, ok := range map[string]bool{
		"http.Flusher":  flusher,
		"http.Hijacker": hijacker,
		"http.Pusher":   pusher,
		"io.ReaderFrom": readerFrom,
	} {
		if !ok {
			t.Errorf("isolated writer does not preserve %s", name)
		}
	}
	if realWriter.flushed {
		t.Error("tentative Flush reached the real writer")
	}
	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", recorder.Code)
	}
	if recorder.Body.Len() == 0 || recorder.Body.Len() > 1<<20 {
		t.Fatalf("buffered body size = %d, want 1..%d", recorder.Body.Len(), 1<<20)
	}
}

func TestAuthenticationSingleProviderReceivesRealWriter(t *testing.T) {
	var gotReal bool
	provider := regressionWritingAuthenticator{authed: true, write: func(w http.ResponseWriter) {
		_, gotReal = w.(*regressionCapabilityWriter)
		w.(http.Flusher).Flush()
	}}
	auth := Authentication{
		Providers: map[string]Authenticator{"only": provider},
		logger:    zap.NewNop(),
	}
	req, _ := newRequestWithReplacer()
	realWriter := &regressionCapabilityWriter{ResponseWriter: httptest.NewRecorder()}
	err := auth.ServeHTTP(realWriter, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !gotReal || !realWriter.flushed {
		t.Fatalf("single provider did not receive the real writer: gotReal=%v flushed=%v", gotReal, realWriter.flushed)
	}
}
