#!/usr/bin/env bash
set -euo pipefail

export GOTOOLCHAIN=local
export GOPROXY=off

go test ./modules/caddyhttp/caddyauth \
  -run '^TestAuthenticationProvidersIsolateFailedResponses$' \
  -count=1
