# 修复多认证提供者的响应相互污染问题

请修改 Caddy 的认证中间件，相关代码位于：

`modules/caddyhttp/caddyauth`

## 问题

配置多个认证提供者时，它们共用真实的 `http.ResponseWriter`。如果某个提供者
认证失败，但已经写入响应状态、响应头或响应体，这些内容可能污染后续成功
提供者的响应。提供者存放在 map 中，遍历顺序不固定，因此问题表现不稳定。

## 建议实现方向

1. 只有零个或一个提供者时，继续把真实的 `ResponseWriter` 传给提供者，保持
   原有行为不变。
2. 有多个提供者时，为每次 `Authenticate` 调用创建独立的临时
   `ResponseWriter`：使用独立的 Header map，记录状态，并有限地缓存响应体。
3. 提供者认证成功时，丢弃临时状态和响应体，只把成功提供者写入的响应头复制
   到真实 writer，然后继续执行下游处理器。
4. 提供者认证失败时，先保存它的临时响应，不要立即写入真实 writer。
5. 所有提供者都失败时，优先回放 3xx 重定向挑战；如果只有
   `WWW-Authenticate` 等响应头而没有状态，则复制响应头并返回正常的 401
   `HandlerError`。

## ResponseWriter 能力

请检查 `modules/caddyhttp/responsewriter.go`，可以复用或参考现有的
`caddyhttp.ResponseWriterWrapper`。

多提供者场景中的临时 writer 需要保留底层已有的这些能力：

- `http.Flusher`
- `http.Hijacker`
- `http.Pusher`
- `io.ReaderFrom`
- `http.ResponseController` 使用的能力

注意：

- 临时响应期间的 Flush 必须被抑制，不能提前提交真实响应。
- `ReaderFrom` 必须写入有限缓冲区，不能绕过隔离直接写入真实 writer。
- 不要只依靠 `Unwrap` 代替普通接口实现，因为提供者可能直接进行
  `w.(http.Flusher)`、`w.(http.Hijacker)` 等类型断言。
- 临时响应体必须有固定大小上限，超过上限后不能继续增长内存。

## 验证

请先复现测试失败，再完成修复。完成后运行：

```text
./verify.sh
go test ./modules/caddyhttp/caddyauth -count=1
go test -race ./modules/caddyhttp/caddyauth -count=1
go vet ./modules/caddyhttp/caddyauth
```

最后检查 `git diff` 和 `git status`，并简要说明修改内容和测试结果。
