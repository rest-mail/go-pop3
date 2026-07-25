# go-pop3

[![CI](https://github.com/rest-mail/go-pop3/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-pop3/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-pop3.svg)](https://pkg.go.dev/github.com/rest-mail/go-pop3)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-pop3)](https://goreportcard.com/report/github.com/rest-mail/go-pop3)

A POP3 ([RFC 1939](https://www.rfc-editor.org/rfc/rfc1939)) server engine for Go
— standard library only, no external dependencies.

## About

POP3 lets a client download and delete mail from a single maildrop. This package
is the server half: you implement a small `Backend` that authenticates users and
exposes each user's maildrop, and the engine speaks the wire protocol on top of
it — greeting, capability negotiation, TLS, authentication, listing, retrieval
and deletion.

The engine holds no assumptions about where mail is stored. A `Backend` returns
messages as neutral `Message` values and their raw RFC 5322 bytes on demand, so
the store can be a database, a maildir on disk, or a remote API — the protocol
code never knows the difference. Message bodies are served **byte-for-byte** as
`Mailbox.Retrieve` returns them, with RFC 1939 dot-stuffing applied on the wire,
so what the client downloads is exactly what you stored.

## Features

- Full RFC 1939 command set: `USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`,
  `TOP`, `DELE`, `RSET`, `NOOP` and `QUIT`.
- STARTTLS via `STLS` ([RFC 2595](https://www.rfc-editor.org/rfc/rfc2595)) on the
  plaintext port, and implicit TLS on the secure port — both from one
  `*tls.Config`.
- Credentials are never sent in the clear: when TLS is configured, `USER` is
  refused until the connection is secured.
- `CAPA` capability advertisement ([RFC 2449](https://www.rfc-editor.org/rfc/rfc2449)):
  `USER`, `STLS`, `TOP`, `UIDL`, `RESP-CODES`, `PIPELINING`.
- Storage-agnostic `Backend`/`Mailbox` seam — mail can live anywhere.
- Deferred deletes with correct RFC 1939 update state: `DELE` marks, `QUIT`
  commits, `RSET` unmarks.
- On-the-wire dot-stuffing for `RETR`/`TOP`, keyed on the real message UID.
- A `MarkSeen` hook fired on the first `RETR` of a message, since POP3 has no
  read state of its own.
- Pluggable per-IP `Limiter` for connection caps and auth-failure bans;
  `NopLimiter` (the default) imposes none.
- Graceful shutdown that drains in-flight sessions.
- Zero external dependencies.

## Install

```sh
go get github.com/rest-mail/go-pop3
```

## Quickstart

Implement `Backend` and `Mailbox`, then hand the server a listener config. This
is the production shape — `ListenAndServe` binds real ports, so it is shown here
rather than as an executed example (see the runnable `Example` in the docs for a
self-contained transcript over an in-memory pipe).

```go
package main

import (
	"crypto/tls"

	pop3 "github.com/rest-mail/go-pop3"
)

// store is your mail store. Authenticate returns a Mailbox scoped to the user.
type store struct{ /* db handle, etc. */ }

func (s *store) Authenticate(user, pass string) (pop3.Mailbox, error) {
	// verify credentials, then return the user's maildrop view
	return &maildrop{ /* ... */ }, nil
}

type maildrop struct{ /* ... */ }

func (m *maildrop) Messages() ([]pop3.Message, error) {
	// oldest-first; UID must be stable, Size is the STAT/LIST octet count
	return []pop3.Message{
		{UID: "1001", Size: 4213, Seen: false},
		{UID: "1002", Size: 1198, Seen: true},
	}, nil
}

func (m *maildrop) Retrieve(uid string) ([]byte, error) { /* full RFC 5322 bytes */ return nil, nil }
func (m *maildrop) MarkSeen(uid string) error           { /* after RETR */ return nil }
func (m *maildrop) Delete(uid string) error             { /* on QUIT */ return nil }

func main() {
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// nil Limiter -> pop3.NopLimiter (no per-IP limits).
	srv := pop3.NewServer(&store{}, tlsConfig, nil)
	if err := srv.ListenAndServe(pop3.Ports{POP3: 110, POP3TLS: 995}); err != nil {
		panic(err)
	}
	select {} // serve until srv.Shutdown(ctx) or srv.Close()
}
```

## Backend

You implement three interfaces:

- **`Backend`** — `Authenticate(user, pass)` validates the `USER`/`PASS`
  credentials and returns the `Mailbox` for that user, or a non-nil error to
  reject the login.
- **`Mailbox`** — one authenticated maildrop. `Messages()` returns its contents
  oldest-first (called once, right after login); `Retrieve(uid)` returns the raw
  message bytes; `MarkSeen(uid)` and `Delete(uid)` apply side effects.
- **`Message`** — a maildrop entry: its `UID` (what the client sees via `UIDL`
  and what the engine passes back to `Retrieve`/`MarkSeen`/`Delete`), its `Size`
  in octets for `STAT`/`LIST`, and whether it is already `Seen`.

A message's slice position (+1) in the `Messages()` result is the POP3 message
number the client uses for the rest of the session; the engine translates
between those numbers and your stable `UID`s.

## Server

`NewServer(backend, tlsConfig, limiter)` builds a `Server`. `ListenAndServe`
opens the plaintext and implicit-TLS listeners named by `Ports` (a zero port is
skipped) and returns immediately, serving connections in the background.
`Shutdown(ctx)` stops accepting and blocks until the in-flight sessions finish
(or `ctx` is cancelled); `Close()` is the immediate hard stop that force-closes
live connections without waiting — the same split as `net/http.Server`. To drive
a single already-accepted connection yourself — behind your own listener or
proxy — construct a `Session` with `NewSession(conn, backend, tlsConfig, limiter)`
and call `Handle()`.

## TLS

Pass a `*tls.Config` to enable both `STLS` (STARTTLS) on the plaintext port and
implicit TLS on the secure port; pass `nil` to run plaintext only. When a config
is present, the engine advertises `STLS` in `CAPA` and refuses `USER` on an
un-upgraded plaintext connection so credentials are never exposed.

## Rate limiting

`NewServer` and `NewSession` accept a `Limiter` — a small structural interface
(`Accept`/`Release`/`RecordAuthFail`/`IsBanned`/`ResetAuth`) the engine consults
for per-IP connection caps and auth-failure bans. Pass `nil` (or
`pop3.NopLimiter{}`) for none, or wire in your own; any type with those methods
satisfies it.

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-pop3](https://pkg.go.dev/github.com/rest-mail/go-pop3).

## License

[MIT](LICENSE) © 2026 rest-mail
