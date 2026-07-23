# pop3

[![CI](https://github.com/rest-mail/go-pop3/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-pop3/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-pop3.svg)](https://pkg.go.dev/github.com/rest-mail/go-pop3)

A POP3 ([RFC 1939](https://www.rfc-editor.org/rfc/rfc1939)) server engine for Go,
with zero external dependencies (standard library only).

You supply a `Backend` that authenticates users and exposes each user's maildrop
as a slice of neutral `Message` values; the `Server` speaks the wire protocol —
`USER`/`PASS`, `CAPA`, `STLS` (STARTTLS), `STAT`, `LIST`, `UIDL`, `RETR`, `TOP`,
`DELE`, `RSET`, `NOOP` and `QUIT`. The engine holds no assumptions about where
mail lives: a `Backend` can be a database, a maildir, or a remote API.

RETR/TOP serve exactly the bytes `Mailbox.Retrieve` returns, with RFC 1939
dot-stuffing applied on the wire, and messages a client `DELE`s are removed only
on `QUIT`.

## Install

```sh
go get github.com/rest-mail/go-pop3
```

## Usage

Implement `Backend` and `Mailbox`, then hand the server a listener config:

```go
package main

import (
	"crypto/tls"

	"github.com/rest-mail/go-pop3"
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
	select {} // serve until Shutdown
}
```

For a single accepted connection (e.g. behind your own listener), construct a
session directly with `pop3.NewSession(conn, backend, tlsConfig, limiter)` and
call `Handle()`.

### Rate limiting

`NewServer` accepts a `Limiter` — a small structural interface
(`Accept`/`Release`/`RecordAuthFail`/`IsBanned`/`ResetAuth`) the engine consults
for per-IP connection caps and auth-failure bans. Pass `nil` (or `pop3.NopLimiter{}`)
for none, or wire in your own; any type with those methods satisfies it.

## License

[MIT](LICENSE) © 2026 rest-mail
