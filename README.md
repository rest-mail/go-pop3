# go-pop3

[![CI](https://github.com/rest-mail/go-pop3/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-pop3/actions/workflows/ci.yml)
[![Coverage gate: >=95%](https://img.shields.io/badge/coverage%20gate-%3E%3D95%25-brightgreen)](COVERAGE.md)
[![Partial checklist: 104/107 mapped](https://img.shields.io/badge/partial%20checklist-104%2F107%20mapped-blue)](CHECKLIST.md)
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
- `AUTH` with SASL `PLAIN` ([RFC 5034](https://www.rfc-editor.org/rfc/rfc5034),
  [RFC 4616](https://www.rfc-editor.org/rfc/rfc4616)) when the backend
  implements `SASLBackend`; without it `AUTH` stays an unknown command.
- Credentials are never sent in the clear: when TLS is configured, `USER` and
  `AUTH` are refused until the connection is secured.
- Credentials stay out of the debug log. Each received command line is logged at
  debug level as follows: `PASS`, `APOP` and `AUTH` keep their keyword and log
  `<redacted>` for the argument; other known commands are logged as sent; and
  any other line, such as ` PASS x`, `PASS<TAB>x`, a lookalike like `paſs x` or a
  password typed on its own, is logged only as `<unknown command redacted>`.
- `CAPA` capability advertisement ([RFC 2449](https://www.rfc-editor.org/rfc/rfc2449)):
  `USER`, `SASL PLAIN` for a `SASLBackend` while `AUTH` is accepted, `STLS`,
  `TOP`, `UIDL`, `RESP-CODES`, `AUTH-RESP-CODE`
  ([RFC 3206](https://www.rfc-editor.org/rfc/rfc3206)), `PIPELINING`,
  `LOGIN-DELAY` for a `LoginDelayBackend`, and
  `UTF8` ([RFC 6856](https://www.rfc-editor.org/rfc/rfc6856)) when the backend
  implements `UTF8Backend`: the `UTF8` command is accepted before login and
  `AuthenticateUTF8` learns whether the client may receive raw UTF-8 headers.
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
	// oldest-first; UID must be stable. Size is the STAT/LIST octet count and
	// MUST equal what RETR transmits — compute it with pop3.OctetCount over the
	// same bytes Retrieve returns so LIST/STAT and RETR agree (RFC 1939 §11).
	return []pop3.Message{
		{UID: "1001", Size: pop3.OctetCount(raw1001), Seen: false},
		{UID: "1002", Size: pop3.OctetCount(raw1002), Seen: true},
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
  in octets for `STAT`/`LIST`, and whether it is already `Seen`. `Size` must be
  the exact octet count `RETR` transmits; use `pop3.OctetCount(raw)` over the
  bytes `Retrieve` returns so the maildrop listing and `RETR` never disagree.

A message's slice position (+1) in the `Messages()` result is the POP3 message
number the client uses for the rest of the session; the engine translates
between those numbers and your stable `UID`s.

After verifying credentials, `Authenticate` or `Messages` may return
`pop3.ErrInUse` (directly or wrapped with `%w`) if another session owns the
maildrop. PASS then replies `-ERR [IN-USE]`, clears the pending USER and permits
a fresh USER/PASS attempt. This resets credential-failure history without
recording an authentication failure or checking for a ban. Partial results are
ignored. The backend must acquire and release maildrop locks itself; the engine
does not implement locking. Use `ErrInUse` only after credentials are verified.

Likewise, `Authenticate` may return `pop3.ErrLoginDelay` (directly or wrapped)
after verifying credentials to refuse a login that comes too soon after the
last one. PASS then replies `-ERR [LOGIN-DELAY]` and permits a later USER/PASS
attempt without counting an authentication failure. The backend tracks login
times and chooses the delay. To tell clients the delay in advance, implement
`pop3.LoginDelayBackend`: CAPA then announces `LOGIN-DELAY <seconds>` before
login, followed by `USER` when the delay varies per user. A Mailbox that also
implements `pop3.LoginDelayMailbox` announces the user's own value after login.

For login infrastructure failures, `Authenticate` and `Messages` may return
`pop3.ErrSystemTemporary` or `pop3.ErrSystemPermanent` (directly or wrapped).
PASS then replies with `SYS/TEMP` for a problem likely to resolve on retry or
`SYS/PERM` for one requiring intervention ([RFC 3206 §4](https://www.rfc-editor.org/rfc/rfc3206#section-4)).
Private error details and partial results stay out of the response. The session
stays in AUTHORIZATION and requires a fresh USER/PASS attempt. An authentication
service failure can occur before credentials are verified, so it neither
records nor resets credential failures or checks for a ban. A successful
`Authenticate` still resets failure history before calling `Messages`.
Unclassified authentication errors remain credential failures (`AUTH`);
unclassified `Messages` errors remain `SYS/TEMP`. These sentinels classify
login-opening errors; transaction commands keep their existing error behavior.

To accept `AUTH PLAIN`, implement `pop3.SASLBackend`. Its
`AuthenticatePlain(authzid, authcid, pass, utf8)` receives the decoded RFC 4616
fields and returns the same errors as `Authenticate`, with the same response
codes: a credential failure replies `-ERR [AUTH]` and counts toward the
`Limiter` ban like a failed PASS. `authzid` is empty unless the client asks to
act as another identity; reject it if you do not support that. CAPA lists
`SASL PLAIN` only while `AUTH PLAIN` is accepted, so with a TLS config it
appears after `STLS` (or on the implicit-TLS port).

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

## Independent client verification

CI runs `TestPythonPoplibReference` against the Python 3.13 standard library's
[`poplib`](https://docs.python.org/3.13/library/poplib.html) client. To run it
locally with Python 3 installed:

```sh
POP3_REFERENCE_PYTHON=python3 go test -count=1 -run '^TestPythonPoplibReference$' ./internal/referencetest
```

The test opens an ephemeral loopback listener and drives the public `Session`
API with a memory backend. The independent client parses CAPA, authentication
errors, STAT, single/multiline LIST and UIDL, RETR, TOP, DELE, RSET, NOOP and
QUIT. Its decoded messages and octet counts are compared with fixed expected
bytes, independently of the server's framing helpers; `OctetCount` is checked
against the same expectations. Fixtures include leading dots, empty messages,
LF normalization, an unterminated final line and opaque byte content. Backend
checks distinguish successful QUIT deletion from disconnect without UPDATE.

This is a limited differential decoding/interoperability check against an
independent client, not a comparison with another server or a full RFC oracle.
`poplib` accepts some noncanonical response syntax, so the existing Go wire
tests remain responsible for strict CRLF/status assertions. TLS/STLS,
pipelining, arbitrary malformed inputs and production backend durability are
outside this reference test. Python is a test-only prerequisite: ordinary Go
tests skip this comparison unless `POP3_REFERENCE_PYTHON` is set; CI explicitly
sets it and fails if Python or the comparison fails. No runtime dependency is
added. The partial checked RFC inventory and remaining gaps are described in
[CHECKLIST.md](CHECKLIST.md).

The coverage badge shows the minimum CI enforces (statements left uncovered are
listed in [COVERAGE.md](COVERAGE.md)); measured statement coverage is printed in
each CI run's **Require at least 95% statement coverage** log. The checklist
badge counts requirements mapped to tests over all rows of the **partial**
checklist: it is not a count of every applicable RFC requirement. Tests check
both badges against the CI gate and the checklist's actual test mappings. The CI
badge reports whether verification passed.

## Changelog

Recent releases — see [CHANGELOG.md](CHANGELOG.md) for the complete history.

- **v0.2.0** (2026-07-25) — breaking: `Shutdown(ctx) error` graceful drain + new `Close()`; UIDL validation, pre-auth NOOP/RSET rejection, QUIT `-ERR` on delete failure, LIST/STAT size consistency.
- **v0.1.2** (2026-07-25) — RETR/TOP normalize bare LF to CRLF so dot-stuffing holds; per-session panic recovery; nil-mailbox and failed-maildrop-load guards; no spurious blank line before the terminator.
- **v0.1.1** (2026-07-23) — initial tagged release.

## License

[MIT](LICENSE) © 2026 rest-mail
