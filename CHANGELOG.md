# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note: pre-1.0, breaking changes may ship in a minor release.

## [Unreleased]

## [0.2.0] - 2026-07-25

### Breaking

- **`Server.Shutdown` now takes a `context.Context` and returns an `error`.** Its
  signature changed from `Shutdown()` to `Shutdown(ctx context.Context) error`: it
  closes the listeners and then blocks until every in-flight session finishes, or
  returns `ctx.Err()` if the context is done first — a graceful drain that mirrors
  `net/http.Server.Shutdown`. Callers must now pass a context and handle the
  returned error. For the previous immediate stop, use the new **`Server.Close()`**,
  which force-closes live connections without waiting.

### Added

- **`OctetCount(raw []byte) int`** computes the RFC 1939 §11 octet count of a
  stored message — the number of octets `RETR` transmits, measured on the
  canonical CRLF wire form (a lone LF counts as the two octets `CR LF`), with the
  §3 leading-dot byte-stuffing and the `CRLF.CRLF` terminator excluded as
  transport framing. Backends size messages with it so `STAT`/`LIST` and `RETR`
  agree to the octet.

### Changed

- **`Message.Size` is now defined as the exact `RETR` octet count.** Its
  documentation previously said the size "need not equal the exact length
  `Retrieve` returns," which licensed `STAT`/`LIST` to disagree with what `RETR`
  delivers — a client that pre-allocates or verifies against the listing size
  would then mismatch. RFC 1939 §5 requires the scan listing to carry the "exact
  size of the message in octets," and §11 fixes that count to the CRLF-normalized
  form. `Size` must now be that count (compute it with the new `OctetCount`); the
  engine already advertises and transmits exactly this value from `RETR`, so the
  two now agree by construction. No wire behavior changed; the contract and its
  documentation were tightened.
- **`Server.Shutdown` now takes a `context.Context` and actually drains
  in-flight sessions.** It previously waited only on the accept-loop goroutines —
  which return the moment their listener closes — so it returned while client
  sessions were still being served, contradicting its "drains them gracefully"
  documentation. Each accepted connection is now tracked in the server's
  `sync.WaitGroup`, and `Shutdown(ctx)` closes the listeners and then blocks
  until every session finishes, or until `ctx` is done (returning `ctx.Err()`),
  mirroring `net/http.Server.Shutdown`. A new `Server.Close()` provides the
  immediate hard stop: it force-closes live connections without waiting.

### Fixed

- **`STLS` is now refused after authentication.** `STLS` (STARTTLS for POP3,
  RFC 2595) belongs to the AUTHORIZATION state, but the handler gated it only on
  the current TLS status, so a connection that reached TRANSACTION while still
  cleartext could begin a TLS handshake after `PASS`. It is now answered `-ERR`
  once the session is authenticated, before any negotiation begins.
- **The failed-authentication ban is now enforced at connection accept.** The
  ban was consulted only after a failed `PASS`, so a banned IP could still open a
  connection and spend one fresh authentication attempt on every reconnect. The
  accept loop now checks the ban list up front and drops a banned client before a
  session is created.
- **`UIDL` now validates each unique-id and refuses a malformed or duplicate
  one.** A backend-supplied unique-id was written into the `UIDL` response without
  being checked, so an id containing a space, `CR`, or `LF`, or one outside the
  RFC 1939 §7 grammar (1–70 characters in the range `0x21`–`0x7E`), could split the
  `n uid` pair a client parses or inject protocol lines and desynchronize the
  session. Single-message `UIDL n` now answers `-ERR` for a malformed id, and the
  full-list form pre-scans every message and answers `-ERR` if any id is malformed
  or duplicated before writing the `+OK` header, so a bad id can never corrupt the
  dot-terminated block mid-stream.
- **`NOOP` and `RSET` are now rejected before authentication.** Both are
  TRANSACTION-state commands (RFC 1939 §5), reachable only after a successful
  login, but they were dispatched with no authentication check, so a pre-auth
  client received `+OK` — and `RSET` even reported a message count for a maildrop
  that was not yet open. They now answer `-ERR` in the AUTHORIZATION state and
  continue to work once the session is authenticated.
- **`QUIT` now answers `-ERR` when a maildrop deletion fails.** On `QUIT` the
  server enters the UPDATE state and commits every message marked for deletion
  (RFC 1939 §6). A failed backend deletion was only logged while `QUIT` still
  answered `+OK`, telling the client its deletions were durable — so a client that
  trusts that reply may drop its local copies and silently lose mail that is still
  on the server. Every deletion is still attempted, but `QUIT` now answers `-ERR`
  when any of them fails and `+OK` only when the update fully succeeds.
- **Credentials are now redacted from the per-command debug log.** With debug
  logging enabled the full raw command line was recorded, so `PASS` wrote the
  user's cleartext password to the logs (also capturing mistyped-but-valid
  passwords on failed attempts). The argument of credential-bearing verbs — `PASS`,
  `APOP`, and `AUTH` — is now replaced with `<redacted>` before logging; the
  command keyword is kept for debuggability and all other command lines are logged
  verbatim.
- **No-argument commands now reject a spurious trailing argument with `-ERR`.**
  `STAT`, `RSET`, `NOOP`, `QUIT`, `STLS`, and `CAPA` take no arguments (RFC 1939
  §3, RFC 2595, RFC 2449), but a trailing token was silently dropped and the
  command still succeeded — `STAT junk` answered `+OK`. Such a line is a syntax
  error and is now refused with `-ERR`, leaving session state untouched (a
  mistyped `QUIT` no longer enters the UPDATE phase and commits deletions). The
  bare forms and every argument-taking command are unaffected.
- **Command lines are now length-bounded, closing a pre-auth memory DoS.**
  Command lines were read with an unbounded `bufio.Reader.ReadString('\n')`, so a
  client — before authenticating — could stream an arbitrarily large "line" with
  no CRLF and force the process to buffer all of it, exhausting memory. The reader
  is now capped at a generous per-line limit (RFC 1939 §3 commands are tiny); a
  line that exceeds it is refused with `-ERR` and the connection is closed rather
  than buffered without limit.

## [0.1.2] - 2026-07-25

### Fixed

- **RETR/TOP now normalize bare LF to CRLF so dot-stuffing holds.** Messages
  stored with a bare LF (an LF not preceded by CR) were framed by splitting on
  CRLF only, so a bare LF survived inside a line and its content was never
  dot-stuffed. A line that was exactly `.` reached the wire unescaped as a
  premature multi-line terminator, letting attacker-controllable message content
  desync the session and forge responses. Retrieved bytes are now canonicalized
  to CRLF before framing, so dot-stuffing and the reported octet count operate on
  real line boundaries.
- **A panicking session no longer crashes the whole server.** A panic in any
  command handler or `Backend`/`Mailbox` call was unrecovered and took down the
  per-connection goroutine along with every other concurrent session. Each
  session now recovers, logs the panic with its stack, replies `-ERR`, and closes
  only that one connection.
- **A `nil` mailbox from `Authenticate` no longer causes a nil dereference.** A
  backend returning `(nil, nil)` from `Authenticate` authenticated the user but
  left a nil `Mailbox`, which was then dereferenced (SIGSEGV). `PASS` now rejects
  a nil mailbox with `-ERR` and stays in AUTHORIZATION.
- **Failed maildrop load no longer wedges the session in TRANSACTION.** The
  session was marked authenticated before `Mailbox.Messages()` was called, so a
  load failure left it authenticated with a nil message list: `STAT` answered
  `+OK 0 0` over a phantom empty maildrop and `USER` retries were refused. The
  maildrop is now loaded first and the authenticated state committed only on
  success; on failure the session replies `-ERR` and remains in AUTHORIZATION so
  the client can retry.
- **RETR/TOP no longer emit a spurious blank line before the terminator.**
  Splitting a well-formed message (which ends in CRLF) on CRLF left a trailing
  empty element that was sent as an extra blank line, so the transmitted octets
  exceeded the advertised count and disagreed with LIST/STAT sizes. The trailing
  empty element is now dropped, so the wire octets match the advertised size.

## [0.1.1] - 2026-07-23

- Initial tagged release lineage (see Git history for v0.1.0 and v0.1.1).
