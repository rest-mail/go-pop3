# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- **Command lines are now length-bounded, closing a pre-auth memory DoS.**
  Command lines were read with an unbounded `bufio.Reader.ReadString('\n')`, so a
  client — before authenticating — could stream an arbitrarily large "line" with
  no CRLF and force the process to buffer all of it, exhausting memory. The reader
  is now capped at a generous per-line limit (RFC 1939 §3 commands are tiny); a
  line that exceeds it is refused with `-ERR` and the connection is closed rather
  than buffered without limit.

## v0.1.2

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

## v0.1.1

- Initial tagged release lineage (see Git history for v0.1.0 and v0.1.1).
