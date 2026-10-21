# POP3 RFC checklist — PARTIAL checked foundation

This is an explicitly **PARTIAL** checklist for selected AUTHORIZATION,
USER/PASS, CAPA, RFC 1939 §§5–6 TRANSACTION/UPDATE, selected §7 TOP/UIDL
behavior, RFC 2595 §4 STLS transitions and selected RFC 2449 §6.6 PIPELINING
behavior across AUTHORIZATION/TRANSACTION, plus selected RFC 2449 RESP-CODES
and RFC 3206 AUTH response-code behavior, plus selected RFC 2449 §4 command-length support
and separately labeled command-reader policy, plus the optional RFC 1939 §3
autologout timer as this library implements it, plus RFC 8314 §§3.1, 3.4 implicit
TLS and selected connection closure. It is not an inventory of all applicable RFC
requirements, a full conformance claim, or a coverage badge. A mapped row means
its named wire test asserts the stated behavior; it does not prove the entire
referenced section.

Requirements below paraphrase the primary texts:
[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939.txt),
[RFC 2449](https://www.rfc-editor.org/rfc/rfc2449.txt),
[RFC 2595](https://www.rfc-editor.org/rfc/rfc2595.txt),
[RFC 3206](https://www.rfc-editor.org/rfc/rfc3206.txt), and
[RFC 8314](https://www.rfc-editor.org/rfc/rfc8314.txt).
`Normative` denotes protocol text without an explicit RFC 2119 keyword.

## RFC 1939: selected AUTHORIZATION and USER/PASS behavior

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-AUTH-01 | RFC 1939 §§3–4 | Normative | Greet positively; refuse transaction commands before authentication. | TestAuthorizationUserPass |
| POP3-AUTH-02 | RFC 1939 §3 | Normative | Accept ASCII case variations of USER and PASS keywords. | TestAuthorizationUserPass |
| POP3-USER-01 | RFC 1939 §7 (USER) | Normative | Require a mailbox argument; USER alone does not authenticate; reject USER in TRANSACTION. | TestAuthorizationUserPass |
| POP3-PASS-01 | RFC 1939 §7 (PASS) | Normative | Require a password and a preceding accepted USER; reject PASS in TRANSACTION. | TestAuthorizationUserPass |
| POP3-PASS-02 | RFC 1939 §§4, 7 (PASS) | Normative | Successful USER/PASS opens maildrop access. | TestAuthorizationUserPass |
| POP3-PASS-03 | RFC 1939 §§4, 7 (USER/PASS) | Normative | Invalid credentials receive a negative reply; permit a new authentication attempt if connected. | TestAuthenticationFailureRetry |
| POP3-AUTH-03 | RFC 1939 §4 | Normative | Maildrop opening failure receives a negative reply and grants no transaction access. | TestMaildropOpenFailure |
| POP3-PASS-04 | RFC 1939 §7 (PASS) | MAY | Treat embedded password spaces as password data. | TestPasswordContainsSpaces |
| POP3-PASS-05 | RFC 1939 §7 (PASS), Appendix A | Normative | Accept PASS only immediately after a successful USER in AUTHORIZATION; intervening commands and empty PASS invalidate pending USER without backend calls, and a fresh USER/PASS pair can retry. | TestPassRequiresImmediateUser |
| POP3-AUTH-04 | RFC 1939 §§3–4, 7 (USER) | Normative | QUIT in AUTHORIZATION replies positively and closes, including after accepted USER. | TestAuthorizationQuit |

## RFC 2449: selected CAPA behavior without TLS

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-CAPA-01 | RFC 2449 §5 | Normative | Accept argumentless CAPA in AUTHORIZATION and TRANSACTION; reject an argument. | TestCapaBothStates |
| POP3-CAPA-02 | RFC 2449 §§3–5 | Normative | Positive CAPA has one capability per CRLF line, at most 512 octets per line, then a dot CRLF terminator. | TestCapaBothStates |
| POP3-CAPA-03 | RFC 2449 §5 | MUST | Retain AUTHORIZATION capabilities in TRANSACTION (tested without TLS). | TestCapaBothStates |
| POP3-CAPA-04 | RFC 2449 §6.2 | Normative | Announce parameterless USER in both states for USER/PASS support. | TestCapaBothStates |

## RFC 1939 §5: selected TRANSACTION requirements

Sizes here use a backend fixture with canonical CRLF messages and correct octet
metadata; this does not certify arbitrary backend metadata or all message formats.
Deletion references below cover LIST, RETR and DELE; selected TOP/UIDL proofs follow in §7.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-TRANS-01 | RFC 1939 §5 | Normative | Require TRANSACTION for STAT, LIST, RETR, DELE, NOOP and RSET. | TestTransactionArguments |
| POP3-TRANS-02 | RFC 1939 §§3, 5 | Normative | Reject arguments to STAT/NOOP/RSET and missing or invalid required message numbers. | TestTransactionArguments |
| POP3-STAT-01 | RFC 1939 §5 (STAT) | Normative | Reply positively with decimal message count and total octets separated by spaces. | TestTransactionStatList, TestTransactionEmptyMaildrop |
| POP3-STAT-02 | RFC 1939 §5 (STAT) | Normative | Exclude deletion marks from count and size. | TestTransactionDeleteReset |
| POP3-LIST-01 | RFC 1939 §§4–5 (LIST) | Normative | List each message using its stable one-based decimal number and exact octet size. | TestTransactionStatList, TestTransactionDeleteReset |
| POP3-LIST-02 | RFC 1939 §§3, 5 (LIST) | Normative | Argumentless LIST sends positive status, scan lines and dot terminator; empty maildrops have no scan lines. | TestTransactionStatList, TestTransactionEmptyMaildrop |
| POP3-LIST-03 | RFC 1939 §5 (LIST) | Normative | LIST with a valid number returns its scan listing; reject nonexistent or deleted messages and omit deleted scan lines. | TestTransactionStatList, TestTransactionArguments, TestTransactionDeleteReset |
| POP3-RETR-01 | RFC 1939 §§3, 5 (RETR) | Normative | Positive RETR sends the selected entire message with CRLF framing, leading-dot stuffing and a dot terminator. | TestTransactionRetrieval |
| POP3-RETR-02 | RFC 1939 §5 (RETR) | Normative | Reject nonexistent and deletion-marked message numbers. | TestTransactionArguments, TestTransactionDeleteReset |
| POP3-DELE-01 | RFC 1939 §5 (DELE) | Normative | Mark a valid message positively; reject nonexistent and already marked messages; defer physical removal. | TestTransactionArguments, TestTransactionDeleteReset |
| POP3-NOOP-01 | RFC 1939 §5 (NOOP) | Normative | Reply positively without altering message visibility or deletion marks. | TestTransactionNoop |
| POP3-RSET-01 | RFC 1939 §5 (RSET) | Normative | Reply positively and clear all deletion marks, restoring listings, counts and retrieval. | TestTransactionDeleteReset |

## RFC 1939 §6: selected UPDATE/QUIT requirements

These proofs observe wire replies, session termination and per-UID backend calls.
Successful fixture deletes model persistence; actual storage durability, exclusive
maildrop ownership, lock acquisition/release and resource cleanup are backend
integration contracts outside this checked inventory. The Mailbox interface has
no multi-message transaction or lock-release operation. On deletion failure the
RFC permits some or none of the marked messages to be removed; these tests prove
both outcomes without claiming atomicity, rollback or a deletion order.
AUTHORIZATION QUIT remains covered by POP3-AUTH-04 above.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-UPDATE-01 | RFC 1939 §§3, 6 | Normative | QUIT takes no arguments; reject an argument without committing or leaving TRANSACTION. | TestUpdateQuit |
| POP3-UPDATE-02 | RFC 1939 §6 | Normative | TRANSACTION QUIT removes marked messages on success; never remove unmarked messages, including on failure or after RSET. | TestUpdateQuit, TestUpdateResetQuit, TestUpdateDeleteFailure |
| POP3-UPDATE-03 | RFC 1939 §6 | Normative | Reply to QUIT with the update status and close the connection after success or failure. | TestUpdateQuit, TestUpdateResetQuit, TestUpdateDeleteFailure |
| POP3-UPDATE-04 | RFC 1939 §6 | Normative | Report successful removal with a positive QUIT reply. | TestUpdateQuit |
| POP3-UPDATE-05 | RFC 1939 §6 | MUST NOT | Remove messages when a session ends without client-issued QUIT (tested with EOF and an incomplete command). | TestUpdateDisconnect |
| POP3-UPDATE-06 | RFC 1939 §6 | Normative | Report removal failure negatively; some or none of the marked messages may have been removed. | TestUpdateDeleteFailure |

## RFC 1939 §7: selected optional TOP/UIDL requirements

TOP and within-session UIDL tests reuse the canonical message corpus. All use
public Session/net.Pipe helpers with opaque backend UIDs distinct from wire
message numbers. UID stability
within one session includes DELE/RSET. Sequential-session tests additionally
prove Session faithfully emits stable backend IDs from a synchronized in-memory
model after committed deletion renumbers a survivor, after a distinct fixture
message is appended, and after EOF without UPDATE. These are fixture proofs, not
production backend persistence, crash recovery, global UID generation/non-reuse
or maildrop lifetime guarantees; those remain integration follow-ups. Format checks
exercise existing fail-safe error handling, not new runtime work. The duplicate-ID
negative case records the library's current rejection policy, not a claim that the
RFC forbids equal hashes for identical message copies.

Sequential sessions use dynamic copied Messages snapshots reflecting successful
Delete calls. STAT checks fixed fixture metadata, not message-body octet accuracy.
Every connection has bounded wire deadlines and explicit QUIT/EOF with a joined
session goroutine before reconnecting; no database or socket listener is used.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-TOP-01 | RFC 1939 §§3, 7 (TOP) | Normative | Require TRANSACTION, a valid message number and a non-negative line count; reject missing, invalid or extra arguments. | TestOptionalArguments |
| POP3-TOP-02 | RFC 1939 §7 (TOP) | Normative | TOP with zero body lines sends headers and one blank separator, with no body lines (including empty-header and headers-only fixtures). | TestOptionalTopFraming |
| POP3-TOP-03 | RFC 1939 §§3, 7 (TOP) | Normative | Send at most the requested body lines, clamping to the available body; use CRLF, leading-dot stuffing and exactly one dot terminator. | TestOptionalTopFraming |
| POP3-TOP-04 | RFC 1939 §§5, 7 (TOP) | Normative | Refuse deletion-marked messages; RSET restores access using the original message number. | TestOptionalDeleteReset |
| POP3-UIDL-01 | RFC 1939 §§3, 7 (UIDL) | Normative | Require TRANSACTION; reject invalid, nonexistent or extra message-number arguments. | TestOptionalArguments |
| POP3-UIDL-02 | RFC 1939 §§3, 7 (UIDL) | Normative | Single and multiline listings contain the exact decimal message number, one space and UID only; terminate lists with dot CRLF, including an empty maildrop. | TestOptionalUIDLListing |
| POP3-UIDL-03 | RFC 1939 §§4–5, 7 (UIDL) | Normative | Retain numbers and UIDs across repeated commands within a session; exclude deletion marks from lists and single replies; RSET restores the original listings. | TestOptionalDeleteReset |
| POP3-UIDL-04 | RFC 1939 §7 (UIDL) | Normative | Emit UIDs of 1–70 printable ASCII characters (0x21–0x7e); reject malformed visible backend UIDs without corrupting subsequent response framing. | TestOptionalUIDLListing, TestOptionalUIDLInvalidBackend |
| POP3-UIDL-05 | RFC 1939 §7 (UIDL) | Normative | In sequential sessions over a stable-ID memory backend, retain a survivor UID when successful QUIT deletion renumbers it from 2 to 1; a later appended fixture has a distinct UID without changing the survivor identity. | TestUIDLSequentialSessionsDeleteAndAppend |
| POP3-UIDL-06 | RFC 1939 §7 (UIDL) | Normative | In sequential sessions over a stable-ID memory backend, retain original UIDs and listings after EOF without UPDATE, including an uncommitted DELE mark. | TestUIDLSequentialSessionsWithoutUpdate |

## RFC 2595 §4: selected POP3 STLS and CAPA transitions

POP3 STLS is specified in RFC 2595 **§4**; §3 specifies IMAP STARTTLS.
These proofs use public Session/net.Pipe with an actual TLS 1.3 handshake,
a temporary self-signed localhost certificate trusted by the client, normal
certificate/hostname verification, bounded client deadlines and joined session
goroutines. TLS 1.3 is the test fixture's choice, not a claimed RFC 2595 mandate.
Re-issued encrypted CAPA verifies the transition, not client cache management.
The two POLICY rows describe existing library choices: configuring TLS refuses
plaintext USER/PASS, and a failed handshake closes the session. They are not
universal RFC mandates. POP3-STLS-07 is also library policy: RFC 2595 does not
spell out buffered-input handling, but the STARTTLS command-injection class
(CVE-2011-0411) is avoided by never reading plaintext octets past the STLS line
under TLS. A temporary control that carried the buffered octets into the TLS
reader (session.go restored byte-for-byte) authenticated the injected USER/PASS
and failed the test. Nil TLS configuration permits plaintext authentication.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-STLS-01 | RFC 2595 §4; RFC 2449 §5 | Normative | Advertise parameterless STLS through CAPA when available before TLS; omit it and refuse STLS when TLS is not configured. | TestSTLSNoConfig, TestSTLSCredentials |
| POP3-STLS-02 | RFC 2595 §4 | Normative | STLS takes no arguments; refuse extra arguments without starting TLS or losing the plaintext session. | TestSTLSArguments |
| POP3-STLS-03 | RFC 2595 §4 | Normative | Start TLS immediately after the positive STLS reply's CRLF; subsequent POP3 commands use the negotiated TLS layer. | TestSTLSCredentials |
| POP3-STLS-04 | RFC 2595 §4 | Normative | Remain in AUTHORIZATION after STLS; do not grant transaction access until USER/PASS succeeds. | TestSTLSCredentials |
| POP3-STLS-05 | RFC 2595 §4; RFC 2449 §5 | Normative | Re-issued CAPA after TLS omits STLS and retains USER; preserve that encrypted capability list after authentication. | TestSTLSCredentials |
| POP3-STLS-06 | RFC 2595 §4 | Normative | Permit STLS only in AUTHORIZATION; refuse it in TRANSACTION and exercise the permitted refusal when TLS is already active. | TestSTLSStates |
| POP3-STLS-07 | RFC 2595 §4; RFC 2449 §6.6 (library policy) | Normative | Plaintext commands pipelined after STLS in the same read are discarded at the handshake: no injected USER/PASS authenticates or is retained, and no injected command is answered under TLS. | TestSTLSDiscardsPipelinedPlaintext |
| POP3-TLS-POLICY-01 | RFC 2595 §§2.5, 4 (library policy) | Normative | With TLS configured, refuse plaintext USER/PASS without calling backend authentication; accept valid credentials through TLS exactly once. | TestSTLSCredentials |
| POP3-TLS-POLICY-02 | RFC 2595 §2.5 (library policy) | Normative | Close after a malformed TLS record header during STLS negotiation without calling backend authentication. | TestSTLSHandshakeFailure |

## RFC 8314 §3.1: implicit TLS ("pop3s")

These proofs start a Server through the public `ListenAndServe` with only the
`POP3TLS` listener, the way the gateway serves port 995. The test reserves a
free loopback port, so this is the one fixture that opens a socket; the client
is a real TLS 1.3 client that verifies the temporary self-signed certificate.
Client-certificate authentication (RFC 8314 §§4.2, 5.5) is not supported, so
the "even if a client certificate was supplied" clause is shown only for
connections without one. Forced shutdown, error-path closure and a `POP3TLS`
port configured with a nil TLS config (which today listens in plaintext) remain
unproven. Selected normal closure proofs follow below.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-ITLS-01 | RFC 8314 §3.1 | Normative | Begin the TLS handshake immediately on connect; send the greeting and every reply only as TLS application data, never in the clear to a plaintext client. | TestImplicitTLSSession, TestImplicitTLSRejectsPlaintext |
| POP3-ITLS-02 | RFC 8314 §3.1 | MUST | After the +OK greeting, enter AUTHORIZATION: refuse transaction commands until USER/PASS succeeds. | TestImplicitTLSSession |
| POP3-ITLS-03 | RFC 8314 §3.1; RFC 2595 §4; RFC 2449 §5 | Normative | On an implicit-TLS connection, omit STLS from CAPA before and after authentication, refuse STLS as already active, and accept USER/PASS without STLS. | TestImplicitTLSSession |

## RFC 8314 §3.4: selected implicit-TLS connection closure

These proofs run through the public implicit-TLS listener with TLS 1.2 and 1.3,
in AUTHORIZATION and TRANSACTION. A normal QUIT reply is followed by a decrypted
TLS close_notify and then TCP EOF. A client can instead send its close_notify
without QUIT or closing TCP: the server sends its own alert and terminates TCP.
The client transport replaces bare TCP EOF with a distinct error, because Go's
TLS reader otherwise accepts it at a record boundary; TLS EOF alone would not
prove an alert was sent. Certificate and hostname verification stay enabled.
Server cleanup drains sessions with bounded deadlines. No deletion, forced
shutdown, failed-handshake, idle-timeout or STLS closure claim is made here.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-ITLS-04 | RFC 8314 §3.4 | SHOULD | Initiate TLS close alerts before TCP termination (tested after QUIT and in response to a client close alert, before and after authentication, with TLS 1.2 and 1.3). | TestImplicitTLSCloseNotify |

## RFC 2449 §6.6: selected PIPELINING requirements

Each bounded batch is written completely before reading any individual reply,
either after sequential login or across USER/PASS authentication. Public
Session/net.Pipe proofs use in-memory backends; transaction proofs reuse the
canonical CRLF corpus and opaque UIDs distinct from wire numbers. Exact response
lines check order, CRLF, dot stuffing and complete multiline terminators before
subsequent replies. Small batches fit the session's
command-reader buffer, avoiding synchronous net.Pipe write deadlock; this does
not prove arbitrary batch sizes or transport-window handling. Existing bounded
client deadlines and session cleanup apply; no extra goroutines are started.
TLS pipelining, all extension combinations, backend lifetime,
rate policy and atomic batch guarantees are outside this selected inventory.
Exact explanatory reply text below records current library behavior; the RFC
requires the relevant status and ordering, not those particular words.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-PIPELINING-01 | RFC 2449 §6.6 | Normative | Announce parameterless PIPELINING in AUTHORIZATION and TRANSACTION without differing arguments. | TestPipeliningCapabilities |
| POP3-PIPELINING-02 | RFC 2449 §6.6 | MUST | Process each command in turn: a queued NOOP/STAT/LIST 1/UIDL 1 batch returns the corresponding complete single-line replies in order. | TestPipeliningSingleReplies |
| POP3-PIPELINING-03 | RFC 2449 §6.6; RFC 1939 §§3, 5, 7 | MUST | Process queued LIST/TOP/RETR/NOOP in turn, finishing each multiline block and dot terminator before the next response. | TestPipeliningMultilineReplies |
| POP3-PIPELINING-04 | RFC 2449 §6.6; RFC 1939 §3 | MUST | Reply negatively to invalid and unknown queued commands in order; subsequent valid commands retain their replies and session access. | TestPipeliningErrorRecovery |
| POP3-PIPELINING-05 | RFC 2449 §6.6; RFC 1939 §5 | MUST | Process queued DELE, queries and RSET in turn; repeated batches observe deletion then restoration with stable message numbers and UIDs. | TestPipeliningStateOrder |
| POP3-PIPELINING-06 | RFC 2449 §6.6 | MUST | Process a bounded CAPA/STAT/USER/PASS/STAT/CAPA/NOOP batch in turn across successful login, completing each capability block before subsequent replies and loading messages only after accepted credentials. | TestAuthPipeliningSuccess |
| POP3-PIPELINING-07 | RFC 2449 §6.6 | MUST | Process a bounded failed USER/PASS, unauthenticated STAT, and fresh successful USER/PASS/STAT batch in turn with ordered replies and exactly the corresponding backend authentication and enumeration calls. | TestAuthPipeliningFailureRetry |
| POP3-PIPELINING-POLICY-01 | Library policy (session.go authentication reset/retry) | Normative | Within one queued batch, a failed PASS clears pending USER: refuse PASS without fresh USER without calling Authenticate, retain AUTHORIZATION, and allow a fresh successful USER/PASS. | TestAuthPipeliningFailureRetry |

The authentication batches additionally check CAPA multiline framing and exact
Authenticate arguments/call order, with no Messages before accepted credentials,
no retrieval/mark-seen/delete calls, fresh STAT/NOOP, and QUIT/EOF with joined
session goroutines. They use nil TLS and the no-op limiter. RFC 2449 §6.6 gives
USER/PASS batching as an example; reset/retry details above record existing
library policy, not an additional RFC mandate or strict immediate-PASS claim.

## RFC 2449 §§3, 6.4, 8 and RFC 3206 §§5–6: selected RESP-CODES/AUTH behavior

RFC 2449 §8 permits optional bracketed response codes; advertising RESP-CODES
does not require a code on every -ERR. RFC 3206 §5 defines AUTH for credential
problems, including wrong passwords and unknown accounts. These public
Session/net.Pipe tests pin that code and its wire placement, not merely error
prose. The exact uppercase spelling, explanatory text and spacing after the
closing bracket record current library output, not additional RFC mandates.
The POLICY rows are library regression contracts, represented as `Normative`
for the checker's existing vocabulary; they are not RFC MUST/SHOULD claims.
They pin identical public credential-failure replies, a fresh USER after a
failed PASS, and maildrop-load errors without credential AUTH labeling or
backend detail disclosure. Fixtures use memory, nil TLS and the default no-op
limiter except for the IN-USE proof below; ordinary backend Authenticate errors
are treated as credential rejection. Arbitrary system-error classification is
not covered by this inventory.
RFC 3206 §6 says a server that labels credential failures with AUTH SHOULD
advertise AUTH-RESP-CODE. The library now does: the PASS failure that earns a
limiter ban is credential-caused, so its reply carries AUTH as well.
RFC 3206 §4 defines SYS/TEMP and SYS/PERM for system errors on PASS. After good
credentials, a maildrop that fails to load replies SYS/TEMP (likely transient,
such as a locked or unavailable store) and a backend that returns no Mailbox
replies SYS/PERM (a backend bug that needs intervention). Neither counts against
the limiter. Choosing TEMP versus PERM per path is library policy; the backend
interface cannot yet classify its own errors.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-RESP-CODES-01 | RFC 2449 §§6.4, 8 | Normative | Announce parameterless RESP-CODES in AUTHORIZATION and TRANSACTION for extended response-code support. | TestResponseCodeCapabilities |
| POP3-RESP-CODES-02 | RFC 2449 §§3, 8; RFC 3206 §5 | Normative | On coded wrong-password and unknown-account PASS failures, AUTH denotes credential trouble and begins response text in brackets after the status space, with CRLF framing. | TestResponseCodeCredentialFailures |
| POP3-RESP-CODES-03 | RFC 3206 §6 | SHOULD | Every credential-caused PASS failure carries AUTH (wrong password, unknown account, and the failure that earns a limiter ban), so CAPA lists parameterless AUTH-RESP-CODE exactly once in AUTHORIZATION and TRANSACTION. | TestResponseCodeAuthRespCodeCapability |
| POP3-RESP-CODES-04 | RFC 3206 §4 | Normative | On a system failure after good credentials, PASS replies `-ERR [SYS/TEMP]` when the maildrop fails to load and `-ERR [SYS/PERM]` when the backend returns no Mailbox, never AUTH; no limiter failure is recorded and the session stays in AUTHORIZATION. | TestResponseCodeSystemFailures |
| POP3-RESP-CODES-05 | RFC 2449 §8.1.2 | Normative | Backend-signalled maildrop contention after valid credentials returns -ERR [IN-USE] on PASS, for direct or wrapped ErrInUse from Authenticate or Messages; ignore partial results, clear USER, retain AUTHORIZATION without a limiter failure/ban check, and permit fresh login or QUIT. | TestResponseCodeInUse |
| POP3-RESP-CODES-06 | RFC 2449 §8.1.1 | Normative | Backend-signalled login delay after valid credentials returns -ERR [LOGIN-DELAY] on PASS (never on USER), for direct or wrapped ErrLoginDelay from Authenticate; ignore partial results, clear USER, retain AUTHORIZATION without a limiter failure/ban check, and permit fresh login or QUIT. | TestResponseCodeLoginDelay |
| POP3-RESP-POLICY-01 | RFC 3206 §5 (library policy) | Normative | Accept USER identically for known and unknown accounts; use the same generic AUTH failure reply for wrong passwords and unknown accounts. | TestResponseCodeCredentialFailures |
| POP3-RESP-POLICY-02 | RFC 1939 §§4, 7 (library policy) | Normative | After a credential failure, reject PASS without a fresh USER, retain AUTHORIZATION, and permit successful USER/PASS with usable STAT/NOOP. | TestResponseCodeAuthenticationRetry |
| POP3-RESP-POLICY-03 | RFC 1939 §4; RFC 3206 §5 (library policy) | Normative | With valid credentials but maildrop enumeration failure, reply with -ERR [SYS/TEMP] without AUTH or backend details; clear USER, refuse transaction access, and permit another attempt and QUIT. | TestResponseCodeMaildropFailure |

The IN-USE proof uses an explicit backend contract: `ErrInUse` (direct or
wrapped with `%w`) means credentials have already been verified and another
session owns the maildrop. Both `Authenticate` and `Messages` may report it.
The engine resets credential-failure history but neither records a failure nor
checks for a ban. It discards partial mailbox/message results and consumes the
pending USER. Eight wire cases cover the two reporting points, direct/wrapped
errors, repeated contention, and either successful retry with the correct
maildrop or AUTHORIZATION QUIT without UPDATE. Counters observe every backend
operation and limiter call. Actual exclusive locking/release remains a backend
responsibility; unrelated backend errors and APOP/SASL remain outside this
proof.

The LOGIN-DELAY proof uses the same shape: `ErrLoginDelay` (direct or wrapped)
from `Authenticate` means credentials were verified but the user logged in too
recently. PASS replies `-ERR [LOGIN-DELAY]`; USER always replies `+OK`, as RFC
2449 §8.1.1 recommends, so the code never reveals that an account exists before
its password is checked. Four wire cases cover direct/wrapped errors, repeated
refusal, and either successful retry or AUTHORIZATION QUIT without UPDATE.
Tracking login times and choosing the delay remain the backend's job. The
optional `LOGIN-DELAY` CAPA tag (RFC 2449 §6.5) is not announced yet.

## RFC 2449 §§3–4: selected command-length support and library policy

CAPA servers MUST support commands up to 255 octets including CRLF. This is
an acceptance requirement, not a server rejection ceiling at 255. The normative
proof sends exact 255-octet ASCII USER and PASS lines, both whole and with
fragmented CRLF, and checks complete credential bytes at Authenticate, successful
authentication and subsequent response framing. This covers selected credential
commands, not every command, capability-specific maximum or parser grammar.

The POLICY rows describe the existing 1024-byte bounded reader, including LF.
Acceptance beyond 255, non-ASCII credential bytes and bare LF are implementation
controls, not claims of RFC-conforming client syntax. A buffer of 1024 bytes
without LF receives one exact error and connection termination; the server does
not resynchronize. Exact explanatory error text is library behavior. These tests
use only public Session/net.Pipe and memory; runtime limits and parsing are unchanged.
The checker accepts `Normative` as its neutral level for these explicitly labeled
library-policy rows; it does not make the policy an RFC requirement.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-LENGTH-01 | RFC 2449 §§3–4 | MUST | Support 255-octet command lines including CRLF (proved for USER/PASS with complete credentials, including fragmented delivery). | TestCommandLength255Credentials |
| POP3-LENGTH-POLICY-01 | Library policy (session.go bounded reader) | Normative | Accept complete 1024-byte USER/PASS lines including LF, preserving credential bytes; count UTF-8 bytes rather than runes. | TestCommandLengthPolicy1024Accepted |
| POP3-LENGTH-POLICY-02 | Library policy (session.go bounded reader) | Normative | Refuse a 1024-byte buffer without LF with one error then close; do not authenticate or resynchronize a 1025-byte complete line or queued command. | TestCommandLengthPolicyOverflowCloses |

## RFC 1939 §3: selected unknown and unimplemented command refusals

These sequential public Session/net.Pipe proofs exercise two unknown keywords
and currently unimplemented optional APOP/AUTH commands (including mixed case)
in AUTHORIZATION, both at greeting and after USER, and in TRANSACTION after DELE.
Exact -ERR replies and the shared wire reader check uppercase status and CRLF;
following CAPA, STAT and NOOP responses check framing and retained session state.
The error prose and unchanged-state POLICY row record current library behavior,
not additional RFC mandates. Backend counters cover authentication, enumeration,
retrieval, mark-seen and deletion; QUIT/RSET controls observe the same marked UID
or no deletion after reset. Fixtures use only memory, nil TLS and the no-op limiter.
This is not an APOP/SASL implementation, authentication-error classification,
exhaustive command grammar/state inventory or new PIPELINING proof. Existing
argument/state and queued unknown-command proofs remain in their sections above.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-COMMAND-01 | RFC 1939 §3 | MUST | Reply to selected unrecognized commands with uppercase -ERR and CRLF in AUTHORIZATION and TRANSACTION. | TestCommandErrorsAuthorization, TestCommandErrorsTransaction |
| POP3-COMMAND-02 | RFC 1939 §3 | MUST | Reply to currently unimplemented optional APOP/AUTH commands with uppercase -ERR and CRLF in AUTHORIZATION and TRANSACTION. | TestCommandErrorsAuthorization, TestCommandErrorsTransaction |
| POP3-COMMAND-POLICY-01 | Library policy (session.go default dispatch) | Normative | Refusal keeps the session usable without authentication or backend read/delete side effects, preserving existing deletion marks until explicit RSET or QUIT. | TestCommandErrorsAuthorization, TestCommandErrorsTransaction |

## RFC 1939 §3: optional autologout timer

RFC 1939 §3 says a server MAY have an inactivity autologout timer. This library
implements one, so these rows prove that implementation; they do not claim the
timer is mandatory. Public Session/net.Pipe proofs wrap only the server end in a
recording net.Conn. Each SetDeadline is paired with the monotonic completion time
of the server's latest Write, so the ten-minute bound is exact without a clock
tolerance: the session computes its deadline only after that write returned. A
client send timestamp taken before each command bounds the deadline from the
other side, proving it was renewed for that command rather than carried over.
Exactly one renewal precedes each next command Read.

No test sleeps. Expiry is forced by moving the underlying pipe's read deadline
into the past once the session waits under its renewed deadline after DELE; the
session then sees a genuine `os.ErrDeadlineExceeded` timeout, not EOF. The
ten-minute duration is thus proved from the configured deadline, not from
elapsed wall-clock time. Fixtures use memory, nil TLS and the no-op limiter.
Expiry in AUTHORIZATION covers greeting-idle and pending-USER states
(POP3-IDLE-05), plus buffered partial USER/PASS lines (POP3-IDLE-06), and expiry
after STLS (POP3-IDLE-07), including buffered partial USER/PASS/QUIT lines
after STLS (POP3-IDLE-08). Other partial commands and real socket keepalive
behavior remain outside this selected inventory.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-IDLE-01 | RFC 1939 §3 | MUST | The implemented autologout timer is at least ten minutes: every idle interval's read deadline falls at least ten minutes after the server's final reply write. | TestIdleDeadlineReset |
| POP3-IDLE-02 | RFC 1939 §3 | Normative | Receipt of any command resets the timer: valid and invalid commands in AUTHORIZATION and TRANSACTION each renew the deadline from that command, once, before the next read. | TestIdleDeadlineReset |
| POP3-IDLE-03 | RFC 1939 §3 | Normative | On expiry the session does not enter UPDATE: a real read timeout after two DELE marks closes the connection with no response, no backend Delete and unchanged messages. | TestIdleAutologoutWithoutUpdate |
| POP3-IDLE-04 | RFC 1939 §3, §6 | Normative | A real read timeout while an incomplete command (`QUIT` or `QUIT\r`, no LF) is buffered closes without a response, never dispatches the partial command, does not enter UPDATE and makes no backend Delete after two DELE marks. | TestIdleTimeoutWithBufferedPartialCommand |
| POP3-IDLE-05 | RFC 1939 §3 | Normative | A real read timeout in AUTHORIZATION, both immediately after the greeting and after an accepted USER with no PASS sent, closes without a response and never reaches backend Authenticate (so no mailbox operation). | TestIdlePreLoginTimeout |
| POP3-IDLE-06 | RFC 1939 §3 | Normative | On a timeout with a buffered partial USER or PASS in AUTHORIZATION, close without a response or backend authentication; never dispatch the incomplete command. | TestIdlePreLoginPartialCommandTimeout |
| POP3-IDLE-07 | RFC 1939 §3; RFC 2595 §4 | Normative | After STLS, the encrypted idle interval is renewed to at least ten minutes after the handshake and each encrypted reply; a real timeout below TLS, after the handshake, after an encrypted USER, or in TRANSACTION with two DELE marks, closes with only TLS close_notify, never authenticates beyond the PASS sent and never enters UPDATE. | TestIdleTimeoutAfterSTLS |
| POP3-IDLE-08 | RFC 1939 §3, §6; RFC 2595 §4 | Normative | After STLS, a real timeout below TLS while an encrypted incomplete `USER`, `PASS` or `QUIT` (no terminator, or CR without LF) is buffered closes with only TLS close_notify, never dispatches it, never authenticates beyond the complete PASS sent and never enters UPDATE after two DELE marks. | TestIdleTimeoutAfterSTLSWithBufferedPartialCommand |

## RFC 1939 §10: ADAPTED TRANSACTION example

This is an **ADAPTED TRANSACTION** example of the published two-message,
120/200-octet sequence, not a literal full RFC session or an APOP proof. Section 10
uses APOP, which this library does not implement, and supplies no message bodies.
The test instead authenticates with existing USER/PASS (`alice`/`secret`), then
runs STAT, LIST, RETR 1, DELE 1, RETR 2, DELE 2 and QUIT in one public
Session/net.Pipe connection. The added STAT/LIST after DELE 1 is a visibility and
stable-numbering control, not a command sequence claimed from section 10.

Synthetic messages have Date/From/Subject headers, canonical CRLF, and independently
asserted byte lengths of exactly 120 and 200; backend metadata is separately fixed
to those sizes. Bodies include `.`, `..`, `.x`, a leading-dot word and a blank
line. Entire RETR bytes are checked against explicitly stuffed expectations,
including every CRLF and the final dot terminator. Backend handles are
`example-alpha`/`example-bravo`, distinct from wire numbers. Both messages stay in
memory through DELE and are removed exactly once per UID only at QUIT; EOF and
session-goroutine completion are checked. Exact explanatory reply text records
current library output, not additional normative RFC prose. No real backend
persistence, locking, APOP, socket listener or complete RFC coverage is claimed.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-EXAMPLE-01 | RFC 1939 §10 (adapted transaction example); §§3, 5–6, 11 | Normative | Exercise the published 120/200-octet transaction sequence with adapted setup and synthetic bodies: exact STAT/LIST numbers, complete RETR framing, deferred DELE, stable remaining number and successful per-UID QUIT removal/EOF. | TestRFC1939AdaptedTransactionExample |

## RFC 1939 §7: immediate PASS sequencing

`TestPassRequiresImmediateUser` exercises sequential and bounded pipelined
USER, intervening command, PASS sequences through the public Session. CAPA is
still allowed and its exact multiline reply is drained; unknown commands,
pre-auth STAT, malformed USER, empty PASS, a malformed PASS keyword, rejected
CAPA arguments and unavailable STLS all require a fresh USER before PASS.
Every stale PASS receives -ERR without Authenticate, Messages, Retrieve,
MarkSeen or Delete calls. A fresh immediate USER/PASS pair then succeeds with
exactly one Authenticate and one Messages call, followed by QUIT/EOF and joined
Handle. The existing immediate login and authentication-pipeline proofs remain.
This proves selected invalidation paths, not the full USER-allowed sequence,
APOP/SASL, mailbox locking or transport-window behavior. Blank lines retain the
existing ignored-line policy; password spaces remain password data. Exact error
prose is library behavior, not an RFC requirement.

## Validation and boundaries

Run `go run ./internal/checklist internal/rfctest` from the module root. The
checker and its generic negative tests are copied unchanged from go-spf commit
`7d291c08d310b9c62afc287e75a534a39150fafb` (`internal/checklist`). The checker
validates IDs and bidirectional named test mappings; it does not interpret RFC
text or test assertions. `internal/rfctest` is a deliberately scoped package of
real wire tests using the public Session API, an in-memory backend and net.Pipe.
Every test in that package must map to this checklist. Existing root tests and
fuzz targets remain outside this partial mapping; they are still run by CI.
`internal/checklist` also tests mutations of this checklist and its annotations:
missing mappings, unknown IDs and duplicate IDs must fail.
The exact current PARTIAL inventory is **87 mapped rows / 61 named wire tests**.
Example negative-control inputs replace
`TestRFC1939AdaptedTransactionExample` in its row with `TestMissingSessionVector`,
or remove the `POP3-EXAMPLE-01` row while retaining the test annotation; both must
exit nonzero. The scoped mutation test also removes its annotation and empties
its row mapping. UIDL-session controls additionally remove each new test, row
and annotation, and empty each new row mapping; every mutation must fail.
Immediate-PASS controls also remove its test, row and annotation and empty its
row mapping; every mutation must fail. Autologout controls do the same for
POP3-IDLE-01, POP3-IDLE-03, POP3-IDLE-04, POP3-IDLE-05, POP3-IDLE-06,
POP3-IDLE-07 and POP3-IDLE-08.
Generic checker source/tests remain pinned and unchanged.

Immediate-PASS regression validation replaces only `session.go` with baseline
`fe05ed851f2765eb26af5568248892fd2d28fddc`: all 16 sequential/pipelined cases
fail because stale PASS authenticates. Restoring the implementation makes all
16 pass. The checker CLI validates the current inventory, and the generic and
scoped mutation tests reject broken mappings.

Autologout validation temporarily edits only `session.go`, restoring it
byte-for-byte (SHA-256 checked) after each control: a 9m59s deadline fails both
idle tests on the ten-minute bound; a single deadline set before the command loop
fails on zero renewals; deleting marked messages after the read error fails on
backend Delete calls; and an -ERR before closing fails on the unexpected
response. Restored, both pass. This slice changes no runtime code.

The partial-command proof (POP3-IDLE-04) runs the same harness with `QUIT` and
`QUIT\r` (no LF) sent after two DELE marks. net.Pipe completes a Write only when
the server's Read has taken the bytes, and the next Read entry signal proves the
session is waiting for the missing LF, so the partial line is buffered with no
sleep. The underlying read deadline is then moved into the past: the session must
end its Read with `os.ErrDeadlineExceeded`, the client sees EOF with no response
byte, the backend gets zero Delete calls and the messages are unchanged. Its
temporary control makes `readCommandLine` return the buffered partial line on a
read error: the partial QUIT is dispatched, UPDATE runs and the test fails;
`session.go` was restored byte-for-byte (SHA-256 checked). Limits: the timeout is
forced, not a real ten-minute wait; only QUIT variants are covered, not other
partial commands; STLS and pre-login partial commands remain untested.

The pre-login proof (POP3-IDLE-05) uses the same harness with a counting backend.
Greeting-idle and pending-USER states are each reached by the next-Read signal
(no sleeps; no PASS is ever sent). The underlying read deadline is then moved into
the past: the session must end its Read with `os.ErrDeadlineExceeded`
(`net.Error.Timeout()` true), the client sees EOF with no response byte, `Handle`
returns, and backend Authenticate (the only route to a mailbox) was called zero
times. A complete USER before the timeout is independent of the partial-QUIT
cases. Temporary controls on `session.go` (restored byte-for-byte, SHA-256
checked, no runtime file committed): writing `-ERR` on a read error fails both
cases on the unexpected response byte; calling `backend.Authenticate` on a read
error fails both on the Authenticate count. Limits: the timeout is forced, not a
real ten-minute wait; plaintext only, with no TLS/STLS claim (expiry after STLS
remains untested); buffered partial pre-login commands are covered separately below.

The buffered pre-login proof (POP3-IDLE-06) sends incomplete `USER alice` or
`PASS secret` lines, each with either no terminator or CR without LF. PASS cases
first receive a positive reply to a complete USER. The next-Read signal proves
that the partial bytes were buffered before forcing the underlying deadline
into the past. Each case checks a genuine timeout, EOF without a response,
joined Handle completion and zero Authenticate calls before and after timeout.
Temporary negative controls (restored byte-for-byte) dispatch the buffered line
on read error, producing an unexpected reply in all four cases, or call
Authenticate on read error, producing a nonzero backend count in all four cases.
This closes the selected plaintext partial-USER/PASS gap, not arbitrary partial
commands, STLS expiry, or a real ten-minute elapsed-time proof.

The STLS proof (POP3-IDLE-07) records deadlines on the raw `net.Pipe` end below
the `tls.Conn` that STLS installs, which forwards SetDeadline to it. A TLS
session reads several times per record and during the handshake, so each Read
entry reports how many deadlines had been set; the first Read under a new
deadline marks the session waiting for its next command. Three cases run over
TLS 1.3 with a temporary self-signed certificate: idle right after the
handshake, after an encrypted USER, and in TRANSACTION after two DELE marks.
Each deadline is at least ten minutes after both the server's final write
(handshake or encrypted reply) and the client's send time. Forcing the raw
pipe's read deadline into the past yields `os.ErrDeadlineExceeded` below TLS;
the client then reads EOF from close_notify with no POP3 byte, `Handle` returns,
Authenticate ran only for a PASS actually sent, and no Delete happened.
Temporary controls on `session.go` (restored, SHA-256 checked): skipping the
renewal under TLS fails all three cases waiting for the renewed deadline;
writing `-ERR` on a TLS read error fails all three on the response byte;
running QUIT handling on a TLS read error with a mailbox fails the TRANSACTION
case on its `+OK`. Limits: the timeout is forced; partial commands after STLS
are covered separately below.

The buffered STLS proof (POP3-IDLE-08) reuses that harness for six cases over
TLS 1.3: encrypted `USER alice` right after the handshake, `PASS secret` after an
encrypted USER, and `QUIT` in TRANSACTION after two DELE marks, each with no
terminator and with CR but no LF. The client's raw pipe end counts the bytes it
writes below TLS, and the server's raw end records how many bytes it had
consumed when each Read entered. A Read entered after every written byte was
consumed, with no further deadline renewal, proves the decrypted partial line is
buffered and the session waits for its LF, with no sleep. Forcing the raw read
deadline into the past then yields `os.ErrDeadlineExceeded` below TLS; the
client reads EOF from close_notify with no POP3 byte, `Handle` returns,
Authenticate ran only for a complete PASS, and no Delete happened. Temporary
control on `session.go` (restored with git checkout): returning the buffered
partial line on a read error dispatches it, and all six cases fail on the `+`
response byte. Limits: the timeout is forced; only USER, PASS and QUIT partials
are covered.

Follow-ups under [rest-mail/rest-mail-server#374](https://github.com/rest-mail/rest-mail-server/issues/374)
include the remaining AUTHORIZATION inventory (including full USER command
sequencing and mailbox locking/backend contracts), remaining UPDATE integration
contracts, remaining RFC 1939 §3 autologout cases (other partial commands and
transport variants), remaining TOP/UIDL vectors and production cross-session UID persistence,
crash recovery and maildrop lifetime/global UID generation/non-reuse,
remaining TLS/STLS vectors and configuration variants, AUTH/APOP/SASL,
remaining PIPELINING vectors (including other AUTHORIZATION sequences, TLS
and transport-window handling), remaining RESP-CODES semantics (including
hierarchical/unknown-code client handling, the LOGIN-DELAY CAPA tag, production maildrop-lock
integration and backend-classified SYS/TEMP versus SYS/PERM), the full RFC 3206 credential-error
contract for AUTH/APOP/SASL, other extension requirements and CAPA configuration variations,
remaining RFC 2449 command-length/grammar and capability-specific maximum proofs,
complete RFC vectors and differential testing,
overall library coverage ≥95% toward 100%, coverage rationale and badges, and
adoption of the shared reusable workflow. Keep library/root coverage separate
from checker/tool coverage. Existing parser fuzzing, octet-count and log-redaction
work is prior work, not newly claimed here. This partial proof does not close
#374 or the all-principals acceptance work in #376.
