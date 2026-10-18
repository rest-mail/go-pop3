# POP3 RFC checklist — PARTIAL checked foundation

This is an explicitly **PARTIAL** checklist for selected AUTHORIZATION,
USER/PASS, CAPA, RFC 1939 §§5–6 TRANSACTION/UPDATE, selected §7 TOP/UIDL
behavior, RFC 2595 §4 STLS transitions and selected RFC 2449 §6.6 PIPELINING
behavior in TRANSACTION. It is not an inventory of all applicable
RFC requirements, a full conformance claim, or a coverage badge. A mapped row means
its named wire test asserts the stated behavior; it does not prove the entire
referenced section.

Requirements below paraphrase the primary texts:
[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939.txt),
[RFC 2449](https://www.rfc-editor.org/rfc/rfc2449.txt), and
[RFC 2595](https://www.rfc-editor.org/rfc/rfc2595.txt).
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

These tests reuse the canonical message corpus and public Session/net.Pipe
helpers with opaque backend UIDs distinct from wire message numbers. UID stability
here means repeated commands within one session, including DELE/RSET; persistence
across sessions, non-reuse over a maildrop's lifetime and backend durability remain
unproved integration follow-ups. Format checks exercise existing fail-safe error
handling, not new runtime work. The duplicate-ID negative case records the
library's current rejection policy, not a claim that the RFC forbids equal hashes
for identical message copies.

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

## RFC 2595 §4: selected POP3 STLS and CAPA transitions

POP3 STLS is specified in RFC 2595 **§4**; §3 specifies IMAP STARTTLS.
These proofs use public Session/net.Pipe with an actual TLS 1.3 handshake,
a temporary self-signed localhost certificate trusted by the client, normal
certificate/hostname verification, bounded client deadlines and joined session
goroutines. TLS 1.3 is the test fixture's choice, not a claimed RFC 2595 mandate.
Re-issued encrypted CAPA verifies the transition, not client cache management.
The two POLICY rows describe existing library choices: configuring TLS refuses
plaintext USER/PASS, and a failed handshake closes the session. They are not
universal RFC mandates. Nil TLS configuration permits plaintext authentication.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| POP3-STLS-01 | RFC 2595 §4; RFC 2449 §5 | Normative | Advertise parameterless STLS through CAPA when available before TLS; omit it and refuse STLS when TLS is not configured. | TestSTLSNoConfig, TestSTLSCredentials |
| POP3-STLS-02 | RFC 2595 §4 | Normative | STLS takes no arguments; refuse extra arguments without starting TLS or losing the plaintext session. | TestSTLSArguments |
| POP3-STLS-03 | RFC 2595 §4 | Normative | Start TLS immediately after the positive STLS reply's CRLF; subsequent POP3 commands use the negotiated TLS layer. | TestSTLSCredentials |
| POP3-STLS-04 | RFC 2595 §4 | Normative | Remain in AUTHORIZATION after STLS; do not grant transaction access until USER/PASS succeeds. | TestSTLSCredentials |
| POP3-STLS-05 | RFC 2595 §4; RFC 2449 §5 | Normative | Re-issued CAPA after TLS omits STLS and retains USER; preserve that encrypted capability list after authentication. | TestSTLSCredentials |
| POP3-STLS-06 | RFC 2595 §4 | Normative | Permit STLS only in AUTHORIZATION; refuse it in TRANSACTION and exercise the permitted refusal when TLS is already active. | TestSTLSStates |
| POP3-TLS-POLICY-01 | RFC 2595 §§2.5, 4 (library policy) | Normative | With TLS configured, refuse plaintext USER/PASS without calling backend authentication; accept valid credentials through TLS exactly once. | TestSTLSCredentials |
| POP3-TLS-POLICY-02 | RFC 2595 §2.5 (library policy) | Normative | Close after a malformed TLS record header during STLS negotiation without calling backend authentication. | TestSTLSHandshakeFailure |

## RFC 2449 §6.6: selected PIPELINING requirements

Each bounded batch is written completely before reading any individual reply,
after ordinary sequential USER/PASS authentication. Public Session/net.Pipe
proofs reuse the canonical CRLF corpus and opaque UIDs distinct from wire
numbers. Exact response lines check order, CRLF, dot stuffing and complete
multiline terminators before subsequent replies. Small batches fit the session's
command-reader buffer, avoiding synchronous net.Pipe write deadlock; this does
not prove arbitrary batch sizes or transport-window handling. Existing bounded
client deadlines and session cleanup apply; no extra goroutines are started.
Authentication/TLS pipelining, all extension combinations, backend lifetime,
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

Follow-ups under [rest-mail/rest-mail-server#374](https://github.com/rest-mail/rest-mail-server/issues/374)
include the complete AUTHORIZATION inventory (notably strict immediate-PASS
sequencing and mailbox locking/backend contracts), remaining UPDATE integration
contracts, remaining TOP/UIDL vectors and cross-session UID persistence/non-reuse,
remaining TLS/STLS vectors and configuration variants, AUTH/APOP/SASL,
remaining PIPELINING vectors (including AUTHORIZATION/TLS and transport-window
handling), RESP-CODES semantics, other extension requirements and CAPA configuration variations,
RFC 2449 command-length bounds, complete RFC vectors and differential testing,
overall library coverage ≥95% toward 100%, coverage rationale and badges, and
adoption of the shared reusable workflow. Keep library/root coverage separate
from checker/tool coverage. Existing parser fuzzing, octet-count and log-redaction
work is prior work, not newly claimed here. This partial proof does not close
#374 or the all-principals acceptance work in #376.
