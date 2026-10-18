# POP3 RFC checklist — PARTIAL checked foundation

This is an explicitly **PARTIAL** checklist for selected AUTHORIZATION,
USER/PASS, CAPA and RFC 1939 §§5–6 TRANSACTION/UPDATE behavior. It is not an inventory of
all applicable RFC requirements, a full conformance claim, or a coverage badge. A mapped row means
its named wire test asserts the stated behavior; it does not prove the entire
referenced section.

Requirements below paraphrase the primary texts:
[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939.txt) and
[RFC 2449](https://www.rfc-editor.org/rfc/rfc2449.txt).
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
Deletion references below cover LIST, RETR and DELE; optional TOP/UIDL are follow-ups.

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
contracts, optional TOP/UIDL,
TLS/STLS, remaining extension requirements and CAPA configuration variations,
RFC 2449 command-length bounds, complete RFC vectors and differential testing,
overall library coverage ≥95% toward 100%, coverage rationale and badges, and
adoption of the shared reusable workflow. Keep library/root coverage separate
from checker/tool coverage. Existing parser fuzzing, octet-count and log-redaction
work is prior work, not newly claimed here. This partial proof does not close
#374 or the all-principals acceptance work in #376.
