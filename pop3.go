// Package pop3 implements a POP3 server engine, RFC 1939, with zero external
// dependencies (standard library only).
//
// You supply a [Backend] that authenticates users and exposes each user's
// maildrop as a slice of neutral [Message] values; the [Server] speaks the wire
// protocol — USER/PASS, CAPA, STLS, STAT, LIST, UIDL, RETR, TOP, DELE, RSET,
// NOOP and QUIT — and calls back into the Backend to fetch, mark-seen and delete
// messages. The engine holds no assumptions about where mail is stored: a
// Backend can be a database, a filesystem, or a remote API.
//
// The message body served by RETR and TOP is whatever [Mailbox.Retrieve]
// returns, with its line endings canonicalized to CRLF and RFC 1939
// dot-stuffing applied on the wire; the reported octet count is that of the
// canonical form. Messages the client DELEtes are only removed on QUIT,
// matching RFC 1939 update-state semantics.
//
// # Backend
//
// A caller implements three interfaces. [Backend] validates credentials and
// returns a [Mailbox]; [Mailbox] enumerates, retrieves, marks-seen and deletes
// messages; each maildrop entry is a [Message] whose slice position (+1) is the
// POP3 message number for the session. The engine calls [Mailbox.Messages] once
// per session immediately after login, then serves the resulting snapshot.
//
// # Server
//
// [NewServer] builds a [Server] that listens on the plaintext and implicit-TLS
// ports named by [Ports]; [Server.ListenAndServe] opens the listeners.
// [Server.Shutdown] stops accepting and then blocks until the in-flight
// sessions drain (or its context deadline passes), while [Server.Close] stops
// at once, force-closing live connections. To drive a single already-accepted
// connection yourself — behind your own listener or proxy — construct a
// [Session] with [NewSession] and call [Session.Handle].
//
// # TLS and authentication
//
// A non-nil *tls.Config enables both the STLS command (STARTTLS for POP3,
// RFC 2595) on the plaintext port and implicit TLS on the secure port. When a
// TLS config is present the engine refuses USER on a plaintext connection, so
// credentials are never sent in the clear; with no TLS config USER is accepted
// as-is. CAPA advertises the supported extensions (RFC 2449): USER, STLS, TOP,
// UIDL, RESP-CODES and PIPELINING.
//
// # Rate limiting
//
// [NewServer] and [NewSession] accept a [Limiter], a small structural interface
// the engine consults for per-IP connection caps and authentication-failure
// bans. Pass nil or [NopLimiter] to impose no limits, or wire in your own; any
// type with the required methods satisfies it.
package pop3

// Message is one message in a POP3 maildrop, presented oldest-first. Its slice
// position (+1) is the POP3 message number the client uses for the session.
type Message struct {
	// UID is the persistent unique identifier a client sees via UIDL (RFC 1939
	// §7). The Server also passes it back to [Mailbox.Retrieve], [Mailbox.MarkSeen]
	// and [Mailbox.Delete] to name this message.
	//
	// The backend must supply a UID that satisfies the RFC 1939 §7 unique-id
	// contract:
	//
	//   - Grammar: 1 to 70 characters, each a printable ASCII byte in the range
	//     0x21 ('!') to 0x7E ('~') inclusive — no spaces, control characters
	//     (including CR and LF), DEL, or non-ASCII bytes.
	//   - Unique: no two messages in the same maildrop may share a UID.
	//   - Persistent across sessions: a leave-on-server client de-duplicates by
	//     UID, so the same message must present the same UID on every future
	//     connection — even after a session ends without reaching the UPDATE
	//     state. Do not hand out sequence numbers or per-session identifiers.
	//
	// When the engine builds a UIDL response it validates each UID against the
	// grammar and checks the listing for duplicates; a malformed UID, or a
	// maildrop containing a duplicate UID, is answered with -ERR rather than
	// emitting a reply that would corrupt the protocol framing or mislead the
	// client. Persistence across sessions cannot be checked by the engine and
	// remains the backend's responsibility. UIDs passed to Retrieve, MarkSeen and
	// Delete are treated as opaque handles and are not re-validated.
	UID string
	// Size is the message's exact octet count as reported by STAT and LIST — the
	// "exact size of the message in octets" of RFC 1939 §5's scan listing. It MUST
	// be the number of octets RETR transmits for this message, measured on the
	// canonical CRLF wire form: RFC 1939 §11 defines the count by normalizing the
	// stored end-of-line convention to CRLF (a lone LF counts as the two octets
	// CR LF), and the §3 byte-stuffing of leading-dot lines and the CRLF.CRLF
	// terminator are transport framing that is NOT counted. This is exactly the
	// value RETR advertises in its "+OK <n> octets" reply, so a client that
	// pre-allocates or verifies against the LIST/STAT size matches what it
	// receives. Compute it with [OctetCount] on the same bytes [Mailbox.Retrieve]
	// returns; a size derived any other way (e.g. the raw on-disk length of
	// bare-LF content) will disagree with RETR.
	Size int
	// Seen reports whether the message is already marked read. RETR issues a
	// MarkSeen only for a message that was previously unseen; TOP never does.
	Seen bool
}

// OctetCount returns the RFC 1939 §11 octet count of a stored message: the number
// of octets RETR transmits for it, measured on the canonical CRLF wire form. Line
// endings are normalized to CRLF exactly as RETR does before transmission (a lone
// LF or a lone CR-then-LF becomes CR LF, so an end-of-line stored as a single
// character counts as two octets, per §11), while a bare CR that is not a line
// terminator is left unchanged. The §3 byte-stuffing of leading-dot lines and the
// CRLF.CRLF terminator are transport framing and are deliberately excluded, so
// the result matches the "+OK <n> octets" count RETR advertises.
//
// A [Backend] computes [Message.Size] with OctetCount over the same bytes
// [Mailbox.Retrieve] returns so that STAT and LIST agree with RETR to the octet.
func OctetCount(raw []byte) int {
	return len(canonicalCRLF(string(raw)))
}

// Backend authenticates POP3 users. A [Server] calls Authenticate once per
// session, after USER and PASS have both been received.
type Backend interface {
	// Authenticate validates the USER/PASS credentials. Returning a non-nil error
	// rejects the login (the client sees "-ERR ...") and counts as an auth
	// failure against the [Limiter]. On success it returns the [Mailbox] the
	// session operates on.
	Authenticate(user, pass string) (Mailbox, error)
}

// Mailbox is a single authenticated POP3 maildrop. Every method is scoped to the
// user that [Backend.Authenticate] accepted; a Mailbox is used by one session.
type Mailbox interface {
	// Messages returns the maildrop contents oldest-first. It is called once,
	// immediately after authentication.
	Messages() ([]Message, error)
	// Retrieve returns the full RFC 5322 bytes of the message with the given UID.
	// RETR and TOP serve these bytes with line endings canonicalized to CRLF and
	// RFC 1939 dot-stuffing applied; a bare LF in the returned bytes is treated
	// as a line boundary and normalized to CRLF on the wire.
	Retrieve(uid string) ([]byte, error)
	// MarkSeen flags a message read after a successful RETR. POP3 has no read
	// state of its own; implementations without one may return nil.
	MarkSeen(uid string) error
	// Delete permanently removes a message. The Server calls it on QUIT, once for
	// each message the client DELEted during the session.
	Delete(uid string) error
}

// Limiter is the per-IP connection and authentication guard the [Server]
// consults. It is a structural interface: any type with these methods satisfies
// it. Pass [NopLimiter] (or nil) to impose no limits.
type Limiter interface {
	// Accept reports whether a new connection from ip may proceed, incrementing
	// the in-use count when it returns true.
	Accept(ip string) bool
	// Release decrements the in-use count for ip when a connection ends.
	Release(ip string)
	// RecordAuthFail records an authentication failure from ip.
	RecordAuthFail(ip string)
	// IsBanned reports whether ip is currently banned.
	IsBanned(ip string) bool
	// ResetAuth clears the recorded auth-failure history for ip after a success.
	ResetAuth(ip string)
}

// NopLimiter is a [Limiter] that imposes no limits: it accepts every connection
// and never bans. It is the default when a nil Limiter is passed to [NewServer]
// or [NewSession].
type NopLimiter struct{}

func (NopLimiter) Accept(string) bool    { return true }
func (NopLimiter) Release(string)        {}
func (NopLimiter) RecordAuthFail(string) {}
func (NopLimiter) IsBanned(string) bool  { return false }
func (NopLimiter) ResetAuth(string)      {}
