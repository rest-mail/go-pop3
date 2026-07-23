// Package pop3 implements a POP3 (RFC 1939) server engine with zero external
// dependencies (standard library only).
//
// A caller supplies a [Backend] that authenticates users and exposes each
// user's maildrop as a slice of neutral [Message] values; the [Server] speaks
// the wire protocol — USER/PASS, CAPA, STLS (STARTTLS), STAT, LIST, UIDL, RETR,
// TOP, DELE, RSET, NOOP and QUIT — and calls back into the Backend to fetch,
// mark-seen and delete messages. The engine holds no assumptions about where
// mail is stored: a Backend can be a database, a filesystem, or a remote API.
//
// The message body served by RETR/TOP is whatever [Mailbox.Retrieve] returns,
// byte-for-byte, with RFC 1939 dot-stuffing applied on the wire. Messages the
// client DELEtes are only removed on QUIT, matching RFC 1939 semantics.
package pop3

// Message is one message in a POP3 maildrop, presented oldest-first. Its slice
// position (+1) is the POP3 message number the client uses for the session.
type Message struct {
	// UID is the persistent unique identifier a client sees via UIDL. The Server
	// also passes it back to [Mailbox.Retrieve], [Mailbox.MarkSeen] and
	// [Mailbox.Delete] to name this message. It must be unique and stable within
	// the maildrop for the session's lifetime.
	UID string
	// Size is the octet count reported by STAT and LIST (the RFC 1939 maildrop
	// listing size). It need not equal the exact length Retrieve returns.
	Size int
	// Seen reports whether the message is already marked read. RETR issues a
	// MarkSeen only for a message that was previously unseen; TOP never does.
	Seen bool
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
	// Retrieve returns the full RFC 5322 bytes of the message with the given UID,
	// served verbatim (subject to dot-stuffing) by RETR and TOP.
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
