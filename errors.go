package pop3

import "errors"

// ErrInUse reports that valid credentials were accepted but the user's maildrop
// is already in use by another session (RFC 2449 §8.1.2). Backend.Authenticate or
// Mailbox.Messages may return it, directly or wrapped, only after verifying the
// credentials. The session replies with -ERR [IN-USE], stays in AUTHORIZATION
// and does not count a credential failure against the Limiter.
//
// The backend remains responsible for acquiring and releasing maildrop locks;
// the POP3 engine does not provide locking itself.
var ErrInUse = errors.New("maildrop already in use")

// ErrLoginDelay reports that valid credentials were accepted but the user
// logged in too recently to be allowed in again (RFC 2449 §8.1.1).
// Backend.Authenticate may return it, directly or wrapped, only after verifying
// the credentials. The session replies to PASS with -ERR [LOGIN-DELAY], stays in
// AUTHORIZATION and does not count a credential failure against the Limiter.
// USER never receives it, so the reply does not reveal whether an account
// exists before the password is checked.
//
// The backend remains responsible for tracking login times and choosing the
// delay; the POP3 engine does not enforce one itself.
var ErrLoginDelay = errors.New("login delay has not expired")
