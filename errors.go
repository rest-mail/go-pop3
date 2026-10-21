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
