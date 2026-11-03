package rfctest

import (
	"testing"

	pop3 "github.com/rest-mail/go-pop3/pkg/pop3"
)

// expireBackend announces EXPIRE. Authenticate returns a Mailbox that reports
// the account's own retention only when user is set.
type expireBackend struct {
	commandErrorMailbox
	policy  pop3.Retention
	perUser bool
	user    *pop3.Retention
}

func (b *expireBackend) Expire() (pop3.Retention, bool) { return b.policy, b.perUser }

func (b *expireBackend) Authenticate(user, pass string) (pop3.Mailbox, error) {
	if _, err := b.commandErrorMailbox.Authenticate(user, pass); err != nil {
		return nil, err
	}
	if b.user != nil {
		return &expireMailbox{commandErrorMailbox: &b.commandErrorMailbox, policy: *b.user}, nil
	}
	return &b.commandErrorMailbox, nil
}

type expireMailbox struct {
	*commandErrorMailbox
	policy pop3.Retention
}

func (m *expireMailbox) Expire() pop3.Retention { return m.policy }

var (
	_ pop3.ExpireBackend = (*expireBackend)(nil)
	_ pop3.ExpireMailbox = (*expireMailbox)(nil)
)

// expireCapa reads a whole CAPA response and returns the EXPIRE line, or ""
// when it is absent. The rest of the list is pinned so the tag adds a line
// rather than replacing one.
func expireCapa(t *testing.T, w *wire) string {
	t.Helper()
	expect(t, w.cmd("CAPA"), "+OK Capability list follows")
	for _, line := range []string{"USER", "TOP", "UIDL", "RESP-CODES", "AUTH-RESP-CODE", "PIPELINING"} {
		expect(t, w.line(), line)
	}
	tag := ""
	line := w.line()
	if line != "." {
		tag = line
		expect(t, w.line(), ".")
	}
	return tag
}

// RFC 2449 §6.7: EXPIRE announces the minimum retention in days, or NEVER, in
// both states. A site that keeps messages indefinitely SHOULD announce EXPIRE
// NEVER, and one with an automatic deletion policy SHOULD announce it; EXPIRE 0
// says mail may not be left on the server. When the policy varies per user,
// AUTHORIZATION MUST carry the smallest value that could apply and SHOULD
// append USER, and TRANSACTION SHOULD carry the user's own value. The smallest
// value is the Backend's to compute; the engine announces it unchanged.
// checklist: POP3-CAPA-09 POP3-EXPIRE-01 POP3-EXPIRE-02
func TestCapaExpire(t *testing.T) {
	days := func(n int) *pop3.Retention { return &pop3.Retention{Days: n} }
	never := &pop3.Retention{Never: true}
	for _, tc := range []struct {
		name          string
		policy        pop3.Retention
		perUser       bool
		user          *pop3.Retention
		authorization string
		transaction   string
	}{
		{"never", pop3.Retention{Never: true}, false, nil, "EXPIRE NEVER", "EXPIRE NEVER"},
		{"never-ignores-days", pop3.Retention{Never: true, Days: 30}, false, nil, "EXPIRE NEVER", "EXPIRE NEVER"},
		{"finite", pop3.Retention{Days: 30}, false, nil, "EXPIRE 30", "EXPIRE 30"},
		{"zero", pop3.Retention{}, false, nil, "EXPIRE 0", "EXPIRE 0"},
		{"per-user", pop3.Retention{Days: 5}, true, days(60), "EXPIRE 5 USER", "EXPIRE 60"},
		{"per-user-never", pop3.Retention{Days: 5}, true, never, "EXPIRE 5 USER", "EXPIRE NEVER"},
		{"per-user-zero", pop3.Retention{}, true, days(0), "EXPIRE 0 USER", "EXPIRE 0"},
		{"per-user-no-mailbox-value", pop3.Retention{Days: 5}, true, nil, "EXPIRE 5 USER", "EXPIRE 5"},
		{"never-minimum-has-no-user", pop3.Retention{Never: true}, true, never, "EXPIRE NEVER", "EXPIRE NEVER"},
		{"same-for-everyone", pop3.Retention{Days: 30}, false, days(30), "EXPIRE 30", "EXPIRE 30"},
		{"omitted-before-login", pop3.Retention{Days: -1}, true, days(14), "", "EXPIRE 14"},
		{"omitted-after-login", pop3.Retention{Days: 7}, true, days(-1), "EXPIRE 7 USER", ""},
		{"omitted", pop3.Retention{Days: -1}, false, nil, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &expireBackend{policy: tc.policy, perUser: tc.perUser, user: tc.user}
			w := connect(t, b)
			expect(t, expireCapa(t, w), tc.authorization)
			// A failed login stays in AUTHORIZATION state.
			expect(t, w.cmd("USER alice"), "+OK")
			expect(t, w.cmd("PASS wrong"), "-ERR [AUTH] Authentication failed")
			expect(t, expireCapa(t, w), tc.authorization)
			w.login("secret")
			expect(t, expireCapa(t, w), tc.transaction)
			expect(t, w.cmd("STAT"), "+OK 2 59")
			quit(t, w, "+OK")
			b.calls(t, 2, 1, 0)
		})
	}
}

// A Backend without ExpireBackend never announces the tag, even when its
// Mailbox reports a retention policy.
// checklist: POP3-CAPA-09
func TestCapaExpireRequiresBackend(t *testing.T) {
	m := &commandErrorMailbox{}
	w := connect(t, expireMailboxOnly{m})
	expect(t, expireCapa(t, w), "")
	w.login("secret")
	expect(t, expireCapa(t, w), "")
	quit(t, w, "+OK")
}

type expireMailboxOnly struct{ m *commandErrorMailbox }

func (b expireMailboxOnly) Authenticate(user, pass string) (pop3.Mailbox, error) {
	if _, err := b.m.Authenticate(user, pass); err != nil {
		return nil, err
	}
	return &expireMailbox{commandErrorMailbox: b.m, policy: pop3.Retention{Days: 30}}, nil
}

// expireZeroMailbox serves one retrievable message under EXPIRE 0.
type expireZeroMailbox struct{ commandErrorMailbox }

const expireZeroMessage = "Subject: hi\r\n\r\nbody\r\n"

func (b *expireZeroMailbox) Expire() (pop3.Retention, bool) { return pop3.Retention{}, false }
func (b *expireZeroMailbox) Messages() ([]pop3.Message, error) {
	b.messages.Add(1)
	return []pop3.Message{{UID: "zero-one", Size: pop3.OctetCount([]byte(expireZeroMessage))}}, nil
}
func (b *expireZeroMailbox) Retrieve(string) ([]byte, error) {
	b.retrieve.Add(1)
	return []byte(expireZeroMessage), nil
}
func (b *expireZeroMailbox) Authenticate(user, pass string) (pop3.Mailbox, error) {
	if _, err := b.commandErrorMailbox.Authenticate(user, pass); err != nil {
		return nil, err
	}
	return b, nil
}

// RFC 2449 §6.7: under EXPIRE 0 the server MAY treat every message downloaded
// with RETR as deleted when the session enters UPDATE. Enforcement is the
// host's: the engine announces the policy and deletes only what the client
// DELEted, and the host sees each RETR through MarkSeen.
// checklist: POP3-EXPIRE-02
func TestCapaExpireZeroLeavesDeletionToHost(t *testing.T) {
	b := &expireZeroMailbox{}
	w := connect(t, b)
	expect(t, expireCapa(t, w), "EXPIRE 0")
	w.login("secret")
	expect(t, expireCapa(t, w), "EXPIRE 0")
	expect(t, w.cmd("RETR 1"), "+OK 21 octets")
	for _, line := range []string{"Subject: hi", "", "body", "."} {
		expect(t, w.line(), line)
	}
	quit(t, w, "+OK")
	if got := [3]int32{b.retrieve.Load(), b.seen.Load(), b.deleted.Load()}; got != [3]int32{1, 1, 0} {
		t.Fatalf("retrieve/seen/delete = %v, want [1 1 0]", got)
	}
}
