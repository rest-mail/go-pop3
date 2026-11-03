package rfctest

import (
	"bufio"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pop3server "github.com/rest-mail/go-pop3/pkg/pop3/server"

	pop3 "github.com/rest-mail/go-pop3/pkg/pop3"
)

// switchBanLimiter bans every address once ban is set, the way a shared
// limiter bans an address after another of its connections failed too often.
type switchBanLimiter struct {
	pop3.NopLimiter
	ban atomic.Bool
}

func (l *switchBanLimiter) IsBanned(string) bool { return l.ban.Load() }

// countingBackend accepts alice/secret over USER/PASS and SASL PLAIN and
// counts every credential that reaches it.
type countingBackend struct {
	backend
	mu    sync.Mutex
	calls int
}

func (b *countingBackend) Authenticate(user, pass string) (pop3.Mailbox, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	return b.backend.Authenticate(user, pass)
}

func (b *countingBackend) AuthenticatePlain(_, authcid, pass string, _ bool) (pop3.Mailbox, error) {
	return b.Authenticate(authcid, pass)
}

func (b *countingBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// A session opened before its address was banned (issue #90): USER, PASS and
// AUTH are refused with SYS/TEMP before any credential reaches the Backend,
// even the correct password, and the connection closes. SYS/TEMP (RFC 3206
// §4), not AUTH (§5): the ban is temporary and the credentials may be right,
// so the client should retry later instead of asking for a new password. An
// address that is not banned still signs in on the same kind of session.
// checklist: POP3-RESP-CODES-12
func TestBannedSessionRefusedBeforeCredential(t *testing.T) {
	const refusal = "-ERR [SYS/TEMP] Too many authentication failures, try again later"
	cases := []struct {
		name string
		// before runs while the address is not banned yet; refused is sent
		// after the ban.
		before  []string
		refused string
	}{
		{"USER", nil, "USER alice"},
		{"PASS", []string{"USER alice"}, "PASS secret"},
		{"AUTH initial response", nil, "AUTH PLAIN " + plain("", "alice", "secret")},
		// Refused before the "+ " challenge: the credential is never solicited.
		{"AUTH challenge", nil, "AUTH PLAIN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &countingBackend{backend: backend{password: "secret"}}
			limiter := &switchBanLimiter{}
			w := banConnect(t, b, limiter)
			for _, step := range c.before {
				expect(t, w.cmd(step), "+OK")
			}
			limiter.ban.Store(true)
			expect(t, w.cmd(c.refused), refusal)
			w.closed()
			if n := b.count(); n != 0 {
				t.Fatalf("Backend calls = %d, want 0", n)
			}
		})
	}

	t.Run("not banned", func(t *testing.T) {
		b := &countingBackend{backend: backend{password: "secret"}}
		w := banConnect(t, b, &switchBanLimiter{})
		w.login("secret")
		w.status(w.cmd("STAT"), "+OK")
		w2 := banConnect(t, b, &switchBanLimiter{})
		w2.status(w2.cmd("AUTH PLAIN "+plain("", "alice", "secret")), "+OK")
		if n := b.count(); n != 2 {
			t.Fatalf("Backend calls = %d, want 2", n)
		}
	})
}

// banConnect runs a session with the given limiter over net.Pipe.
func banConnect(t *testing.T, b pop3.Backend, limiter pop3.Limiter) *wire {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); pop3server.NewSession(server, b, nil, limiter).Handle() }()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("session did not stop")
		}
	})
	w := &wire{t: t, conn: client, reader: bufio.NewReader(client), done: done}
	w.status(w.line(), "+OK")
	return w
}
