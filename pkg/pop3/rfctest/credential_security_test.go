package rfctest

import (
	"crypto/tls"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	pop3 "github.com/rest-mail/go-pop3/pkg/pop3"
)

// failLimiter counts authentication failures and never bans.
type failLimiter struct {
	pop3.NopLimiter
	fails atomic.Int32
}

func (l *failLimiter) RecordAuthFail(string) { l.fails.Add(1) }

// credentialCall is one login as a Backend received it.
type credentialCall struct {
	user, pass string
	utf8       bool
}

// credentialBackend accepts alice/secret and records every credential that
// reached it, through AuthenticateUTF8 when it is a UTF8Backend and through
// Authenticate when wrapped as plainCredentialBackend.
type credentialBackend struct {
	mu    sync.Mutex
	calls []credentialCall
}

func (b *credentialBackend) record(user, pass string, utf8 bool) (pop3.Mailbox, error) {
	b.mu.Lock()
	b.calls = append(b.calls, credentialCall{user, pass, utf8})
	b.mu.Unlock()
	if user != "alice" || pass != "secret" {
		return nil, errors.New("invalid credentials")
	}
	return mailbox{}, nil
}

func (b *credentialBackend) Authenticate(user, pass string) (pop3.Mailbox, error) {
	return b.record(user, pass, false)
}

func (b *credentialBackend) AuthenticateUTF8(user, pass string, utf8 bool) (pop3.Mailbox, error) {
	return b.record(user, pass, utf8)
}

func (b *credentialBackend) expect(t *testing.T, want ...credentialCall) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.calls) != len(want) {
		t.Fatalf("backend calls = %+v, want %+v", b.calls, want)
	}
	for i := range want {
		if b.calls[i] != want[i] {
			t.Fatalf("backend calls = %+v, want %+v", b.calls, want)
		}
	}
}

// plainCredentialBackend hides AuthenticateUTF8, leaving a plain Backend.
type plainCredentialBackend struct{ b *credentialBackend }

func (p plainCredentialBackend) Authenticate(user, pass string) (pop3.Mailbox, error) {
	return p.b.Authenticate(user, pass)
}

// RFC 6856 §2.2: in UTF-8 mode a user name or password that is not well-formed
// UTF-8 (RFC 3629) is refused. The engine refuses it at USER or PASS, before
// any credential reaches the Backend, with a plain -ERR: no credential was
// checked, so neither [AUTH] nor a Limiter failure applies. Overlong forms and
// encoded surrogates are malformed too. Well-formed non-ASCII credentials
// reach the Backend unchanged (no SASLprep: the UTF8 capability has no USER
// argument). Outside UTF-8 mode, on a UTF8Backend or a plain Backend, the
// arguments are legacy octets and reach the Backend byte for byte.
// checklist: POP3-UTF8-08
func TestUTF8CredentialValidation(t *testing.T) {
	malformed := []struct{ name, value string }{
		{"invalid-byte", "al\xffice"},
		{"truncated", "j\xc3"},
		{"overlong", "\xc0\xafetc"},
		{"surrogate", "x\xed\xa0\x80"},
	}
	for _, tc := range malformed {
		t.Run("utf8-user-"+tc.name, func(t *testing.T) {
			b, l := &credentialBackend{}, &failLimiter{}
			w := saslConnect(t, b, nil, l)
			w.status(w.cmd("UTF8"), "+OK")
			expect(t, w.cmd("USER "+tc.value), "-ERR Username is not valid UTF-8")
			// The refused USER leaves nothing for PASS to complete.
			expect(t, w.cmd("PASS secret"), "-ERR USER first")
			w.login("secret")
			quit(t, w, "+OK")
			b.expect(t, credentialCall{"alice", "secret", true})
			if got := l.fails.Load(); got != 0 {
				t.Fatalf("auth failures = %d, want 0", got)
			}
		})
		t.Run("utf8-pass-"+tc.name, func(t *testing.T) {
			b, l := &credentialBackend{}, &failLimiter{}
			w := saslConnect(t, b, nil, l)
			w.status(w.cmd("UTF8"), "+OK")
			w.status(w.cmd("USER alice"), "+OK")
			expect(t, w.cmd("PASS "+tc.value), "-ERR Password is not valid UTF-8")
			// The refused PASS consumed the USER, as a failed PASS does.
			expect(t, w.cmd("PASS secret"), "-ERR USER first")
			w.login("secret")
			quit(t, w, "+OK")
			b.expect(t, credentialCall{"alice", "secret", true})
			if got := l.fails.Load(); got != 0 {
				t.Fatalf("auth failures = %d, want 0", got)
			}
		})
	}
	t.Run("utf8-well-formed", func(t *testing.T) {
		b := &credentialBackend{}
		w := connect(t, b)
		w.status(w.cmd("UTF8"), "+OK")
		w.status(w.cmd("USER jörg"), "+OK")
		expect(t, w.cmd("PASS pässwörd ✓"), "-ERR [AUTH] Authentication failed")
		quit(t, w, "+OK")
		b.expect(t, credentialCall{"jörg", "pässwörd ✓", true})
	})
	t.Run("legacy-utf8-backend", func(t *testing.T) {
		b := &credentialBackend{}
		w := connect(t, b)
		w.status(w.cmd("USER al\xffice"), "+OK")
		expect(t, w.cmd("PASS p\xe9ss"), "-ERR [AUTH] Authentication failed")
		quit(t, w, "+OK")
		b.expect(t, credentialCall{"al\xffice", "p\xe9ss", false})
	})
	t.Run("legacy-plain-backend", func(t *testing.T) {
		b := &credentialBackend{}
		w := connect(t, plainCredentialBackend{b})
		w.status(w.cmd("USER al\xffice"), "+OK")
		expect(t, w.cmd("PASS p\xe9ss"), "-ERR [AUTH] Authentication failed")
		quit(t, w, "+OK")
		b.expect(t, credentialCall{"al\xffice", "p\xe9ss", false})
	})
	t.Run("legacy-after-stls", func(t *testing.T) {
		// STLS discards UTF-8 mode (POP3-UTF8-04), and with it the check.
		serverConfig, clientConfig := stlsConfigs(t)
		b := &credentialBackend{}
		w := extensionConnect(t, b, serverConfig)
		w.status(w.cmd("UTF8"), "+OK")
		stlsUpgrade(t, w, clientConfig)
		w.status(w.cmd("USER al\xffice"), "+OK")
		expect(t, w.cmd("PASS secret"), "-ERR [AUTH] Authentication failed")
		quit(t, w, "+OK")
		b.expect(t, credentialCall{"al\xffice", "secret", false})
	})
}

// securityBackend is a ConnectionAuthBackend (and a SASL and UTF8 Backend)
// that accepts alice/secret on any connection and tlsonly/secret only over
// TLS, recording every request. Its older methods count calls so a test can
// prove AuthenticateConnection replaced them.
type securityBackend struct {
	mu       sync.Mutex
	requests []pop3.AuthRequest
	older    atomic.Int32
}

func (b *securityBackend) AuthenticateConnection(req pop3.AuthRequest) (pop3.Mailbox, error) {
	b.mu.Lock()
	b.requests = append(b.requests, req)
	b.mu.Unlock()
	if req.User == "tlsonly" && !req.Security.TLS {
		return nil, errors.New("account requires TLS")
	}
	if (req.User != "alice" && req.User != "tlsonly") || req.Pass != "secret" {
		return nil, errors.New("invalid credentials")
	}
	return mailbox{}, nil
}

func (b *securityBackend) Authenticate(string, string) (pop3.Mailbox, error) {
	b.older.Add(1)
	return nil, errors.New("not used")
}

func (b *securityBackend) AuthenticateUTF8(string, string, bool) (pop3.Mailbox, error) {
	b.older.Add(1)
	return nil, errors.New("not used")
}

func (b *securityBackend) AuthenticatePlain(string, string, string, bool) (pop3.Mailbox, error) {
	b.older.Add(1)
	return nil, errors.New("not used")
}

func (b *securityBackend) take(t *testing.T, n int) []pop3.AuthRequest {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.requests) != n {
		t.Fatalf("AuthenticateConnection calls = %d, want %d", len(b.requests), n)
	}
	if got := b.older.Load(); got != 0 {
		t.Fatalf("Authenticate/AuthenticateUTF8/AuthenticatePlain calls = %d, want 0", got)
	}
	return b.requests
}

var (
	_ pop3.ConnectionAuthBackend = (*securityBackend)(nil)
	_ pop3.SASLBackend           = (*securityBackend)(nil)
	_ pop3.UTF8Backend           = (*securityBackend)(nil)
)

// expectTLS checks a request's security against a TLS 1.3 session.
func expectTLS(t *testing.T, sec pop3.ConnectionSecurity, implicit bool) {
	t.Helper()
	if !sec.TLS || sec.ImplicitTLS != implicit {
		t.Fatalf("security TLS=%t ImplicitTLS=%t, want TLS=true ImplicitTLS=%t", sec.TLS, sec.ImplicitTLS, implicit)
	}
	if !sec.State.HandshakeComplete || sec.State.Version != tls.VersionTLS13 || len(sec.State.PeerCertificates) != 0 {
		t.Fatalf("security State = version %x complete=%t peers=%d, want a completed TLS 1.3 handshake without client certificates",
			sec.State.Version, sec.State.HandshakeComplete, len(sec.State.PeerCertificates))
	}
}

// RFC 2595 §2.3: a server that allows clear-text logins SHOULD be able to
// refuse them per user. A ConnectionAuthBackend is told, for every USER/PASS
// and AUTH PLAIN login, whether TLS protects the session and how: not at all,
// after STLS, or from the first byte on the implicit-TLS listener, with the
// negotiated TLS state. It replaces the older Authenticate methods. Refusing
// a plaintext login for policy is an ordinary error: [AUTH], and a failure
// against the Limiter.
// checklist: POP3-STLS-14
func TestConnectionSecurityReachesBackend(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		b, l := &securityBackend{}, &failLimiter{}
		w := saslConnect(t, b, nil, l)
		w.status(w.cmd("USER tlsonly"), "+OK")
		expect(t, w.cmd("PASS secret"), "-ERR [AUTH] Authentication failed")
		expect(t, w.cmd("AUTH PLAIN "+plain("", "tlsonly", "secret")), "-ERR [AUTH] Authentication failed")
		if got := l.fails.Load(); got != 2 {
			t.Fatalf("auth failures = %d, want 2", got)
		}
		w.status(w.cmd("UTF8"), "+OK")
		expect(t, w.cmd("AUTH PLAIN "+plain("admin", "alice", "secret")), "+OK Authentication successful")
		quit(t, w, "+OK")
		reqs := b.take(t, 3)
		want := []pop3.AuthRequest{
			{Mechanism: pop3.MechanismUser, User: "tlsonly", Pass: "secret"},
			{Mechanism: pop3.MechanismPlain, User: "tlsonly", Pass: "secret"},
			{Mechanism: pop3.MechanismPlain, Authzid: "admin", User: "alice", Pass: "secret", UTF8: true},
		}
		for i := range want {
			// A zero ConnectionSecurity also proves State is empty.
			if !reflect.DeepEqual(reqs[i], want[i]) {
				t.Fatalf("request %d = %+v, want %+v", i, reqs[i], want[i])
			}
		}
	})
	t.Run("stls", func(t *testing.T) {
		serverConfig, clientConfig := stlsConfigs(t)
		b := &securityBackend{}
		w := saslConnect(t, b, serverConfig, nil)
		stlsUpgrade(t, w, clientConfig)
		w.status(w.cmd("USER tlsonly"), "+OK")
		expect(t, w.cmd("PASS secret"), "+OK Authentication successful")
		quit(t, w, "+OK")
		req := b.take(t, 1)[0]
		if req.Mechanism != pop3.MechanismUser || req.User != "tlsonly" || req.UTF8 {
			t.Fatalf("request = %+v", req)
		}
		expectTLS(t, req.Security, false)
	})
	t.Run("stls-plain", func(t *testing.T) {
		serverConfig, clientConfig := stlsConfigs(t)
		b := &securityBackend{}
		w := saslConnect(t, b, serverConfig, nil)
		stlsUpgrade(t, w, clientConfig)
		expect(t, w.cmd("AUTH PLAIN "+plain("", "tlsonly", "secret")), "+OK Authentication successful")
		quit(t, w, "+OK")
		req := b.take(t, 1)[0]
		if req.Mechanism != pop3.MechanismPlain || req.User != "tlsonly" {
			t.Fatalf("request = %+v", req)
		}
		expectTLS(t, req.Security, false)
	})
	t.Run("implicit-tls", func(t *testing.T) {
		serverConfig, clientConfig := stlsConfigs(t)
		b := &securityBackend{}
		w := implicitTLSDial(t, implicitTLSServe(t, serverConfig, b), clientConfig)
		w.status(w.cmd("USER tlsonly"), "+OK")
		expect(t, w.cmd("PASS secret"), "+OK Authentication successful")
		w.status(w.cmd("QUIT"), "+OK")
		req := b.take(t, 1)[0]
		if req.Mechanism != pop3.MechanismUser || req.User != "tlsonly" {
			t.Fatalf("request = %+v", req)
		}
		expectTLS(t, req.Security, true)
	})
	t.Run("tls-config-still-gates", func(t *testing.T) {
		// The whole-server switch (POP3-STLS-13) refuses before any request.
		serverConfig, _ := stlsConfigs(t)
		b := &securityBackend{}
		w := saslConnect(t, b, serverConfig, nil)
		expect(t, w.cmd("USER alice"), "-ERR TLS required")
		expect(t, w.cmd("AUTH PLAIN "+plain("", "alice", "secret")), "-ERR TLS required")
		b.take(t, 0)
	})
}
