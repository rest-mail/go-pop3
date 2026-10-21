package pop3

import (
	"slices"
	"testing"
)

// utf8MockBackend is a [UTF8Backend] that records the mode each login saw.
type utf8MockBackend struct {
	*mockBackend
	logins []bool
}

func (m *utf8MockBackend) AuthenticateUTF8(user, pass string, utf8 bool) (Mailbox, error) {
	m.logins = append(m.logins, utf8)
	return m.Authenticate(user, pass)
}

func capaLines(h *pop3Harness) []string {
	h.t.Helper()
	if r := h.cmd("CAPA"); r != "+OK Capability list follows" {
		h.t.Fatalf("CAPA = %q", r)
	}
	return h.readDotBody()
}

// RFC 6856 §3.1: a UTF8Backend advertises UTF8 in both states, accepts UTF8
// before login and passes the chosen mode to AuthenticateUTF8.
func TestUTF8EnabledBeforeLogin(t *testing.T) {
	m := &utf8MockBackend{mockBackend: newMockBackend()}
	h := newPOP3HarnessFor(t, m, m.mockBackend)

	if caps := capaLines(h); !slices.Contains(caps, "UTF8") {
		t.Fatalf("CAPA = %q, want UTF8", caps)
	}
	if r := h.cmd("UTF8 USER"); r != "-ERR Command accepts no arguments" {
		t.Errorf("UTF8 USER = %q", r)
	}
	if r := h.cmd("UTF8"); r != "+OK UTF8 enabled" {
		t.Fatalf("UTF8 = %q", r)
	}
	h.login()
	if !slices.Equal(m.logins, []bool{true}) {
		t.Errorf("AuthenticateUTF8 modes = %v, want [true]", m.logins)
	}
	if r := h.cmd("UTF8"); r != "-ERR Command only valid before authentication" {
		t.Errorf("UTF8 after login = %q", r)
	}
	if caps := capaLines(h); !slices.Contains(caps, "UTF8") {
		t.Errorf("TRANSACTION CAPA = %q, want UTF8", caps)
	}
}

// Without the UTF8 command the UTF8Backend is told to serve downgraded mail.
func TestUTF8NotRequested(t *testing.T) {
	m := &utf8MockBackend{mockBackend: newMockBackend()}
	h := newPOP3HarnessFor(t, m, m.mockBackend)
	h.login()
	if !slices.Equal(m.logins, []bool{false}) {
		t.Errorf("AuthenticateUTF8 modes = %v, want [false]", m.logins)
	}
}

// A plain Backend neither advertises nor accepts UTF8.
func TestUTF8PlainBackend(t *testing.T) {
	h := newPOP3Harness(t, newMockBackend())
	if caps := capaLines(h); slices.Contains(caps, "UTF8") {
		t.Errorf("CAPA = %q, want no UTF8", caps)
	}
	if r := h.cmd("UTF8"); r != "-ERR Unknown command" {
		t.Errorf("UTF8 = %q, want -ERR Unknown command", r)
	}
}
