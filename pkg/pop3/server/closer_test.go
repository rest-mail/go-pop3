package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rest-mail/go-pop3/pkg/pop3"
)

// closingMailbox is a [pop3.MailboxCloser] over a mockMailbox that records
// Delete and Close calls in order.
type closingMailbox struct {
	*mockMailbox
	loadErr       error
	panicRetrieve bool
	closeErr      error
	panicClose    bool

	mu     sync.Mutex
	events []string
	closed chan struct{} // closed by the first Close
}

var _ pop3.MailboxCloser = (*closingMailbox)(nil)

func (m *closingMailbox) record(event string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *closingMailbox) log() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

func (m *closingMailbox) closes() int {
	n := 0
	for _, e := range m.log() {
		if e == "close" {
			n++
		}
	}
	return n
}

func (m *closingMailbox) Messages() ([]pop3.Message, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.mockMailbox.Messages()
}

func (m *closingMailbox) Retrieve(uid string) ([]byte, error) {
	if m.panicRetrieve {
		panic("retrieve exploded")
	}
	return m.mockMailbox.Retrieve(uid)
}

func (m *closingMailbox) Delete(uid string) error {
	m.record("delete " + uid)
	return m.mockMailbox.Delete(uid)
}

func (m *closingMailbox) Close() error {
	m.record("close")
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	if m.panicClose {
		panic("close exploded")
	}
	return m.closeErr
}

// closingBackend hands out a fresh closingMailbox on every successful
// Authenticate. setup, when set, adjusts each new mailbox; it receives the
// login's 0-based index.
type closingBackend struct {
	*mockBackend
	setup func(i int, m *closingMailbox)

	mu     sync.Mutex
	opened []*closingMailbox
}

func newClosingBackend() *closingBackend {
	m := newMockBackend()
	seedThree(m)
	return &closingBackend{mockBackend: m}
}

func (b *closingBackend) Authenticate(user, pass string) (pop3.Mailbox, error) {
	if _, err := b.mockBackend.Authenticate(user, pass); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	m := &closingMailbox{mockMailbox: b.mbox, closed: make(chan struct{})}
	if b.setup != nil {
		b.setup(len(b.opened), m)
	}
	b.opened = append(b.opened, m)
	return m, nil
}

func (b *closingBackend) mailboxes() []*closingMailbox {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.opened)
}

// only returns the one Mailbox the backend handed out.
func (b *closingBackend) only(t *testing.T) *closingMailbox {
	t.Helper()
	opened := b.mailboxes()
	if len(opened) != 1 {
		t.Fatalf("mailboxes opened = %d, want 1", len(opened))
	}
	return opened[0]
}

// closerHarness runs a Session over net.Pipe, letting wrap replace the server
// end of the pipe.
func closerHarness(t *testing.T, b *closingBackend, wrap func(net.Conn) net.Conn) *pop3Harness {
	t.Helper()
	client, server := net.Pipe()
	if wrap != nil {
		server = wrap(server)
	}
	h := &pop3Harness{
		t:    t,
		mock: b.mockBackend,
		conn: client,
		cr:   bufio.NewReader(client),
		cw:   bufio.NewWriter(client),
		done: make(chan struct{}),
	}
	go func() {
		defer close(h.done)
		NewSession(server, b, nil, pop3.NopLimiter{}).Handle()
	}()
	t.Cleanup(func() {
		_ = client.Close()
		<-h.done
	})
	if g := h.readLine(); !strings.HasPrefix(g, "+OK") {
		t.Fatalf("greeting = %q, want +OK...", g)
	}
	return h
}

// ended waits for the session to finish.
func (h *pop3Harness) ended() {
	h.t.Helper()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("session did not end")
	}
}

// expectClosedOnce fails unless m was closed exactly once.
func expectClosedOnce(t *testing.T, m *closingMailbox) {
	t.Helper()
	if n := m.closes(); n != 1 {
		t.Fatalf("Close calls = %d, want 1 (events %q)", n, m.log())
	}
}

// QUIT closes the Mailbox once, after the UPDATE state committed (or tried to
// commit) the deletions, whether or not they all succeeded.
func TestMailboxCloserQuit(t *testing.T) {
	for _, deleteErr := range []error{nil, errors.New("store down")} {
		t.Run(fmt.Sprintf("deleteErr=%v", deleteErr), func(t *testing.T) {
			b := newClosingBackend()
			b.mbox.failDelete(deleteErr)
			h := closerHarness(t, b, nil)
			h.login()
			if r := h.cmd("DELE 2"); !strings.HasPrefix(r, "+OK") {
				t.Fatalf("DELE: %q", r)
			}
			want := "+OK"
			if deleteErr != nil {
				want = "-ERR"
			}
			if r := h.cmd("QUIT"); !strings.HasPrefix(r, want) {
				t.Fatalf("QUIT = %q, want %s", r, want)
			}
			if deleteErr != nil {
				// A failed UPDATE keeps the session open; the client leaves.
				_ = h.conn.Close()
			}
			h.ended()
			m := b.only(t)
			if got, want := m.log(), []string{"delete 9", "close"}; !slices.Equal(got, want) {
				t.Fatalf("events = %q, want %q", got, want)
			}
		})
	}
}

// A client that disconnects without QUIT, or a session that ends after a
// recovered panic, still closes its Mailbox once. An error or a panic from
// Close does not disturb the session's end.
func TestMailboxCloserDisconnectAndPanic(t *testing.T) {
	t.Run("disconnect", func(t *testing.T) {
		b := newClosingBackend()
		b.setup = func(_ int, m *closingMailbox) { m.closeErr = errors.New("upstream gone") }
		h := closerHarness(t, b, nil)
		h.login()
		_ = h.conn.Close()
		h.ended()
		m := b.only(t)
		expectClosedOnce(t, m)
		if d := b.mbox.deletedUIDs(); len(d) != 0 {
			t.Fatalf("deleted %q without QUIT", d)
		}
	})
	t.Run("close panics", func(t *testing.T) {
		b := newClosingBackend()
		b.setup = func(_ int, m *closingMailbox) { m.panicClose = true }
		h := closerHarness(t, b, nil)
		h.login()
		if r := h.cmd("QUIT"); !strings.HasPrefix(r, "+OK") {
			t.Fatalf("QUIT = %q", r)
		}
		h.ended()
		expectClosedOnce(t, b.only(t))
	})
	t.Run("panic", func(t *testing.T) {
		b := newClosingBackend()
		b.setup = func(_ int, m *closingMailbox) { m.panicRetrieve = true }
		h := closerHarness(t, b, nil)
		h.login()
		if r := h.cmd("RETR 1"); r != "-ERR Internal server error" {
			t.Fatalf("RETR = %q", r)
		}
		h.ended()
		expectClosedOnce(t, b.only(t))
	})
}

// shortDeadlineConn turns every session deadline into a short one, so the
// idle timeout fires without waiting ten minutes.
type shortDeadlineConn struct{ net.Conn }

func (c shortDeadlineConn) SetDeadline(time.Time) error {
	return c.Conn.SetDeadline(time.Now().Add(time.Second))
}

// An idle session that times out closes its Mailbox once.
func TestMailboxCloserIdleTimeout(t *testing.T) {
	b := newClosingBackend()
	h := closerHarness(t, b, func(c net.Conn) net.Conn { return shortDeadlineConn{c} })
	h.login()
	h.ended()
	expectClosedOnce(t, b.only(t))
}

// Server.Close ends every session, and each closes its Mailbox once, also
// after a later Shutdown.
func TestMailboxCloserServerClose(t *testing.T) {
	b := newClosingBackend()
	port := freePort(t)
	srv := New(b, nil, nil)
	if err := srv.ListenAndServe(Ports{POP3: port}); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	conn, r := dialPOP3(t, port)
	defer func() { _ = conn.Close() }()
	clientLogin(t, conn, r)

	_ = srv.Close()
	m := b.only(t)
	select {
	case <-m.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Mailbox not closed after Server.Close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	expectClosedOnce(t, m)
}

// A Mailbox the session never uses, because Messages failed after
// Authenticate returned it, is closed straight away; the Mailbox of the retry
// that succeeds is closed when the session ends. A session that never gets a
// Mailbox closes nothing.
func TestMailboxCloserAbandonedLogin(t *testing.T) {
	b := newClosingBackend()
	b.setup = func(i int, m *closingMailbox) {
		if i == 0 {
			m.loadErr = pop3.ErrInUse
		}
	}
	h := closerHarness(t, b, nil)
	if r := h.cmd("USER %s", b.user); !strings.HasPrefix(r, "+OK") {
		t.Fatalf("USER: %q", r)
	}
	if r := h.cmd("PASS %s", b.pass); r != "-ERR [IN-USE] Maildrop already in use" {
		t.Fatalf("PASS = %q", r)
	}
	first := b.only(t)
	expectClosedOnce(t, first)

	h.login()
	if r := h.cmd("QUIT"); !strings.HasPrefix(r, "+OK") {
		t.Fatalf("QUIT = %q", r)
	}
	h.ended()
	opened := b.mailboxes()
	if len(opened) != 2 {
		t.Fatalf("mailboxes opened = %d, want 2", len(opened))
	}
	expectClosedOnce(t, opened[0])
	expectClosedOnce(t, opened[1])

	t.Run("never signed in", func(t *testing.T) {
		b := newClosingBackend()
		h := closerHarness(t, b, nil)
		if r := h.cmd("USER %s", b.user); !strings.HasPrefix(r, "+OK") {
			t.Fatalf("USER: %q", r)
		}
		if r := h.cmd("PASS wrong"); !strings.HasPrefix(r, "-ERR [AUTH]") {
			t.Fatalf("PASS = %q", r)
		}
		if r := h.cmd("QUIT"); !strings.HasPrefix(r, "+OK") {
			t.Fatalf("QUIT = %q", r)
		}
		h.ended()
		if n := len(b.mailboxes()); n != 0 {
			t.Fatalf("mailboxes opened = %d, want 0", n)
		}
	})
}
