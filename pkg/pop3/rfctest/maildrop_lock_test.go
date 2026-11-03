package rfctest

import (
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pop3 "github.com/rest-mail/go-pop3/pkg/pop3"
)

// lockStore models a host that takes an exclusive maildrop lock (RFC 1939 §4)
// and releases it in pop3.MailboxCloser.Close. The engine never locks; these
// proofs show it opens the maildrop before +OK, never touches it before
// UPDATE, and gives the host a release point, once, on every exit path.
type lockStore struct {
	mu     sync.Mutex
	holder *lockedMailbox
	events []string

	// partialErr makes Authenticate lock the maildrop and then return the
	// Mailbox together with this error.
	partialErr error
	// loadErr and loadPanic act in Messages, after it took the lock.
	loadErr   error
	loadPanic bool
	// closing, when set, is signalled as Close starts, and Close then waits
	// for release.
	closing, release chan struct{}

	opened []*lockedMailbox
}

func (s *lockStore) record(event string) {
	s.events = append(s.events, event)
}

func (s *lockStore) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

func (s *lockStore) locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holder != nil
}

// lock takes the maildrop lock for m, or reports that another session has it.
func (s *lockStore) lock(m *lockedMailbox) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holder != nil && s.holder != m {
		return false
	}
	s.holder = m
	s.record("lock")
	return true
}

func (s *lockStore) Authenticate(user, pass string) (pop3.Mailbox, error) {
	if user != "alice" || pass != "secret" {
		return nil, errors.New("invalid credentials")
	}
	m := &lockedMailbox{store: s}
	s.mu.Lock()
	s.opened = append(s.opened, m)
	partialErr := s.partialErr
	s.mu.Unlock()
	if partialErr != nil {
		s.lock(m)
		return m, partialErr
	}
	return m, nil
}

// mailbox returns the i-th Mailbox Authenticate handed out.
func (s *lockStore) mailbox(t *testing.T, i int) *lockedMailbox {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.opened) {
		t.Fatalf("mailboxes opened = %d, want more than %d", len(s.opened), i)
	}
	return s.opened[i]
}

type lockedMailbox struct {
	store  *lockStore
	loads  int
	closes int
}

func (m *lockedMailbox) Messages() ([]pop3.Message, error) {
	m.store.mu.Lock()
	m.loads++
	loadErr, loadPanic := m.store.loadErr, m.store.loadPanic
	m.store.mu.Unlock()
	if !m.store.lock(m) {
		return nil, pop3.ErrInUse
	}
	if loadPanic {
		panic("maildrop load exploded")
	}
	if loadErr != nil {
		return nil, loadErr
	}
	return []pop3.Message{{UID: "uid-1", Size: 5}, {UID: "uid-2", Size: 5}}, nil
}
func (*lockedMailbox) Retrieve(string) ([]byte, error) { return []byte("Hi\r\n"), nil }
func (*lockedMailbox) MarkSeen(string) error           { return nil }
func (m *lockedMailbox) Delete(uid string) error {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.store.record("delete " + uid)
	return nil
}

// Close releases the lock if this Mailbox holds it.
func (m *lockedMailbox) Close() error {
	if m.store.closing != nil {
		m.store.closing <- struct{}{}
		<-m.store.release
	}
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.closes++
	if m.store.holder == m {
		m.store.holder = nil
		m.store.record("unlock")
	}
	return nil
}

func (m *lockedMailbox) counts() (loads, closes int) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	return m.loads, m.closes
}

// expectReleased fails unless the maildrop is unlocked and m was closed
// exactly once.
func expectReleased(t *testing.T, s *lockStore, m *lockedMailbox) {
	t.Helper()
	if s.locked() {
		t.Fatalf("maildrop still locked (events %q)", s.log())
	}
	if _, closes := m.counts(); closes != 1 {
		t.Fatalf("Close calls = %d, want 1", closes)
	}
}

// expectEOF reads the end of the connection.
func expectEOF(t *testing.T, w *wire) {
	t.Helper()
	_ = w.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := w.reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v, want EOF", err)
	}
	waitStopped(t, w)
}

// RFC 1939 §4: the server acquires exclusive access to the maildrop before
// reporting successful authentication, so the maildrop is not modified or
// removed before UPDATE. The engine opens the maildrop (Messages) before +OK,
// holds the Mailbox for the session without changing the store, and releases
// it only when the session ends; a second session for the same maildrop is
// refused while the first holds it, and gets in once it has left.
// checklist: POP3-LOCK-01
func TestMaildropLockHeldForSession(t *testing.T) {
	s := &lockStore{}
	first := connect(t, s)
	first.login("secret")
	if !s.locked() {
		t.Fatal("+OK sent before the maildrop was locked")
	}

	second := connect(t, s)
	second.status(second.cmd("USER alice"), "+OK")
	if r := second.cmd("PASS secret"); r != "-ERR [IN-USE] Maildrop already in use" {
		t.Fatalf("second PASS = %q, want IN-USE", r)
	}
	if _, closes := s.mailbox(t, 1).counts(); closes != 1 {
		t.Fatalf("refused session's Close calls = %d, want 1", closes)
	}
	if !s.locked() {
		t.Fatal("refused session released the first session's lock")
	}

	first.status(first.cmd("DELE 1"), "+OK")
	first.status(first.cmd("RETR 2"), "+OK")
	if body := first.line(); body != "Hi" {
		t.Fatalf("RETR body = %q", body)
	}
	first.status(first.line(), ".")
	if got := s.log(); !slices.Equal(got, []string{"lock"}) {
		t.Fatalf("store events before UPDATE = %q, want only the lock", got)
	}
	quit(t, first, "+OK")
	expectReleased(t, s, s.mailbox(t, 0))

	second.login("secret")
	if !s.locked() {
		t.Fatal("second session signed in without the lock")
	}
	quit(t, second, "+OK")
	expectReleased(t, s, s.mailbox(t, 2))
	want := []string{"lock", "delete uid-1", "unlock", "lock", "unlock"}
	if got := s.log(); !slices.Equal(got, want) {
		t.Fatalf("store events = %q, want %q", got, want)
	}
}

// RFC 1939 §4: a lock taken while opening the maildrop is released before the
// server refuses access. Whether the lock was taken in Messages, which then
// failed or panicked, or in Authenticate, which then returned the Mailbox
// together with an error (a partial result the engine never uses), the
// Mailbox is closed exactly once before the -ERR reaches the client, and a
// retry can take the lock again.
// checklist: POP3-LOCK-02
func TestMaildropLockReleasedBeforeRefusal(t *testing.T) {
	t.Run("Messages fails", func(t *testing.T) {
		for _, tc := range []struct {
			err   error
			reply string
		}{
			{errors.New("index unreadable"), "-ERR [SYS/TEMP] Failed to load mailbox"},
			{pop3.ErrSystemPermanent, "-ERR [SYS/PERM] Failed to load mailbox"},
			{pop3.ErrInUse, "-ERR [IN-USE] Maildrop already in use"},
		} {
			t.Run(tc.err.Error(), func(t *testing.T) {
				s := &lockStore{loadErr: tc.err}
				w := connect(t, s)
				w.status(w.cmd("USER alice"), "+OK")
				if r := w.cmd("PASS secret"); r != tc.reply {
					t.Fatalf("PASS = %q, want %q", r, tc.reply)
				}
				expectReleased(t, s, s.mailbox(t, 0))

				s.mu.Lock()
				s.loadErr = nil
				s.mu.Unlock()
				w.login("secret")
				quit(t, w, "+OK")
				expectReleased(t, s, s.mailbox(t, 1))
				want := []string{"lock", "unlock", "lock", "unlock"}
				if got := s.log(); !slices.Equal(got, want) {
					t.Fatalf("store events = %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("partial authentication result", func(t *testing.T) {
		for _, tc := range []struct {
			err   error
			reply string
		}{
			{pop3.ErrInUse, "-ERR [IN-USE] Maildrop already in use"},
			{pop3.ErrLoginDelay, "-ERR [LOGIN-DELAY] Logged in too recently"},
			{pop3.ErrSystemTemporary, "-ERR [SYS/TEMP] Authentication unavailable"},
			{errors.New("account disabled"), "-ERR [AUTH] Authentication failed"},
		} {
			t.Run(tc.err.Error(), func(t *testing.T) {
				s := &lockStore{partialErr: tc.err}
				w := connect(t, s)
				w.status(w.cmd("USER alice"), "+OK")
				if r := w.cmd("PASS secret"); r != tc.reply {
					t.Fatalf("PASS = %q, want %q", r, tc.reply)
				}
				m := s.mailbox(t, 0)
				expectReleased(t, s, m)
				if loads, _ := m.counts(); loads != 0 {
					t.Fatalf("Messages calls on a partial result = %d, want 0", loads)
				}
				if r := w.cmd("STAT"); !strings.HasPrefix(r, "-ERR") {
					t.Fatalf("STAT after refused login = %q, want -ERR", r)
				}
				quit(t, w, "+OK")
				expectReleased(t, s, m)
			})
		}
	})

	t.Run("Messages panics", func(t *testing.T) {
		s := &lockStore{loadPanic: true}
		w := connect(t, s)
		w.status(w.cmd("USER alice"), "+OK")
		if r := w.cmd("PASS secret"); r != "-ERR Internal server error" {
			t.Fatalf("PASS = %q, want the recovered panic's -ERR", r)
		}
		expectEOF(t, w)
		expectReleased(t, s, s.mailbox(t, 0))
	})
}

// RFC 1939 §6: after UPDATE the server releases the exclusive-access lock and
// all maildrop resources, then closes the TCP connection. Close is held open
// here: while it runs the connection stays up, and by the time the client
// reads the end of the connection the deletions have been made and the
// Mailbox has been closed exactly once.
// checklist: POP3-UPDATE-07
func TestUpdateReleasesLockBeforeClose(t *testing.T) {
	s := &lockStore{closing: make(chan struct{}, 1), release: make(chan struct{})}
	w := connect(t, s)
	var once sync.Once
	letGo := func() { once.Do(func() { close(s.release) }) }
	t.Cleanup(letGo) // runs before connect's cleanup waits for the session
	w.login("secret")
	w.status(w.cmd("DELE 2"), "+OK")
	w.status(w.cmd("QUIT"), "+OK")

	eof := make(chan error, 1)
	go func() {
		_ = w.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := w.reader.ReadByte()
		eof <- err
	}()
	select {
	case <-s.closing:
	case <-time.After(5 * time.Second):
		t.Fatal("Close not called after QUIT")
	}
	select {
	case err := <-eof:
		t.Fatalf("connection ended (%v) before the lock was released", err)
	case <-time.After(100 * time.Millisecond):
	}
	letGo()
	if err := <-eof; !errors.Is(err, io.EOF) {
		t.Fatalf("after QUIT: %v, want EOF", err)
	}
	// Checked at EOF, before waiting for the session to return: the release
	// must already have happened when the connection closed.
	expectReleased(t, s, s.mailbox(t, 0))
	if got, want := s.log(), []string{"lock", "delete uid-2", "unlock"}; !slices.Equal(got, want) {
		t.Fatalf("store events = %q, want %q", got, want)
	}
	waitStopped(t, w)
}
