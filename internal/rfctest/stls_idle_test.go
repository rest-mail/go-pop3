package rfctest

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pop3 "github.com/rest-mail/go-pop3"
)

// tlsIdleConn records deadlines below the tls.Conn that STLS installs, which
// forwards SetDeadline to it. A tls.Conn may Read several times per command
// and during the handshake, so each Read entry reports how many deadlines had
// been set: the first Read after a renewal marks the session waiting for its
// next command under that renewed deadline.
type tlsIdleConn struct {
	net.Conn
	mu        sync.Mutex
	lastWrite time.Time
	sets      []deadlineSet
	readErr   error
	reads     chan int
}

func (c *tlsIdleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.lastWrite = time.Now()
	c.mu.Unlock()
	return n, err
}
func (c *tlsIdleConn) SetDeadline(d time.Time) error {
	err := c.Conn.SetDeadline(d)
	c.mu.Lock()
	c.sets = append(c.sets, deadlineSet{deadline: d, afterWrite: c.lastWrite})
	c.mu.Unlock()
	return err
}
func (c *tlsIdleConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	renewals := len(c.sets)
	c.mu.Unlock()
	c.reads <- renewals
	n, err := c.Conn.Read(p)
	if err != nil {
		c.mu.Lock()
		c.readErr = err
		c.mu.Unlock()
	}
	return n, err
}

// awaitRenewal returns the deadline once the session has entered a Read under
// its want-th deadline, that is, after renewing the timer for that interval.
func (c *tlsIdleConn) awaitRenewal(t *testing.T, want int) deadlineSet {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-c.reads:
			if got > want {
				t.Fatalf("%d deadline renewals before the next read, want %d", got, want)
			}
			if got == want {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.sets[want-1]
			}
		case <-timeout:
			t.Fatalf("session did not wait under deadline %d", want)
		}
	}
}

// stlsIdleBackend counts Authenticate calls in front of a mailbox that records
// UPDATE deletions.
type stlsIdleBackend struct {
	*updateMailbox
	calls atomic.Int32
}

func (b *stlsIdleBackend) Authenticate(user, pass string) (pop3.Mailbox, error) {
	b.calls.Add(1)
	return b.updateMailbox.Authenticate(user, pass)
}

// checklist: POP3-IDLE-07
func TestIdleTimeoutAfterSTLS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sent  []string // encrypted commands answered +OK before the timeout
		auths int32
	}{
		{"after-handshake", nil, 0},
		{"after-encrypted-user", []string{"USER alice"}, 0},
		{"transaction-with-marks", []string{"USER alice", "PASS secret", "DELE 1", "DELE 3"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &updateMailbox{
				transactionMailbox: transactionMailbox{raw: transactionMessages},
				attempts:           map[string]int{}, removed: map[string]bool{},
			}
			want, err := m.Messages()
			if err != nil {
				t.Fatal(err)
			}
			b := &stlsIdleBackend{updateMailbox: m}
			serverConfig, clientConfig := stlsConfigs(t)
			client, server := net.Pipe()
			rec := &tlsIdleConn{Conn: server, reads: make(chan int, 1024)}
			done := make(chan struct{})
			go func() { defer close(done); pop3.NewSession(rec, b, serverConfig, nil).Handle() }()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("session did not stop")
				}
			})
			w := &wire{t: t, conn: client, reader: bufio.NewReader(client), done: done}
			w.status(w.line(), "+OK")
			rec.awaitRenewal(t, 1) // The greeting's plaintext idle interval.

			sent := time.Now()
			stlsUpgrade(t, w, clientConfig)
			// The encrypted idle interval is timed from the handshake's final
			// server write and renewed after STLS, not carried over from it.
			set := rec.awaitRenewal(t, 2)
			if set.deadline.Before(set.afterWrite.Add(minIdle)) || set.deadline.Before(sent.Add(minIdle)) {
				t.Fatalf("post-STLS %v is under %v after the handshake or the STLS command sent at %v", set, minIdle, sent)
			}
			renewals := 2
			for _, command := range tc.sent {
				sent := time.Now()
				w.status(w.cmd(command), "+OK")
				renewals++
				set := rec.awaitRenewal(t, renewals)
				if set.deadline.Before(set.afterWrite.Add(minIdle)) || set.deadline.Before(sent.Add(minIdle)) {
					t.Fatalf("%s: %v is under %v after the encrypted reply or the command sent at %v", command, set, minIdle, sent)
				}
			}

			// The session is blocked in an encrypted Read under its renewed
			// deadline. Moving the raw pipe's read deadline into the past
			// stands in for ten idle minutes with a genuine timeout below TLS.
			if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			// No POP3 response: the client sees only TLS closing (close_notify).
			_ = w.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if got, err := w.reader.ReadByte(); !errors.Is(err, io.EOF) {
				t.Fatalf("after autologout: byte %q, err %v, want EOF without a response", got, err)
			}
			waitStopped(t, w)
			rec.mu.Lock()
			readErr := rec.readErr
			rec.mu.Unlock()
			var netErr net.Error
			if !errors.Is(readErr, os.ErrDeadlineExceeded) || !errors.As(readErr, &netErr) || !netErr.Timeout() {
				t.Fatalf("session read ended with %v, want a deadline timeout", readErr)
			}
			if got := b.calls.Load(); got != tc.auths {
				t.Fatalf("Authenticate called %d times, want %d", got, tc.auths)
			}
			// UPDATE was never entered: no Delete, despite any marks.
			deletions(t, m, nil, nil)
			got, err := m.Messages()
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("messages after autologout = %v (%v), want %v", got, err, want)
			}
		})
	}
}
