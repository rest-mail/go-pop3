package pop3

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// syncBuffer is a goroutine-safe log sink. The session logs from its own
// goroutine while the test reads from the test goroutine, so the buffer must
// serialize access to stay clean under `go test -race`.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestPOP3_PassNotLoggedInCleartext is the regression guard for issue #10. The
// per-command debug log recorded the full raw line, so `PASS <password>` wrote
// the cleartext password to the logs whenever debug logging was enabled.
//
// Against the old code this test fails: the recv log contains the mock's
// password "s3cret". Against the fix, the PASS argument is redacted before
// logging, so the secret never reaches the sink while the command keyword still
// does (for debuggability).
func TestPOP3_PassNotLoggedInCleartext(t *testing.T) {
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	m := newMockBackend()
	seedThree(m)
	// The harness cleanup (registered after ours) closes the connection and
	// joins the session goroutine first, so no logging races our slog restore.
	h := newPOP3Harness(t, m)
	h.login() // USER + PASS with the mock's valid password ("s3cret").

	// A subsequent reply guarantees the PASS recv-log write already happened in
	// the session goroutine and is visible here.
	if got := h.cmd("NOOP"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("NOOP = %q", got)
	}

	logs := buf.String()
	if strings.Contains(logs, m.pass) {
		t.Errorf("cleartext password %q leaked into logs:\n%s", m.pass, logs)
	}
	// The command keyword must still be logged, redacted, for debuggability.
	if !strings.Contains(logs, "PASS <redacted>") {
		t.Errorf("expected redacted PASS marker in logs, got:\n%s", logs)
	}
}

// TestRedactCommand covers the log-safe rendering of raw command lines directly:
// credential-bearing verbs have their arguments stripped, everything else is
// passed through verbatim.
func TestRedactCommand(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"pass redacted", "PASS s3cret", "PASS <redacted>"},
		{"pass lowercase redacted", "pass s3cret", "PASS <redacted>"},
		{"pass with spaces in secret", "PASS my pass phrase", "PASS <redacted>"},
		{"apop digest redacted", "APOP alice c4c9334bac560ecc979e58001b3e22fb", "APOP <redacted>"},
		{"sasl auth response redacted", "AUTH PLAIN dGVzdAB0ZXN0AHMzY3JldA==", "AUTH <redacted>"},
		{"pass no arg passthrough", "PASS", "PASS"},
		{"user not redacted", "USER alice@example.com", "USER alice@example.com"},
		{"retr not redacted", "RETR 1", "RETR 1"},
		{"quit not redacted", "QUIT", "QUIT"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactCommand(tc.line); got != tc.want {
				t.Errorf("redactCommand(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}
