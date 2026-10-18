package rfctest

import (
	"errors"
	"strings"
	"testing"
)

// checklist: POP3-RESP-CODES-01
func TestResponseCodeCapabilities(t *testing.T) {
	w := connect(t, backend{password: "secret"})
	for _, authenticated := range []bool{false, true} {
		if authenticated {
			w.login("secret")
		}
		w.status(w.cmd("CAPA"), "+OK")
		count := 0
		for i := 0; ; i++ {
			if i > 32 {
				t.Fatal("CAPA missing terminator")
			}
			line := w.line()
			if line == "." {
				break
			}
			tag, _, _ := strings.Cut(line, " ")
			if strings.EqualFold(tag, "RESP-CODES") {
				expect(t, line, "RESP-CODES")
				count++
			}
		}
		if count != 1 {
			t.Fatalf("CAPA authenticated=%t: RESP-CODES count = %d, want 1", authenticated, count)
		}
		if authenticated {
			expect(t, w.cmd("STAT"), "+OK 1 42")
		} else {
			expect(t, w.cmd("STAT"), "-ERR Not authenticated")
		}
	}
}

// checklist: POP3-RESP-CODES-02 POP3-RESP-POLICY-01
func TestResponseCodeCredentialFailures(t *testing.T) {
	w := connect(t, backend{password: "secret"})
	for _, credentials := range [][2]string{{"alice", "wrong"}, {"unknown", "secret"}} {
		// USER does not distinguish an existing account from an unknown one.
		expect(t, w.cmd("USER "+credentials[0]), "+OK")
		// Exact equality pins the status separator, brackets, AUTH token and
		// following space; wire.line also checks the actual CRLF framing.
		expect(t, w.cmd("PASS "+credentials[1]), "-ERR [AUTH] Authentication failed")
	}
}

// checklist: POP3-RESP-POLICY-02
func TestResponseCodeAuthenticationRetry(t *testing.T) {
	for _, user := range []string{"alice", "unknown"} {
		t.Run(user, func(t *testing.T) {
			w := connect(t, backend{password: "secret"})
			expect(t, w.cmd("USER "+user), "+OK")
			expect(t, w.cmd("PASS wrong"), "-ERR [AUTH] Authentication failed")
			// Even correct credentials cannot reuse the failed attempt's USER.
			expect(t, w.cmd("PASS secret"), "-ERR USER first")
			expect(t, w.cmd("STAT"), "-ERR Not authenticated")
			expect(t, w.cmd("USER alice"), "+OK")
			expect(t, w.cmd("PASS secret"), "+OK Authentication successful")
			expect(t, w.cmd("STAT"), "+OK 1 42")
			expect(t, w.cmd("NOOP"), "+OK")
		})
	}
}

// checklist: POP3-RESP-POLICY-03
func TestResponseCodeMaildropFailure(t *testing.T) {
	w := connect(t, backend{password: "secret", loadErr: errors.New("private backend detail")})
	for range 2 {
		expect(t, w.cmd("USER alice"), "+OK")
		// Valid credentials followed by Messages failure are not an AUTH error.
		// A plain -ERR is permitted: RESP-CODES does not require a code on every error.
		expect(t, w.cmd("PASS secret"), "-ERR Failed to load mailbox")
		expect(t, w.cmd("PASS secret"), "-ERR USER first")
		expect(t, w.cmd("STAT"), "-ERR Not authenticated")
	}
	expect(t, w.cmd("QUIT"), "+OK POP3 server signing off")
}
