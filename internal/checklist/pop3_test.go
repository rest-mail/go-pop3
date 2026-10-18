package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPOP3ChecklistMutations checks the real scoped inventory, then proves
// independent mapping failures cannot silently pass the generic checker.
func TestPOP3ChecklistMutations(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	checklist := read("CHECKLIST.md")
	tests := read("internal/rfctest/authorization_test.go")
	transaction := read("internal/rfctest/transaction_test.go")
	update := read("internal/rfctest/update_test.go")
	optional := read("internal/rfctest/optional_test.go")
	stls := read("internal/rfctest/stls_test.go")
	pipelining := read("internal/rfctest/pipelining_test.go")
	responseCodes := read("internal/rfctest/response_codes_test.go")
	commandLength := read("internal/rfctest/command_length_test.go")
	commandErrors := read("internal/rfctest/command_errors_test.go")
	authPipelining := read("internal/rfctest/auth_pipelining_test.go")
	sessionVector := read("internal/rfctest/session_vector_test.go")
	uidSessions := read("internal/rfctest/uidl_sessions_test.go")
	passImmediate := read("internal/rfctest/pass_immediate_test.go")
	idle := read("internal/rfctest/idle_test.go")
	for _, tc := range []struct{ name, checklist, tests, authPipelining, sessionVector, want string }{
		{"valid", checklist, tests, authPipelining, sessionVector, ""},
		{"missing-command-error-test", strings.Replace(checklist, "TestCommandErrorsAuthorization", "TestMissingCommandError", 1), tests, authPipelining, sessionVector, "POP3-COMMAND-01 lists TestMissingCommandError, which is not a test"},
		{"unmapped-command-error-row", strings.Replace(checklist, "| TestCommandErrorsAuthorization, TestCommandErrorsTransaction |", "| |", 1), tests, authPipelining, sessionVector, "POP3-COMMAND-01 names no test"},
		{"missing-annotation", checklist, strings.Replace(tests, "// checklist: POP3-PASS-03", "// mapping removed", 1), authPipelining, sessionVector, "TestAuthenticationFailureRetry does not name POP3-PASS-03"},
		{"missing-test", strings.Replace(checklist, "TestAuthenticationFailureRetry", "TestMissing", 1), tests, authPipelining, sessionVector, "POP3-PASS-03 lists TestMissing, which is not a test"},
		{"unknown-id", checklist, strings.Replace(tests, "// checklist: POP3-PASS-03", "// checklist: POP3-UNKNOWN-99", 1), authPipelining, sessionVector, "names POP3-UNKNOWN-99, which is not in"},
		{"duplicate-id", strings.Replace(checklist, "| POP3-AUTH-02 |", "| POP3-AUTH-01 |", 1), tests, authPipelining, sessionVector, "POP3-AUTH-01 is already used"},
		{"unmapped-row", strings.Replace(checklist, "| TestAuthenticationFailureRetry |", "| |", 1), tests, authPipelining, sessionVector, "POP3-PASS-03 names no test"},
		{"missing-auth-pipeline-success-test", strings.Replace(checklist, "TestAuthPipeliningSuccess", "TestMissingAuthPipeline", 1), tests, authPipelining, sessionVector, "POP3-PIPELINING-06 lists TestMissingAuthPipeline, which is not a test"},
		{"missing-auth-pipeline-retry-test", strings.Replace(checklist, "TestAuthPipeliningFailureRetry", "TestMissingAuthRetry", 1), tests, authPipelining, sessionVector, "POP3-PIPELINING-07 lists TestMissingAuthRetry, which is not a test"},
		{"unmapped-auth-pipeline-success-row", strings.Replace(checklist, "| TestAuthPipeliningSuccess |", "| |", 1), tests, authPipelining, sessionVector, "POP3-PIPELINING-06 names no test"},
		{"unmapped-auth-pipeline-retry-row", strings.Replace(checklist, "| TestAuthPipeliningFailureRetry |", "| |", 1), tests, authPipelining, sessionVector, "POP3-PIPELINING-07 names no test"},
		{"unmapped-auth-pipeline-policy-row", strings.ReplaceAll(checklist, "| TestAuthPipeliningFailureRetry |", "| |"), tests, authPipelining, sessionVector, "POP3-PIPELINING-POLICY-01 names no test"},
		{"missing-auth-pipeline-success-annotation", checklist, tests, strings.Replace(authPipelining, "// checklist: POP3-PIPELINING-06", "// mapping removed", 1), sessionVector, "TestAuthPipeliningSuccess does not name POP3-PIPELINING-06"},
		{"missing-auth-pipeline-retry-annotation", checklist, tests, strings.Replace(authPipelining, "// checklist: POP3-PIPELINING-07 POP3-PIPELINING-POLICY-01", "// mapping removed", 1), sessionVector, "TestAuthPipeliningFailureRetry does not name POP3-PIPELINING-07"},
		{"missing-auth-pipeline-policy-annotation", checklist, tests, strings.Replace(authPipelining, "POP3-PIPELINING-07 POP3-PIPELINING-POLICY-01", "POP3-PIPELINING-07", 1), sessionVector, "TestAuthPipeliningFailureRetry does not name POP3-PIPELINING-POLICY-01"},
		{"unknown-auth-pipeline-id", checklist, tests, strings.Replace(authPipelining, "// checklist: POP3-PIPELINING-06", "// checklist: POP3-UNKNOWN-99", 1), sessionVector, "TestAuthPipeliningSuccess names POP3-UNKNOWN-99, which is not in"},
		{"missing-session-vector-test", strings.Replace(checklist, "TestRFC1939AdaptedTransactionExample", "TestMissingSessionVector", 1), tests, authPipelining, sessionVector, "POP3-EXAMPLE-01 lists TestMissingSessionVector, which is not a test"},
		{"unmapped-session-vector-row", strings.Replace(checklist, "| TestRFC1939AdaptedTransactionExample |", "| |", 1), tests, authPipelining, sessionVector, "POP3-EXAMPLE-01 names no test"},
		{"missing-session-vector-annotation", checklist, tests, authPipelining, strings.Replace(sessionVector, "// checklist: POP3-EXAMPLE-01", "// mapping removed", 1), "TestRFC1939AdaptedTransactionExample does not name POP3-EXAMPLE-01"},
		{"missing-session-vector-row", removeSessionVectorRow(checklist), tests, authPipelining, sessionVector, "TestRFC1939AdaptedTransactionExample names POP3-EXAMPLE-01, which is not in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "CHECKLIST.md")
			for path, content := range map[string]string{
				file: tc.checklist,
				filepath.Join(dir, "authorization_test.go"):   tc.tests,
				filepath.Join(dir, "transaction_test.go"):     transaction,
				filepath.Join(dir, "update_test.go"):          update,
				filepath.Join(dir, "optional_test.go"):        optional,
				filepath.Join(dir, "stls_test.go"):            stls,
				filepath.Join(dir, "pipelining_test.go"):      pipelining,
				filepath.Join(dir, "response_codes_test.go"):  responseCodes,
				filepath.Join(dir, "command_length_test.go"):  commandLength,
				filepath.Join(dir, "command_errors_test.go"):  commandErrors,
				filepath.Join(dir, "auth_pipelining_test.go"): tc.authPipelining,
				filepath.Join(dir, "session_vector_test.go"):  tc.sessionVector,
				filepath.Join(dir, "uidl_sessions_test.go"):   uidSessions,
				filepath.Join(dir, "pass_immediate_test.go"):  passImmediate,
				filepath.Join(dir, "idle_test.go"):            idle,
			} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			code := run([]string{"-file", file, dir}, &out, &out)
			if tc.want == "" {
				if code != 0 || !strings.Contains(out.String(), "75 items (75 mapped to tests, 0 not applicable), 50 tests") {
					t.Fatalf("valid checklist: exit %d\n%s", code, &out)
				}
				return
			}
			if code != 1 || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("exit %d, want 1 and %q:\n%s", code, tc.want, &out)
			}
		})
	}
}

func removeSessionVectorRow(checklist string) string {
	lines := strings.Split(checklist, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "| POP3-EXAMPLE-01 |") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// Each new UIDL-session, immediate-PASS and autologout proof must remain
// connected in both directions. These checker-input mutations never execute or
// alter wire tests.
func TestPOP3UIDLSessionChecklistMutations(t *testing.T) {
	checklist, err := os.ReadFile(filepath.Join("..", "..", "CHECKLIST.md"))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join("..", "rfctest", "*_test.go"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("wire test paths: %v (%v)", paths, err)
	}
	original := map[string]string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		original[filepath.Base(path)] = string(data)
	}
	for _, proof := range []struct{ id, test, file string }{
		{"POP3-UIDL-05", "TestUIDLSequentialSessionsDeleteAndAppend", "uidl_sessions_test.go"},
		{"POP3-UIDL-06", "TestUIDLSequentialSessionsWithoutUpdate", "uidl_sessions_test.go"},
		{"POP3-PASS-05", "TestPassRequiresImmediateUser", "pass_immediate_test.go"},
		{"POP3-IDLE-01", "TestIdleDeadlineReset", "idle_test.go"},
		{"POP3-IDLE-03", "TestIdleAutologoutWithoutUpdate", "idle_test.go"},
		{"POP3-IDLE-04", "TestIdleTimeoutWithBufferedPartialCommand", "idle_test.go"},
		{"POP3-IDLE-05", "TestIdlePreLoginTimeout", "idle_test.go"},
	} {
		var row string
		for _, line := range strings.Split(string(checklist), "\n") {
			if strings.HasPrefix(line, "| "+proof.id+" |") {
				row = line
			}
		}
		if row == "" {
			t.Fatalf("missing real row %s", proof.id)
		}
		source := original[proof.file]
		for _, mutation := range []struct{ name, checklist, source, want string }{
			{"missing-test", string(checklist), strings.Replace(source, "func "+proof.test+"(", "func missingProof(", 1), proof.id + " lists " + proof.test + ", which is not a test"},
			{"missing-row", strings.Replace(string(checklist), row, "", 1), source, proof.test + " names " + proof.id + ", which is not in"},
			{"missing-annotation", string(checklist), strings.Replace(source, "// checklist: "+proof.id, "// mapping removed", 1), proof.test + " does not name " + proof.id},
			{"empty-mapping", strings.Replace(string(checklist), "| "+proof.test+" |", "| |", 1), source, proof.id + " names no test"},
		} {
			t.Run(proof.id+"/"+mutation.name, func(t *testing.T) {
				dir := t.TempDir()
				file := filepath.Join(dir, "CHECKLIST.md")
				if err := os.WriteFile(file, []byte(mutation.checklist), 0o644); err != nil {
					t.Fatal(err)
				}
				for name, content := range original {
					if name == proof.file {
						content = mutation.source
					}
					if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				var out bytes.Buffer
				if code := run([]string{"-file", file, dir}, &out, &out); code != 1 || !strings.Contains(out.String(), mutation.want) {
					t.Fatalf("exit %d, want 1 and %q:\n%s", code, mutation.want, &out)
				}
			})
		}
	}
}
