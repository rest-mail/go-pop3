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
	for _, tc := range []struct{ name, checklist, tests, authPipelining, want string }{
		{"valid", checklist, tests, authPipelining, ""},
		{"missing-command-error-test", strings.Replace(checklist, "TestCommandErrorsAuthorization", "TestMissingCommandError", 1), tests, authPipelining, "POP3-COMMAND-01 lists TestMissingCommandError, which is not a test"},
		{"unmapped-command-error-row", strings.Replace(checklist, "| TestCommandErrorsAuthorization, TestCommandErrorsTransaction |", "| |", 1), tests, authPipelining, "POP3-COMMAND-01 names no test"},
		{"missing-annotation", checklist, strings.Replace(tests, "// checklist: POP3-PASS-03", "// mapping removed", 1), authPipelining, "TestAuthenticationFailureRetry does not name POP3-PASS-03"},
		{"missing-test", strings.Replace(checklist, "TestAuthenticationFailureRetry", "TestMissing", 1), tests, authPipelining, "POP3-PASS-03 lists TestMissing, which is not a test"},
		{"unknown-id", checklist, strings.Replace(tests, "// checklist: POP3-PASS-03", "// checklist: POP3-UNKNOWN-99", 1), authPipelining, "names POP3-UNKNOWN-99, which is not in"},
		{"duplicate-id", strings.Replace(checklist, "| POP3-AUTH-02 |", "| POP3-AUTH-01 |", 1), tests, authPipelining, "POP3-AUTH-01 is already used"},
		{"unmapped-row", strings.Replace(checklist, "| TestAuthenticationFailureRetry |", "| |", 1), tests, authPipelining, "POP3-PASS-03 names no test"},
		{"missing-auth-pipeline-success-test", strings.Replace(checklist, "TestAuthPipeliningSuccess", "TestMissingAuthPipeline", 1), tests, authPipelining, "POP3-PIPELINING-06 lists TestMissingAuthPipeline, which is not a test"},
		{"missing-auth-pipeline-retry-test", strings.Replace(checklist, "TestAuthPipeliningFailureRetry", "TestMissingAuthRetry", 1), tests, authPipelining, "POP3-PIPELINING-07 lists TestMissingAuthRetry, which is not a test"},
		{"unmapped-auth-pipeline-success-row", strings.Replace(checklist, "| TestAuthPipeliningSuccess |", "| |", 1), tests, authPipelining, "POP3-PIPELINING-06 names no test"},
		{"unmapped-auth-pipeline-retry-row", strings.Replace(checklist, "| TestAuthPipeliningFailureRetry |", "| |", 1), tests, authPipelining, "POP3-PIPELINING-07 names no test"},
		{"unmapped-auth-pipeline-policy-row", strings.ReplaceAll(checklist, "| TestAuthPipeliningFailureRetry |", "| |"), tests, authPipelining, "POP3-PIPELINING-POLICY-01 names no test"},
		{"missing-auth-pipeline-success-annotation", checklist, tests, strings.Replace(authPipelining, "// checklist: POP3-PIPELINING-06", "// mapping removed", 1), "TestAuthPipeliningSuccess does not name POP3-PIPELINING-06"},
		{"missing-auth-pipeline-retry-annotation", checklist, tests, strings.Replace(authPipelining, "// checklist: POP3-PIPELINING-07 POP3-PIPELINING-POLICY-01", "// mapping removed", 1), "TestAuthPipeliningFailureRetry does not name POP3-PIPELINING-07"},
		{"missing-auth-pipeline-policy-annotation", checklist, tests, strings.Replace(authPipelining, "POP3-PIPELINING-07 POP3-PIPELINING-POLICY-01", "POP3-PIPELINING-07", 1), "TestAuthPipeliningFailureRetry does not name POP3-PIPELINING-POLICY-01"},
		{"unknown-auth-pipeline-id", checklist, tests, strings.Replace(authPipelining, "// checklist: POP3-PIPELINING-06", "// checklist: POP3-UNKNOWN-99", 1), "TestAuthPipeliningSuccess names POP3-UNKNOWN-99, which is not in"},
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
			} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			code := run([]string{"-file", file, dir}, &out, &out)
			if tc.want == "" {
				if code != 0 || !strings.Contains(out.String(), "66 items (66 mapped to tests, 0 not applicable), 42 tests") {
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
