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
	for _, tc := range []struct{ name, checklist, tests, want string }{
		{"valid", checklist, tests, ""},
		{"missing-annotation", checklist, strings.Replace(tests, "// checklist: POP3-PASS-03", "// mapping removed", 1), "TestAuthenticationFailureRetry does not name POP3-PASS-03"},
		{"missing-test", strings.Replace(checklist, "TestAuthenticationFailureRetry", "TestMissing", 1), tests, "POP3-PASS-03 lists TestMissing, which is not a test"},
		{"unknown-id", checklist, strings.Replace(tests, "// checklist: POP3-PASS-03", "// checklist: POP3-UNKNOWN-99", 1), "names POP3-UNKNOWN-99, which is not in"},
		{"duplicate-id", strings.Replace(checklist, "| POP3-AUTH-02 |", "| POP3-AUTH-01 |", 1), tests, "POP3-AUTH-01 is already used"},
		{"unmapped-row", strings.Replace(checklist, "| TestAuthenticationFailureRetry |", "| |", 1), tests, "POP3-PASS-03 names no test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "CHECKLIST.md")
			for path, content := range map[string]string{
				file: tc.checklist,
				filepath.Join(dir, "authorization_test.go"): tc.tests,
				filepath.Join(dir, "transaction_test.go"):   transaction,
				filepath.Join(dir, "update_test.go"):        update,
			} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			code := run([]string{"-file", file, dir}, &out, &out)
			if tc.want == "" {
				if code != 0 {
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
