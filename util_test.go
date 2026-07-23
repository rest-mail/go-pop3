package pop3

import "testing"

// ── parseCommand ─────────────────────────────────────────────────────

func TestParseCommand_UserCommand(t *testing.T) {
	cmd, arg := parseCommand("USER foo")
	if cmd != "USER" {
		t.Errorf("expected cmd USER, got %q", cmd)
	}
	if arg != "foo" {
		t.Errorf("expected arg foo, got %q", arg)
	}
}

func TestParseCommand_PassCommand(t *testing.T) {
	cmd, arg := parseCommand("PASS bar")
	if cmd != "PASS" {
		t.Errorf("expected cmd PASS, got %q", cmd)
	}
	if arg != "bar" {
		t.Errorf("expected arg bar, got %q", arg)
	}
}

func TestParseCommand_QuitNoArg(t *testing.T) {
	cmd, arg := parseCommand("QUIT")
	if cmd != "QUIT" {
		t.Errorf("expected cmd QUIT, got %q", cmd)
	}
	if arg != "" {
		t.Errorf("expected empty arg, got %q", arg)
	}
}

func TestParseCommand_EmptyString(t *testing.T) {
	cmd, arg := parseCommand("")
	if cmd != "" {
		t.Errorf("expected empty cmd, got %q", cmd)
	}
	if arg != "" {
		t.Errorf("expected empty arg, got %q", arg)
	}
}

func TestParseCommand_StatNoArg(t *testing.T) {
	cmd, arg := parseCommand("STAT")
	if cmd != "STAT" {
		t.Errorf("expected cmd STAT, got %q", cmd)
	}
	if arg != "" {
		t.Errorf("expected empty arg, got %q", arg)
	}
}

func TestParseCommand_RetrWithNumber(t *testing.T) {
	cmd, arg := parseCommand("RETR 1")
	if cmd != "RETR" {
		t.Errorf("expected cmd RETR, got %q", cmd)
	}
	if arg != "1" {
		t.Errorf("expected arg 1, got %q", arg)
	}
}

func TestParseCommand_CaseInsensitivity(t *testing.T) {
	cmd, arg := parseCommand("user alice")
	if cmd != "USER" {
		t.Errorf("expected cmd USER (uppercased), got %q", cmd)
	}
	if arg != "alice" {
		t.Errorf("expected arg alice, got %q", arg)
	}
}

func TestParseCommand_MixedCase(t *testing.T) {
	cmd, arg := parseCommand("rEtR 5")
	if cmd != "RETR" {
		t.Errorf("expected cmd RETR (uppercased), got %q", cmd)
	}
	if arg != "5" {
		t.Errorf("expected arg 5, got %q", arg)
	}
}

func TestParseCommand_ArgWithSpaces(t *testing.T) {
	cmd, arg := parseCommand("PASS my secret password")
	if cmd != "PASS" {
		t.Errorf("expected cmd PASS, got %q", cmd)
	}
	if arg != "my secret password" {
		t.Errorf("expected arg 'my secret password', got %q", arg)
	}
}
