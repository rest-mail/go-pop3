package pop3

import "strings"

// parseCommand splits a POP3 command line into command and argument. The command
// is upper-cased; the argument is the remainder of the line, if any.
func parseCommand(line string) (string, string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	arg := ""
	if len(parts) > 1 {
		arg = parts[1]
	}
	return cmd, arg
}

// credentialCommands are POP3 verbs whose arguments carry secret material that
// must never be written to logs: PASS (the cleartext password), APOP (a digest
// derived from the shared secret, replayable/attackable if leaked), and AUTH
// (SASL initial responses, which base64-encode credentials). Keys are the
// upper-cased command keyword as returned by parseCommand.
var credentialCommands = map[string]bool{
	"PASS": true,
	"APOP": true,
	"AUTH": true,
}

// redactCommand returns a log-safe rendering of a raw client command line. For
// credential-bearing verbs (see credentialCommands) the entire argument is
// replaced with a fixed marker so no secret — password, auth digest, or SASL
// response — reaches the logs; the command keyword is preserved for
// debuggability. Every other command line is returned verbatim.
//
// This is the redaction boundary for issue #10: the per-command debug log used
// to record the full raw line, writing "PASS <password>" in cleartext.
func redactCommand(line string) string {
	cmd, arg := parseCommand(line)
	if arg != "" && credentialCommands[cmd] {
		return cmd + " <redacted>"
	}
	return line
}

// canonicalCRLF rewrites a stored message's line endings to canonical CRLF for
// POP3 transmission (RFC 1939 §3). Every LF becomes CRLF, an existing CR that
// already precedes an LF is kept (not doubled), and a bare CR not followed by
// LF is passed through verbatim (it is not a line terminator).
//
// This is a security boundary, not cosmetics: RETR/TOP frame the multi-line
// response by splitting on CRLF and dot-stuffing each line. A bare LF in
// attacker-controllable message content would otherwise survive inside a line,
// smuggling a raw line boundary onto the wire that evades dot-stuffing and can
// forge the "CRLF.CRLF" terminator (premature termination, session desync,
// response forgery). Canonicalizing first guarantees every wire line boundary
// is a real CRLF the stuffing and terminator logic can see.
func canonicalCRLF(raw string) string {
	var b strings.Builder
	b.Grow(len(raw) + 16)
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\n':
			// Bare LF (a preceding CR was already consumed by the '\r' case).
			b.WriteString("\r\n")
		case '\r':
			if i+1 < len(raw) && raw[i+1] == '\n' {
				b.WriteString("\r\n")
				i++ // consume the paired LF
			} else {
				b.WriteByte('\r') // bare CR: not a terminator, keep verbatim
			}
		default:
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

// maxUIDLen is the RFC 1939 §7 upper bound on a UIDL unique-id: a unique-id is
// "1 to 70 characters in the range 0x21 to 0x7E".
const maxUIDLen = 70

// validUID reports whether uid conforms to the RFC 1939 §7 unique-id grammar:
// 1 to 70 characters, each a printable ASCII byte in the range 0x21 ('!') to
// 0x7E ('~') inclusive. This rejects the empty string, any id longer than 70
// bytes, the space (0x20), CR, LF, every other control character, DEL (0x7F),
// and all high-bit/non-ASCII bytes. Because every legal byte is single-byte
// ASCII, the byte length is also the character count.
//
// A UID that fails this test cannot be safely interpolated into a UIDL response
// line: a space would split the "n uid" pair the client parses, and a CR or LF
// would terminate the line early or inject an extra protocol line. The engine
// therefore validates each UID at UIDL-response time and answers -ERR rather
// than emitting a malformed reply (issue #15).
func validUID(uid string) bool {
	if len(uid) == 0 || len(uid) > maxUIDLen {
		return false
	}
	for i := 0; i < len(uid); i++ {
		if uid[i] < 0x21 || uid[i] > 0x7E {
			return false
		}
	}
	return true
}

// splitMessageLines splits a canonical CRLF message block into the lines to
// transmit for RETR/TOP. A well-formed block ends in CRLF, so strings.Split on
// "\r\n" yields a trailing "" that is the terminator of the final line, not a
// separate empty line. splitMessageLines drops that single trailing empty
// element so callers do not emit a spurious blank line before the "."
// terminator (RFC 1939 §5.1/§7); the transmitted octets then equal the
// advertised count (§11). An empty block yields no lines.
func splitMessageLines(block string) []string {
	if block == "" {
		return nil
	}
	lines := strings.Split(block, "\r\n")
	if n := len(lines); lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}
