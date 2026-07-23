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
