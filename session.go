package pop3

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// maxCommandLine bounds a single client command line, including its CRLF. RFC
// 1939 §3 keeps commands tiny (a keyword plus short arguments), so this is far
// more than any legitimate line yet small enough that a pre-authentication
// client cannot exhaust memory by streaming an unterminated line. The command
// reader's buffer is sized to this cap; see [Session.readCommandLine].
const maxCommandLine = 1024

// errLineTooLong reports that a command line exceeded [maxCommandLine] bytes
// without a terminating LF.
var errLineTooLong = errors.New("command line too long")

// Session represents a single POP3 conversation with a client.
type Session struct {
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	backend   Backend
	tlsConfig *tls.Config
	limiter   Limiter

	// Session state
	usingTLS bool
	auth     *authState
	mailbox  Mailbox
	messages []Message
	deleted  map[int]bool // sequence numbers marked for deletion
}

type authState struct {
	authenticated bool
	username      string // stored between USER and PASS
}

// NewSession creates a POP3 session over conn, authenticating against backend.
// A nil limiter defaults to [NopLimiter]. Call [Session.Handle] to run it.
func NewSession(conn net.Conn, backend Backend, tlsConfig *tls.Config, limiter Limiter) *Session {
	if limiter == nil {
		limiter = NopLimiter{}
	}
	return &Session{
		conn:      conn,
		reader:    bufio.NewReaderSize(conn, maxCommandLine),
		writer:    bufio.NewWriter(conn),
		backend:   backend,
		tlsConfig: tlsConfig,
		limiter:   limiter,
		auth:      &authState{},
		deleted:   make(map[int]bool),
	}
}

// Handle runs the POP3 state machine until the client disconnects or QUITs.
//
// A panic in any command handler or Backend/Mailbox call is recovered here so a
// single misbehaving session is isolated — logged and answered with -ERR before
// the connection is closed — rather than unwinding the per-connection goroutine
// and crashing the whole process along with every concurrent session.
func (s *Session) Handle() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("pop3: session panic recovered",
				"remote", s.conn.RemoteAddr(),
				"panic", r,
				"stack", string(debug.Stack()),
			)
			// Best-effort notice to the client; the deferred Close follows.
			s.err("Internal server error")
		}
		_ = s.conn.Close()
	}()

	slog.Info("pop3: new connection", "remote", s.conn.RemoteAddr())

	// Send greeting
	s.ok("POP3 server ready")

	for {
		_ = s.conn.SetDeadline(time.Now().Add(10 * time.Minute))

		line, err := s.readCommandLine()
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				// A client streamed a command line past the cap (likely hostile,
				// possibly pre-auth). Refuse it and drop the connection rather than
				// attempt to resynchronize on a line we deliberately truncated.
				slog.Warn("pop3: command line too long",
					"remote", s.conn.RemoteAddr(),
					"limit", maxCommandLine,
				)
				s.err("Command line too long")
				return
			}
			slog.Debug("pop3: connection closed", "remote", s.conn.RemoteAddr(), "error", err)
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		slog.Debug("pop3: recv", "remote", s.conn.RemoteAddr(), "cmd", line)

		cmd, arg := parseCommand(line)

		switch cmd {
		case "CAPA":
			s.handleCapa()
		case "STLS":
			if s.handleSTLS() {
				return
			}
		case "USER":
			s.handleUser(arg)
		case "PASS":
			s.handlePass(arg)
		case "STAT":
			s.handleStat()
		case "LIST":
			s.handleList(arg)
		case "UIDL":
			s.handleUidl(arg)
		case "RETR":
			s.handleRetr(arg)
		case "TOP":
			s.handleTop(arg)
		case "DELE":
			s.handleDele(arg)
		case "NOOP":
			s.ok("")
		case "RSET":
			s.handleRset()
		case "QUIT":
			s.handleQuit()
			return
		default:
			s.err("Unknown command")
		}
	}
}

// readCommandLine reads one LF-terminated command line, refusing to buffer more
// than [maxCommandLine] bytes. The underlying [bufio.Reader] is sized to that
// cap, so ReadSlice returns [bufio.ErrBufferFull] the instant a line fills the
// buffer without an LF — the overflow signal we surface as [errLineTooLong]
// instead of letting an unterminated line grow without limit. The returned slice
// aliases the reader's buffer, so it is copied into a string before returning.
func (s *Session) readCommandLine() (string, error) {
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func (s *Session) handleCapa() {
	s.ok("Capability list follows")
	s.sendLine("USER")
	if !s.usingTLS && s.tlsConfig != nil {
		s.sendLine("STLS")
	}
	s.sendLine("TOP")
	s.sendLine("UIDL")
	s.sendLine("RESP-CODES")
	s.sendLine("PIPELINING")
	s.sendLine(".")
}

func (s *Session) handleSTLS() bool {
	if s.usingTLS {
		s.err("Already using TLS")
		return false
	}
	if s.tlsConfig == nil {
		s.err("TLS not available")
		return false
	}

	s.ok("Begin TLS negotiation")

	tlsConn := tls.Server(s.conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Warn("pop3: TLS handshake failed", "error", err)
		return true
	}

	s.conn = tlsConn
	s.reader = bufio.NewReaderSize(tlsConn, maxCommandLine)
	s.writer = bufio.NewWriter(tlsConn)
	s.usingTLS = true

	slog.Info("pop3: TLS established", "remote", s.conn.RemoteAddr())
	return false
}

func (s *Session) handleUser(arg string) {
	if s.auth.authenticated {
		s.err("Already authenticated")
		return
	}
	if !s.usingTLS && s.tlsConfig != nil {
		s.err("TLS required")
		return
	}
	if arg == "" {
		s.err("Username required")
		return
	}
	s.auth.username = arg
	s.ok("")
}

func (s *Session) handlePass(arg string) {
	if s.auth.authenticated {
		s.err("Already authenticated")
		return
	}
	if s.auth.username == "" {
		s.err("USER first")
		return
	}
	if arg == "" {
		s.err("Password required")
		return
	}

	ip := extractIP(s.conn.RemoteAddr().String())

	mailbox, err := s.backend.Authenticate(s.auth.username, arg)
	if err != nil {
		slog.Warn("pop3: auth failed",
			"remote", s.conn.RemoteAddr(),
			"user", s.auth.username,
			"event", "pop3_auth_failed",
			"ip", ip,
		)
		s.limiter.RecordAuthFail(ip)
		if s.limiter.IsBanned(ip) {
			s.err("Too many authentication failures")
			_ = s.conn.Close()
			return
		}
		s.err("[AUTH] Authentication failed")
		s.auth.username = "" // reset
		return
	}

	s.limiter.ResetAuth(ip)

	// A backend that returns (nil, nil) authenticated the user but handed us no
	// mailbox. Reject it and stay in AUTHORIZATION rather than dereferencing a
	// nil Mailbox interface below.
	if mailbox == nil {
		slog.Error("pop3: backend returned nil mailbox",
			"remote", s.conn.RemoteAddr(),
			"user", s.auth.username,
		)
		s.err("Failed to load mailbox")
		s.auth.username = "" // reset; client may retry
		return
	}

	// Open the maildrop as part of entering TRANSACTION state (RFC 1939 §4). The
	// session must not be marked authenticated until the message list is loaded:
	// if the load fails after we flip the flag, the client is wedged in
	// TRANSACTION with a phantom empty maildrop and cannot re-authenticate.
	messages, err := mailbox.Messages()
	if err != nil {
		slog.Error("pop3: failed to load mailbox", "error", err)
		s.err("Failed to load mailbox")
		s.auth.username = "" // stay in AUTHORIZATION; client may retry
		return
	}

	// The load succeeded: commit the session to TRANSACTION state atomically.
	s.auth.authenticated = true
	s.mailbox = mailbox
	s.messages = messages

	slog.Info("pop3: authenticated", "remote", s.conn.RemoteAddr(), "user", s.auth.username, "messages", len(s.messages))
	s.ok("Authentication successful")
}

func (s *Session) handleStat() {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}

	count := 0
	var totalSize int
	for i, msg := range s.messages {
		if !s.deleted[i+1] {
			count++
			totalSize += msg.Size
		}
	}

	s.ok("%d %d", count, totalSize)
}

func (s *Session) handleList(arg string) {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}

	if arg != "" {
		// Single message
		n, err := strconv.Atoi(arg)
		if err != nil || n < 1 || n > len(s.messages) {
			s.err("No such message")
			return
		}
		if s.deleted[n] {
			s.err("Message is deleted")
			return
		}
		s.ok("%d %d", n, s.messages[n-1].Size)
		return
	}

	// All messages
	count := 0
	var totalSize int
	for i, msg := range s.messages {
		if !s.deleted[i+1] {
			count++
			totalSize += msg.Size
		}
	}

	s.ok("%d messages (%d octets)", count, totalSize)
	for i, msg := range s.messages {
		if !s.deleted[i+1] {
			s.sendLine("%d %d", i+1, msg.Size)
		}
	}
	s.sendLine(".")
}

func (s *Session) handleUidl(arg string) {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}

	if arg != "" {
		// Single message
		n, err := strconv.Atoi(arg)
		if err != nil || n < 1 || n > len(s.messages) {
			s.err("No such message")
			return
		}
		if s.deleted[n] {
			s.err("Message is deleted")
			return
		}
		s.ok("%d %s", n, s.messages[n-1].UID)
		return
	}

	// All messages
	s.ok("")
	for i, msg := range s.messages {
		if !s.deleted[i+1] {
			s.sendLine("%d %s", i+1, msg.UID)
		}
	}
	s.sendLine(".")
}

func (s *Session) handleRetr(arg string) {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}

	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(s.messages) {
		s.err("No such message")
		return
	}
	if s.deleted[n] {
		s.err("Message is deleted")
		return
	}

	msg := s.messages[n-1]

	rawBytes, err := s.mailbox.Retrieve(msg.UID)
	if err != nil {
		s.err("Failed to retrieve message")
		return
	}
	// Canonicalize line endings to CRLF first: a bare LF in stored content must
	// not survive inside a line, or it would evade dot-stuffing and could forge
	// the "." terminator. Octets are counted on this canonical wire form.
	raw := canonicalCRLF(string(rawBytes))

	s.ok("%d octets", len(raw))
	// Send message, byte-stuffing lines starting with ".". splitMessageLines
	// drops the trailing "" that strings.Split leaves for the final line's CRLF,
	// so no spurious blank line is emitted before the "." terminator and the
	// transmitted octets match the advertised count (RFC 1939 §5.1/§11).
	for _, line := range splitMessageLines(raw) {
		s.sendStuffed(line)
	}
	s.sendLine(".")

	// Mark as read
	if !msg.Seen {
		_ = s.mailbox.MarkSeen(msg.UID)
		s.messages[n-1].Seen = true
	}
}

func (s *Session) handleTop(arg string) {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}

	parts := strings.SplitN(arg, " ", 2)
	if len(parts) < 2 {
		s.err("Syntax: TOP msg lines")
		return
	}

	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 1 || n > len(s.messages) {
		s.err("No such message")
		return
	}
	if s.deleted[n] {
		s.err("Message is deleted")
		return
	}

	lines, err := strconv.Atoi(parts[1])
	if err != nil || lines < 0 {
		s.err("Invalid line count")
		return
	}

	msg := s.messages[n-1]
	rawBytes, err := s.mailbox.Retrieve(msg.UID)
	if err != nil {
		s.err("Failed to retrieve message")
		return
	}
	// Canonicalize line endings to CRLF first, so a bare LF cannot hide a line
	// boundary from the header/body split or the per-line dot-stuffing below.
	raw := canonicalCRLF(string(rawBytes))

	// Split into headers and body
	headerEnd := strings.Index(raw, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = len(raw)
	}

	s.ok("")
	// Send headers. splitMessageLines drops the trailing "" that strings.Split
	// leaves when the header block ends in CRLF (a headers-only message), so no
	// phantom header line is emitted (RFC 1939 §7).
	for _, line := range splitMessageLines(raw[:headerEnd]) {
		s.sendStuffed(line)
	}
	s.sendLine("") // blank line separating headers from body

	// Send requested number of body lines. splitMessageLines drops the trailing
	// "" from the body's final CRLF so it is never counted or emitted as an extra
	// blank line when the requested count meets or exceeds the body length.
	if headerEnd+4 <= len(raw) {
		bodyLines := splitMessageLines(raw[headerEnd+4:]) // skip \r\n\r\n
		if lines > len(bodyLines) {
			lines = len(bodyLines)
		}
		for i := 0; i < lines; i++ {
			s.sendStuffed(bodyLines[i])
		}
	}
	s.sendLine(".")
}

func (s *Session) handleDele(arg string) {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}

	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(s.messages) {
		s.err("No such message")
		return
	}
	if s.deleted[n] {
		s.err("Message already deleted")
		return
	}

	s.deleted[n] = true
	s.ok("Message %d deleted", n)
}

func (s *Session) handleRset() {
	s.deleted = make(map[int]bool)
	s.ok("Maildrop has %d messages", len(s.messages))
}

func (s *Session) handleQuit() {
	// Actually delete marked messages
	for n := range s.deleted {
		if n >= 1 && n <= len(s.messages) {
			msg := s.messages[n-1]
			if err := s.mailbox.Delete(msg.UID); err != nil {
				slog.Error("pop3: failed to delete message", "uid", msg.UID, "error", err)
			}
		}
	}

	s.ok("POP3 server signing off")
}

// ── Output helpers ────────────────────────────────────────────────────

func (s *Session) ok(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if msg != "" {
		s.write("+OK " + msg + "\r\n")
	} else {
		s.write("+OK\r\n")
	}
}

func (s *Session) err(format string, args ...interface{}) {
	s.write("-ERR " + fmt.Sprintf(format, args...) + "\r\n")
}

func (s *Session) sendLine(format string, args ...interface{}) {
	s.write(fmt.Sprintf(format, args...) + "\r\n")
}

// write emits a pre-formatted line to the client and flushes. Protocol writes
// are best-effort: a failure surfaces on the next read, so the error is ignored.
func (s *Session) write(line string) {
	_, _ = s.writer.WriteString(line)
	_ = s.writer.Flush()
}

// sendStuffed writes one line of message content with POP3 byte-stuffing
// (RFC 1939): a line beginning with "." gets an extra leading "." so it is not
// mistaken for the "." terminator.
func (s *Session) sendStuffed(line string) {
	if strings.HasPrefix(line, ".") {
		s.sendLine(".%s", line)
	} else {
		s.sendLine("%s", line)
	}
}
