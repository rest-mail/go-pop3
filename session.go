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
	utf8     bool // client issued UTF8 (RFC 6856); reset by STLS
	auth     *authState
	mailbox  Mailbox
	messages []Message
	deleted  map[int]bool // sequence numbers marked for deletion
}

type authState struct {
	authenticated bool
	username      string // pending only until the next command
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

		slog.Debug("pop3: recv", "remote", s.conn.RemoteAddr(), "cmd", redactCommand(line))

		cmd, arg := parseCommand(line)
		// RFC 1939 §7: PASS must immediately follow a successful USER.
		// Clear before dispatch so even refused commands and malformed USER
		// invalidate the previous exchange, including an empty command line.
		if cmd != "PASS" {
			s.auth.username = ""
		}

		switch cmd {
		case "CAPA":
			if !s.rejectArg(arg) {
				s.handleCapa()
			}
		case "STLS":
			if !s.rejectArg(arg) && s.handleSTLS() {
				return
			}
		case "UTF8":
			if !s.rejectArg(arg) {
				s.handleUTF8()
			}
		case "USER":
			s.handleUser(arg)
		case "PASS":
			s.handlePass(arg)
		case "STAT":
			if !s.rejectArg(arg) {
				s.handleStat()
			}
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
			if !s.rejectArg(arg) {
				s.handleNoop()
			}
		case "RSET":
			if !s.rejectArg(arg) {
				s.handleRset()
			}
		case "QUIT":
			// A spurious argument makes QUIT a syntax error: reject it and stay in
			// the current state rather than entering the UPDATE phase, so a client
			// that mistyped the line does not unintentionally commit deletions.
			if !s.rejectArg(arg) {
				s.handleQuit()
				return
			}
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
	s.sendLine("AUTH-RESP-CODE")
	s.sendLine("PIPELINING")
	if tag, ok := s.loginDelayTag(); ok {
		s.sendLine("%s", tag)
	}
	if _, ok := s.backend.(UTF8Backend); ok {
		s.sendLine("UTF8")
	}
	s.sendLine(".")
}

// loginDelayTag builds the LOGIN-DELAY capability line (RFC 2449 §6.5) for the
// current state. AUTHORIZATION announces the Backend's minimum, followed by USER
// when the delay varies per user; TRANSACTION announces the user's own value
// when the Mailbox reports one.
func (s *Session) loginDelayTag() (string, bool) {
	b, ok := s.backend.(LoginDelayBackend)
	if !ok {
		return "", false
	}
	seconds, perUser := b.LoginDelay()
	if s.mailbox != nil {
		perUser = false
		if m, ok := s.mailbox.(LoginDelayMailbox); ok {
			seconds = m.LoginDelay()
		}
	}
	if seconds < 0 {
		return "", false
	}
	tag := "LOGIN-DELAY " + strconv.Itoa(seconds)
	if perUser {
		tag += " USER"
	}
	return tag, true
}

// handleUTF8 enables UTF-8 mode (RFC 6856 §3.1). The command is valid only in
// AUTHORIZATION state, and only when the Backend can serve both forms of a
// message; otherwise it is as unknown as before the extension existed.
func (s *Session) handleUTF8() {
	if _, ok := s.backend.(UTF8Backend); !ok {
		s.err("Unknown command")
		return
	}
	if s.auth.authenticated {
		s.err("Command only valid before authentication")
		return
	}
	s.utf8 = true
	s.ok("UTF8 enabled")
}

func (s *Session) handleSTLS() bool {
	// STLS belongs to the AUTHORIZATION state (RFC 2595 §3): it may be issued only
	// before authentication, so the USER/PASS exchange that follows is protected by
	// the freshly negotiated TLS layer. Once the session has entered TRANSACTION
	// state the command is out of sequence — upgrading an already-authenticated
	// connection serves no purpose — and must be refused with -ERR regardless of
	// the current TLS status (issue #17). This state check precedes the usingTLS
	// check so an authenticated session gets the correct "out of sequence" reason
	// rather than an incidental "already using TLS".
	if s.auth.authenticated {
		s.err("Command only valid before authentication")
		return false
	}
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
	// Like the capability list (RFC 2595 §4), a mode the client chose before
	// TLS is not trusted afterwards: it must issue UTF8 again.
	s.utf8 = false

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
	// Consume once, including empty PASS and every backend failure path. Keep
	// the username locally for authentication and logs after clearing state.
	username := s.auth.username
	s.auth.username = ""
	if s.auth.authenticated {
		s.err("Already authenticated")
		return
	}
	if username == "" {
		s.err("USER first")
		return
	}
	if arg == "" {
		s.err("Password required")
		return
	}

	ip := extractIP(s.conn.RemoteAddr().String())

	var mailbox Mailbox
	var err error
	if b, ok := s.backend.(UTF8Backend); ok {
		mailbox, err = b.AuthenticateUTF8(username, arg, s.utf8)
	} else {
		mailbox, err = s.backend.Authenticate(username, arg)
	}
	if errors.Is(err, ErrInUse) {
		// ErrInUse is a backend assertion that the credentials were valid;
		// contention must not earn an authentication-failure ban.
		s.limiter.ResetAuth(ip)
		s.err("[IN-USE] Maildrop already in use")
		return
	}
	if errors.Is(err, ErrLoginDelay) {
		// Like ErrInUse, the credentials were valid: logging in too soon is a
		// backend policy refusal, not an authentication failure.
		s.limiter.ResetAuth(ip)
		s.err("[LOGIN-DELAY] Logged in too recently")
		return
	}
	if errors.Is(err, ErrSystemTemporary) || errors.Is(err, ErrSystemPermanent) {
		// A system outage does not establish whether the credentials were
		// valid. Preserve their failure history without charging a failure.
		slog.Error("pop3: authentication system failure", "error", err)
		s.systemError(err, "Authentication unavailable")
		return
	}
	if err != nil {
		slog.Warn("pop3: auth failed",
			"remote", s.conn.RemoteAddr(),
			"user", username,
			"event", "pop3_auth_failed",
			"ip", ip,
		)
		s.limiter.RecordAuthFail(ip)
		if s.limiter.IsBanned(ip) {
			s.err("[AUTH] Too many authentication failures")
			_ = s.conn.Close()
			return
		}
		s.err("[AUTH] Authentication failed")
		return
	}

	s.limiter.ResetAuth(ip)

	// A backend that returns (nil, nil) authenticated the user but handed us no
	// mailbox. Reject it and stay in AUTHORIZATION rather than dereferencing a
	// nil Mailbox interface below. A backend bug will not heal on retry, so
	// the reply carries RFC 3206 §4 SYS/PERM rather than a credential code.
	if mailbox == nil {
		slog.Error("pop3: backend returned nil mailbox",
			"remote", s.conn.RemoteAddr(),
			"user", username,
		)
		s.err("[SYS/PERM] Failed to load mailbox")
		return
	}

	// Open the maildrop as part of entering TRANSACTION state (RFC 1939 §4). The
	// session must not be marked authenticated until the message list is loaded:
	// if the load fails after we flip the flag, the client is wedged in
	// TRANSACTION with a phantom empty maildrop and cannot re-authenticate.
	messages, err := mailbox.Messages()
	// The credentials were good, so this is not AUTH. A maildrop held by another
	// session is IN-USE (RFC 2449 §8.1.2); other errors use the backend
	// classification or default to SYS/TEMP (RFC 3206 §4).
	if err != nil {
		if errors.Is(err, ErrInUse) {
			s.err("[IN-USE] Maildrop already in use")
			return
		}
		slog.Error("pop3: failed to load mailbox", "error", err)
		s.systemError(err, "Failed to load mailbox")
		return
	}

	// The load succeeded: commit the session to TRANSACTION state atomically.
	s.auth.authenticated = true
	s.mailbox = mailbox
	s.messages = messages

	slog.Info("pop3: authenticated", "remote", s.conn.RemoteAddr(), "user", username, "messages", len(s.messages))
	s.ok("Authentication successful")
}

// systemError keeps backend details out of the wire response. Unclassified
// maildrop errors remain temporary; an explicit permanent error takes priority.
func (s *Session) systemError(err error, message string) {
	code := "SYS/TEMP"
	if errors.Is(err, ErrSystemPermanent) {
		code = "SYS/PERM"
	}
	s.err("[%s] %s", code, message)
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
		uid := s.messages[n-1].UID
		// Fail safe on a non-conforming id (RFC 1939 §7): emitting it verbatim
		// would break the "n uid" line or inject protocol lines (CR/LF). See
		// [validUID].
		if !validUID(uid) {
			slog.Error("pop3: backend supplied invalid UIDL unique-id",
				"remote", s.conn.RemoteAddr(),
				"msg", n,
				"uidlen", len(uid),
			)
			s.err("Invalid unique-id for message")
			return
		}
		s.ok("%d %s", n, uid)
		return
	}

	// All messages. Validate the whole listing BEFORE writing the "+OK" header:
	// once the header is sent the reply is a dot-terminated block we cannot
	// cleanly abort, so a single malformed id emitted mid-list would corrupt the
	// framing. Pre-scan the non-deleted messages and reject the entire command
	// with -ERR if any id is malformed (RFC 1939 §7 grammar) or duplicated (§7
	// requires ids unique within the maildrop; a duplicate breaks leave-on-server
	// de-duplication).
	seen := make(map[string]bool, len(s.messages))
	for i, msg := range s.messages {
		if s.deleted[i+1] {
			continue
		}
		if !validUID(msg.UID) {
			slog.Error("pop3: backend supplied invalid UIDL unique-id",
				"remote", s.conn.RemoteAddr(),
				"msg", i+1,
				"uidlen", len(msg.UID),
			)
			s.err("Invalid unique-id in maildrop")
			return
		}
		if seen[msg.UID] {
			slog.Error("pop3: duplicate UIDL unique-id in maildrop",
				"remote", s.conn.RemoteAddr(),
				"msg", i+1,
			)
			s.err("Duplicate unique-id in maildrop")
			return
		}
		seen[msg.UID] = true
	}

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
	// the "." terminator. An unterminated last line gets its CRLF here too, so
	// octets are counted on exactly the message the client decodes.
	raw := wireMessage(string(rawBytes))

	// The advertised count is the RFC 1939 §11 octet count of the message on the
	// canonical CRLF form: len(raw) == OctetCount(rawBytes). This is the exact
	// value STAT/LIST report via Message.Size when the backend sizes messages with
	// OctetCount, so the two agree (issue #16).
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

	s.ok("")
	// topLines splits headers from body at the first empty line, emits the blank
	// separator, and caps the body at the requested count. Its lines come from
	// splitMessageLines, so no phantom or trailing blank line is emitted (§7).
	for _, line := range topLines(raw, lines) {
		s.sendStuffed(line)
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

// handleNoop answers NOOP. NOOP is a TRANSACTION-state command (RFC 1939 §5):
// like every other post-authentication command it is refused with -ERR while the
// session is still in AUTHORIZATION (issue #11).
func (s *Session) handleNoop() {
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}
	s.ok("")
}

func (s *Session) handleRset() {
	// RSET resets the maildrop and is only meaningful once a maildrop is open, so
	// it belongs to the TRANSACTION state (RFC 1939 §5). Reject it before
	// authentication rather than reporting +OK on a maildrop that does not yet
	// exist (issue #11).
	if !s.auth.authenticated {
		s.err("Not authenticated")
		return
	}
	s.deleted = make(map[int]bool)
	s.ok("Maildrop has %d messages", len(s.messages))
}

func (s *Session) handleQuit() {
	// Enter the UPDATE state (RFC 1939 §6): commit every message the client
	// marked for deletion. If any commit fails, the maildrop update did not fully
	// succeed, so we must NOT report +OK — a +OK tells the client its DELEtes are
	// durable and it may drop local copies, silently losing mail that is still on
	// the server (and leaving UIDLs the client believes are gone). Attempt every
	// deletion regardless, then answer -ERR when any of them failed.
	failed := false
	for n := range s.deleted {
		if n >= 1 && n <= len(s.messages) {
			msg := s.messages[n-1]
			if err := s.mailbox.Delete(msg.UID); err != nil {
				slog.Error("pop3: failed to delete message", "uid", msg.UID, "error", err)
				failed = true
			}
		}
	}

	if failed {
		s.err("some deleted messages not removed")
		return
	}

	s.ok("POP3 server signing off")
}

// rejectArg reports whether a no-argument command carried an unexpected
// argument. STAT, RSET, NOOP, and QUIT (RFC 1939 §3), together with STLS
// (RFC 2595) and CAPA (RFC 2449), are defined to take no arguments, so a
// trailing token makes the command line a syntax error that must be answered
// -ERR rather than silently ignored (issue #14). When arg is non-empty this
// writes the -ERR reply and returns true; the caller then skips the handler and
// preserves transaction state. Dispatch still invalidates pending USER.
// An empty arg returns false so the handler runs normally. Only a
// non-whitespace token counts as an argument, so a stray
// trailing space is tolerated rather than treated as a syntax error.
func (s *Session) rejectArg(arg string) bool {
	if strings.TrimSpace(arg) != "" {
		s.err("Command accepts no arguments")
		return true
	}
	return false
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
	s.sendLine("%s", dotStuff(line))
}
