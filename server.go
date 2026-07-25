package pop3

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// Server listens for POP3 connections and spawns a session handler per client.
type Server struct {
	backend   Backend
	tlsConfig *tls.Config
	limiter   Limiter
	listeners []net.Listener
	wg        sync.WaitGroup
	shutdown  chan struct{}
}

// NewServer creates a POP3 Server backed by the given [Backend]. A non-nil
// tlsConfig enables STLS (STARTTLS) and implicit-TLS listeners. A nil limiter
// defaults to [NopLimiter].
func NewServer(backend Backend, tlsConfig *tls.Config, limiter Limiter) *Server {
	if limiter == nil {
		limiter = NopLimiter{}
	}
	return &Server{
		backend:   backend,
		tlsConfig: tlsConfig,
		limiter:   limiter,
		shutdown:  make(chan struct{}),
	}
}

// Ports defines the ports for POP3 services.
type Ports struct {
	POP3    int // 110 (STARTTLS)
	POP3TLS int // 995 (implicit TLS)
}

// ListenAndServe starts POP3 listeners on the specified ports. A zero port is
// skipped. It returns once the listeners are open; connections are served in
// the background until [Server.Shutdown].
func (s *Server) ListenAndServe(ports Ports) error {
	if ports.POP3 > 0 {
		if err := s.listen(ports.POP3, false); err != nil {
			return fmt.Errorf("failed to listen on port %d: %w", ports.POP3, err)
		}
	}
	if ports.POP3TLS > 0 {
		if err := s.listen(ports.POP3TLS, true); err != nil {
			return fmt.Errorf("failed to listen on port %d: %w", ports.POP3TLS, err)
		}
	}
	return nil
}

func (s *Server) listen(port int, implicitTLS bool) error {
	addr := fmt.Sprintf(":%d", port)
	var listener net.Listener
	var err error

	if implicitTLS && s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", addr, s.tlsConfig)
		if err != nil {
			return err
		}
		slog.Info("pop3: listening (implicit TLS)", "port", port)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		slog.Info("pop3: listening", "port", port)
	}

	s.listeners = append(s.listeners, listener)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(listener, implicitTLS)
	}()

	return nil
}

func (s *Server) acceptLoop(listener net.Listener, implicitTLS bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				slog.Error("pop3: accept error", "error", err)
				continue
			}
		}

		ip := extractIP(conn.RemoteAddr().String())

		// Consult the ban list at accept time (issue #17): a client whose repeated
		// authentication failures earned a ban is dropped up front, before a session
		// is created and before it can spend another authentication attempt.
		// Previously the ban was re-checked only after a failed PASS, so a banned IP
		// could reconnect and make one fresh attempt on every connection.
		if s.limiter.IsBanned(ip) {
			slog.Warn("pop3: connection rejected, banned", "ip", ip)
			_ = conn.Close()
			continue
		}

		if !s.limiter.Accept(ip) {
			slog.Warn("pop3: connection rejected by limiter", "ip", ip)
			_ = conn.Close()
			continue
		}

		go func() {
			defer s.limiter.Release(ip)
			session := NewSession(conn, s.backend, s.tlsConfig, s.limiter)
			if implicitTLS {
				session.usingTLS = true
			}
			session.Handle()
		}()
	}
}

// Shutdown gracefully stops the server: it closes all listeners and waits for
// in-flight sessions to finish.
func (s *Server) Shutdown() {
	close(s.shutdown)
	for _, l := range s.listeners {
		_ = l.Close()
	}
	s.wg.Wait()
	slog.Info("pop3: server stopped")
}

// extractIP extracts the IP address from a host:port string.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
