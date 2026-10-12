package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Server struct {
	cfg      *config.ServerConfig
	registry *Registry
	log      *slog.Logger

	mu        sync.Mutex
	tcpStops  map[string]context.CancelFunc
	listeners []net.Listener
}

func New(cfg *config.ServerConfig, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		log:      log,
		tcpStops: make(map[string]context.CancelFunc),
	}
}

func (s *Server) Run(ctx context.Context) error {
	agentLn, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen agent: %w", err)
	}
	s.trackListener(agentLn)
	s.log.Info("agent mux listening", "addr", agentLn.Addr().String())

	httpLn, err := net.Listen("tcp", s.cfg.HTTPGateway)
	if err != nil {
		_ = agentLn.Close()
		return fmt.Errorf("listen http gateway: %w", err)
	}
	s.trackListener(httpLn)
	s.log.Info("http gateway listening", "addr", httpLn.Addr().String())

	go s.serveHTTPGateway(ctx, httpLn)

	go func() {
		<-ctx.Done()
		s.shutdown()
	}()

	for {
		conn, err := agentLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handleAgent(ctx, conn)
	}
}

func (s *Server) trackListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, ln)
}

func (s *Server) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, stop := range s.tcpStops {
		stop()
	}
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
}

func (s *Server) handleAgent(ctx context.Context, conn net.Conn) {
	remote := conn.RemoteAddr().String()
	s.log.Info("agent connected", "remote", remote)
	defer conn.Close()

	sess, err := tunnel.ServerSession(conn)
	if err != nil {
		s.log.Debug("yamux server", "err", err, "remote", remote)
		return
	}
	defer sess.Close()

	hello, ack, err := sess.HandshakeAsServer(s.validateHello)
	if err != nil {
		s.log.Warn("handshake failed", "remote", remote, "err", err)
		return
	}
	s.log.Info("agent registered", "agent_id", ack.AgentID, "tunnels", len(ack.Tunnels))

	for _, assigned := range ack.Tunnels {
		route := &Route{
			AgentID:    ack.AgentID,
			TunnelName: assigned.Name,
			Type:       assigned.Type,
			PublicAddr: assigned.PublicAddr,
			RemotePort: assigned.RemotePort,
			Session:    sess,
		}
		for _, t := range hello.Tunnels {
			if t.Name == assigned.Name {
				route.LocalHint = t.LocalAddr
				break
			}
		}
		if err := s.registry.Register(route); err != nil {
			s.log.Error("register tunnel", "tunnel", assigned.Name, "err", err)
			continue
		}
		if assigned.Type == protocol.TunnelTCP {
			s.startTCPListener(ctx, assigned.Name, assigned.RemotePort)
		}
		s.log.Info("tunnel online",
			"name", assigned.Name,
			"type", assigned.Type,
			"public", assigned.PublicAddr,
		)
	}

	select {
	case <-ctx.Done():
	case <-sess.CloseChan():
	}

	s.registry.UnregisterAgent(ack.AgentID)
	s.stopTCPListenersForAgent(ack.AgentID, ack.Tunnels)
	s.log.Info("agent offline", "agent_id", ack.AgentID)
}

func (s *Server) validateHello(hello protocol.Hello) (*protocol.HelloAck, error) {
	if hello.Version != 0 && hello.Version != protocol.Version {
		return nil, fmt.Errorf("unsupported protocol version %d", hello.Version)
	}
	if hello.Token != s.cfg.Token {
		return nil, fmt.Errorf("invalid token")
	}
	if hello.AgentID == "" {
		return nil, fmt.Errorf("agent_id required")
	}
	if len(hello.Tunnels) == 0 {
		return nil, fmt.Errorf("no tunnels")
	}

	ack := &protocol.HelloAck{
		Version: protocol.Version,
		AgentID: hello.AgentID,
		Message: "ok",
	}

	seen := make(map[string]struct{})
	for _, t := range hello.Tunnels {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			return nil, fmt.Errorf("tunnel name required")
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate tunnel name %q", name)
		}
		seen[name] = struct{}{}

		switch t.Type {
		case protocol.TunnelHTTP:
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       protocol.TunnelHTTP,
				PublicAddr: fmt.Sprintf("http://%s/%s/", s.httpHost(), name),
			})
		case protocol.TunnelTCP:
			port, err := s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, t.RemotePort)
			if err != nil {
				return nil, err
			}
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       protocol.TunnelTCP,
				RemotePort: port,
				PublicAddr: fmt.Sprintf("%s:%d", s.cfg.PublicHost, port),
			})
		default:
			return nil, fmt.Errorf("unsupported tunnel type %q", t.Type)
		}
	}
	return ack, nil
}

func (s *Server) httpHost() string {
	host := s.cfg.PublicHost
	_, port, err := net.SplitHostPort(s.cfg.HTTPGateway)
	if err != nil {
		// :8080 form
		port = strings.TrimPrefix(s.cfg.HTTPGateway, ":")
	}
	if port != "" && port != "80" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func (s *Server) stopTCPListenersForAgent(agentID string, tunnels []protocol.AssignedTunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tunnels {
		if t.Type != protocol.TunnelTCP {
			continue
		}
		if stop, ok := s.tcpStops[t.Name]; ok {
			stop()
			delete(s.tcpStops, t.Name)
		}
		if t.RemotePort > 0 {
			s.registry.ReleasePort(t.RemotePort)
		}
	}
	_ = agentID
}
