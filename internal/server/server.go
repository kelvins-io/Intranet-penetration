package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tlsutil"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Server struct {
	cfg      *config.ServerConfig
	registry *Registry
	store    *store.Store
	log      *slog.Logger

	mu        sync.Mutex
	tcpStops  map[string]context.CancelFunc
	listeners []net.Listener
}

func New(cfg *config.ServerConfig, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	storePath := ""
	if cfg.DataDir != "" {
		storePath = filepath.Join(cfg.DataDir, "store.json")
	}
	st, err := store.Open(storePath)
	if err != nil {
		return nil, err
	}
	if err := st.Bootstrap(cfg.AdminEmail, cfg.AdminPassword, cfg.AdminAPIKey, cfg.Token); err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		store:    st,
		log:      log,
		tcpStops: make(map[string]context.CancelFunc),
	}, nil
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

	if s.cfg.HTTPSGateway != "" {
		tlsCfg, err := tlsutil.LoadOrGenerate(
			absPath(s.cfg.DataDir, s.cfg.TLSCert),
			absPath(s.cfg.DataDir, s.cfg.TLSKey),
			s.cfg.AutoTLS,
			[]string{s.cfg.PublicHost, "localhost", s.cfg.BaseDomain, "*." + s.cfg.BaseDomain},
		)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		raw, err := net.Listen("tcp", s.cfg.HTTPSGateway)
		if err != nil {
			return fmt.Errorf("listen https gateway: %w", err)
		}
		ln := tls.NewListener(raw, tlsCfg)
		s.trackListener(ln)
		s.log.Info("https gateway listening", "addr", ln.Addr().String())
		go s.serveHTTPGateway(ctx, ln)
	}

	s.log.Info("control plane ready",
		"dashboard", fmt.Sprintf("http://%s/dashboard/", s.httpAdvertiseHost()),
		"admin_api_key_hint", maskKey(s.store.AdminAPIKey()),
	)

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

func absPath(dir, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

func maskKey(k string) string {
	if len(k) <= 8 {
		return "***"
	}
	return k[:4] + "..." + k[len(k)-4:]
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

// Close releases runtime resources (listeners are closed via shutdown).
func (s *Server) Close() {
	s.shutdown()
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

	var tenant *store.Tenant
	hello, ack, err := sess.HandshakeAsServer(func(h protocol.Hello) (*protocol.HelloAck, error) {
		a, t, err := s.validateHello(h)
		if err != nil {
			return nil, err
		}
		tenant = t
		return a, nil
	})
	if err != nil {
		s.log.Warn("handshake failed", "remote", remote, "err", err)
		return
	}
	s.log.Info("agent registered",
		"agent_id", ack.AgentID,
		"tenant", tenant.Slug,
		"tunnels", len(ack.Tunnels),
	)
	s.store.Audit(tenant.ID, ack.AgentID, "agent.connect", ack.AgentID, remote)

	for _, assigned := range ack.Tunnels {
		route := &Route{
			TenantID:   tenant.ID,
			TenantSlug: tenant.Slug,
			AgentID:    ack.AgentID,
			TunnelName: assigned.Name,
			Type:       assigned.Type,
			PublicAddr: assigned.PublicAddr,
			Domain:     assigned.Domain,
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
		_, _ = s.store.UpsertTunnel(store.TunnelRecord{
			TenantID:   tenant.ID,
			Name:       assigned.Name,
			Type:       string(assigned.Type),
			LocalHint:  route.LocalHint,
			Domain:     assigned.Domain,
			PublicAddr: assigned.PublicAddr,
			RemotePort: assigned.RemotePort,
			AgentID:    ack.AgentID,
			Online:     true,
		})
		if assigned.Type == protocol.TunnelTCP {
			s.startTCPListener(ctx, route.Key(), assigned.RemotePort, tenant.ID, assigned.Name)
		}
		s.log.Info("tunnel online",
			"tenant", tenant.Slug,
			"name", assigned.Name,
			"type", assigned.Type,
			"public", assigned.PublicAddr,
			"domain", assigned.Domain,
		)
		s.store.Audit(tenant.ID, ack.AgentID, "tunnel.online", assigned.Name, assigned.PublicAddr)
	}

	select {
	case <-ctx.Done():
	case <-sess.CloseChan():
	}

	s.registry.UnregisterAgent(tenant.ID, ack.AgentID)
	s.stopTCPListenersForAgent(tenant.ID, ack.AgentID, ack.Tunnels)
	s.store.MarkAgentOffline(tenant.ID, ack.AgentID)
	s.store.Audit(tenant.ID, ack.AgentID, "agent.disconnect", ack.AgentID, "")
	s.log.Info("agent offline", "agent_id", ack.AgentID, "tenant", tenant.Slug)
}

func (s *Server) validateHello(hello protocol.Hello) (*protocol.HelloAck, *store.Tenant, error) {
	if hello.Version != 0 && hello.Version != protocol.Version {
		return nil, nil, fmt.Errorf("unsupported protocol version %d", hello.Version)
	}
	if hello.AgentID == "" {
		return nil, nil, fmt.Errorf("agent_id required")
	}
	if len(hello.Tunnels) == 0 {
		return nil, nil, fmt.Errorf("no tunnels")
	}

	_, tenant, err := s.store.ResolveAgentToken(hello.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token")
	}

	names := make([]string, 0, len(hello.Tunnels))
	types := make([]string, 0, len(hello.Tunnels))
	for _, t := range hello.Tunnels {
		names = append(names, strings.TrimSpace(t.Name))
		types = append(types, string(t.Type))
	}
	if err := s.store.CheckTunnelQuota(tenant.ID, hello.AgentID, names, types); err != nil {
		return nil, nil, err
	}

	ack := &protocol.HelloAck{
		Version:  protocol.Version,
		AgentID:  hello.AgentID,
		TenantID: tenant.ID,
		Message:  "ok",
	}

	seen := make(map[string]struct{})
	for _, t := range hello.Tunnels {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			return nil, nil, fmt.Errorf("tunnel name required")
		}
		if _, ok := seen[name]; ok {
			return nil, nil, fmt.Errorf("duplicate tunnel name %q", name)
		}
		seen[name] = struct{}{}

		domain := strings.ToLower(strings.TrimSpace(t.Domain))
		switch t.Type {
		case protocol.TunnelHTTP:
			if domain == "" {
				domain = fmt.Sprintf("%s.%s.%s", name, tenant.Slug, s.cfg.BaseDomain)
			}
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       protocol.TunnelHTTP,
				Domain:     domain,
				PublicAddr: s.publicHTTPURL(tenant.Slug, name, domain),
			})
		case protocol.TunnelTCP:
			port, err := s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, t.RemotePort)
			if err != nil {
				return nil, nil, err
			}
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       protocol.TunnelTCP,
				RemotePort: port,
				PublicAddr: fmt.Sprintf("%s:%d", s.cfg.PublicHost, port),
			})
		default:
			return nil, nil, fmt.Errorf("unsupported tunnel type %q", t.Type)
		}
	}
	return ack, tenant, nil
}

func (s *Server) publicHTTPURL(slug, name, domain string) string {
	host := s.httpAdvertiseHost()
	pathURL := fmt.Sprintf("http://%s/%s/%s/", host, slug, name)
	if domain != "" {
		_, port, err := net.SplitHostPort(host)
		if err != nil {
			port = ""
		}
		if s.cfg.HTTPSGateway != "" {
			hp := domain
			if p := httpsPort(s.cfg.HTTPSGateway); p != "" && p != "443" {
				hp = net.JoinHostPort(domain, p)
			}
			return fmt.Sprintf("https://%s/ (also %s)", hp, pathURL)
		}
		if port != "" && port != "80" {
			return fmt.Sprintf("http://%s/ (also %s)", net.JoinHostPort(domain, port), pathURL)
		}
		return fmt.Sprintf("http://%s/ (also %s)", domain, pathURL)
	}
	return pathURL
}

func httpsPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.TrimPrefix(addr, ":")
	}
	return port
}

func (s *Server) httpAdvertiseHost() string {
	host := s.cfg.PublicHost
	_, port, err := net.SplitHostPort(s.cfg.HTTPGateway)
	if err != nil {
		port = strings.TrimPrefix(s.cfg.HTTPGateway, ":")
	}
	if port != "" && port != "80" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func (s *Server) stopTCPListenersForAgent(tenantID, agentID string, tunnels []protocol.AssignedTunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tunnels {
		if t.Type != protocol.TunnelTCP {
			continue
		}
		key := store.RouteKey(tenantID, t.Name)
		if stop, ok := s.tcpStops[key]; ok {
			stop()
			delete(s.tcpStops, key)
		}
		if t.RemotePort > 0 {
			s.registry.ReleasePort(t.RemotePort)
		}
	}
	_ = agentID
}
