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
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/authoidc"
	"github.com/kelvins-io/Intranet-penetration/internal/cluster"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/resume"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tlsutil"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
	"github.com/quic-go/quic-go"
)

type Server struct {
	cfg      *config.ServerConfig
	registry *Registry
	store    *store.Store
	cluster  cluster.Registry
	resume   *resume.Store
	oidc     *authoidc.Provider
	tlsConf  *tls.Config
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

	var clus cluster.Registry = cluster.NewMemory()
	if cfg.Cluster.RedisURL != "" {
		r, err := cluster.NewRedis(cfg.Cluster.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("cluster redis: %w", err)
		}
		clus = r
		log.Info("cluster registry", "backend", "redis")
	} else {
		log.Info("cluster registry", "backend", "memory")
	}

	oidcProv, err := authoidc.New(cfg.OIDC)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}

	needTLS := cfg.AutoTLS || cfg.QUICListen != "" || cfg.HTTPSGateway != ""
	var tlsConf *tls.Config
	if needTLS {
		tlsConf, err = tlsutil.LoadOrGenerate(
			absPath(cfg.DataDir, cfg.TLSCert),
			absPath(cfg.DataDir, cfg.TLSKey),
			cfg.AutoTLS || cfg.TLSCert == "",
			[]string{cfg.PublicHost, "localhost", cfg.BaseDomain, "*." + cfg.BaseDomain},
		)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
	}

	return &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		store:    st,
		cluster:  clus,
		resume:   resume.New(cfg.ResumeTTL),
		oidc:     oidcProv,
		tlsConf:  tlsConf,
		log:      log,
		tcpStops: make(map[string]context.CancelFunc),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	agentLn, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen agent tcp: %w", err)
	}
	s.trackListener(agentLn)
	s.log.Info("agent mux listening", "transport", "tcp", "addr", agentLn.Addr().String())

	if s.cfg.QUICListen != "" {
		if s.tlsConf == nil {
			return fmt.Errorf("quic requires tls config")
		}
		qln, err := tunnel.ListenQUIC(s.cfg.QUICListen, s.tlsConf)
		if err != nil {
			return fmt.Errorf("listen agent quic: %w", err)
		}
		go func() {
			<-ctx.Done()
			_ = qln.Close()
		}()
		s.log.Info("agent mux listening", "transport", "quic", "addr", s.cfg.QUICListen)
		go s.serveQUIC(ctx, qln)
	}

	httpLn, err := net.Listen("tcp", s.cfg.HTTPGateway)
	if err != nil {
		_ = agentLn.Close()
		return fmt.Errorf("listen http gateway: %w", err)
	}
	s.trackListener(httpLn)
	s.log.Info("http gateway listening", "addr", httpLn.Addr().String())
	go s.serveHTTPGateway(ctx, httpLn)

	if s.cfg.HTTPSGateway != "" {
		if s.tlsConf == nil {
			return fmt.Errorf("https requires tls config")
		}
		raw, err := net.Listen("tcp", s.cfg.HTTPSGateway)
		if err != nil {
			return fmt.Errorf("listen https gateway: %w", err)
		}
		ln := tls.NewListener(raw, s.tlsConf)
		s.trackListener(ln)
		s.log.Info("https gateway listening", "addr", ln.Addr().String())
		go s.serveHTTPGateway(ctx, ln)
	}

	_ = s.cluster.Heartbeat(s.cfg.EdgeID, s.cfg.Cluster.AdvertiseHTTP)
	go s.heartbeatLoop(ctx)

	s.log.Info("control plane ready",
		"edge_id", s.cfg.EdgeID,
		"dashboard", fmt.Sprintf("http://%s/dashboard/", s.httpAdvertiseHost()),
		"oidc", s.oidc != nil,
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
		go s.handleAgentTCP(ctx, conn)
	}
}

func (s *Server) serveQUIC(ctx context.Context, ln *quic.Listener) {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.log.Debug("quic accept", "err", err)
				return
			}
		}
		go s.handleAgentQUIC(ctx, conn)
	}
}

func (s *Server) handleAgentTCP(ctx context.Context, conn net.Conn) {
	remote := conn.RemoteAddr().String()
	s.log.Info("agent connected", "remote", remote, "transport", "tcp")
	defer conn.Close()
	sess, err := tunnel.ServerSession(conn)
	if err != nil {
		s.log.Debug("yamux server", "err", err, "remote", remote)
		return
	}
	s.serveAgentSession(ctx, sess, remote)
}

func (s *Server) handleAgentQUIC(ctx context.Context, conn *quic.Conn) {
	remote := conn.RemoteAddr().String()
	s.log.Info("agent connected", "remote", remote, "transport", "quic")
	defer conn.CloseWithError(0, "done")
	sess, err := tunnel.ServerQUICSession(conn)
	if err != nil {
		s.log.Debug("quic session", "err", err, "remote", remote)
		return
	}
	s.serveAgentSession(ctx, sess, remote)
}

func (s *Server) serveAgentSession(ctx context.Context, sess *tunnel.Session, remote string) {
	defer sess.Close()

	var tenant *store.Tenant
	hello, ack, err := sess.HandshakeAsServer(func(h protocol.Hello) (*protocol.HelloAck, error) {
		a, t, err := s.validateHello(h)
		if err != nil {
			return nil, err
		}
		tenant = t
		a.Transport = sess.Transport()
		a.EdgeID = s.cfg.EdgeID
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
		"resumed", ack.Resumed,
		"transport", ack.Transport,
	)
	s.store.Audit(tenant.ID, ack.AgentID, "agent.connect", ack.AgentID, remote+" "+ack.Transport)

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
		_ = s.cluster.Put(cluster.TunnelLocation{
			EdgeID:        s.cfg.EdgeID,
			AdvertiseHTTP: s.cfg.Cluster.AdvertiseHTTP,
			TenantID:      tenant.ID,
			TenantSlug:    tenant.Slug,
			TunnelName:    assigned.Name,
			AgentID:       ack.AgentID,
			Type:          string(assigned.Type),
			Domain:        assigned.Domain,
			PublicAddr:    assigned.PublicAddr,
			RemotePort:    assigned.RemotePort,
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

	// Soft-hold for session resume: keep TCP ports briefly via resume store.
	_ = s.resume.SoftHold(tenant.ID, ack.AgentID, ack.Tunnels)
	s.registry.UnregisterAgent(tenant.ID, ack.AgentID)
	_ = s.cluster.DeleteAgent(tenant.ID, ack.AgentID)
	s.stopTCPListenersForAgent(tenant.ID, ack.AgentID, ack.Tunnels)
	s.store.MarkAgentOffline(tenant.ID, ack.AgentID)
	s.store.Audit(tenant.ID, ack.AgentID, "agent.disconnect", ack.AgentID, "resume_held")
	s.log.Info("agent offline", "agent_id", ack.AgentID, "tenant", tenant.Slug)
}

func (s *Server) validateHello(hello protocol.Hello) (*protocol.HelloAck, *store.Tenant, error) {
	if hello.Version != 0 && hello.Version != protocol.Version && hello.Version != 1 {
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

	// Session resume: reuse prior domain/port assignments when possible.
	if hello.ResumeToken != "" {
		if st, ok := s.resume.Consume(hello.ResumeToken); ok &&
			st.TenantID == tenant.ID && st.AgentID == hello.AgentID {
			tunnels := make([]protocol.AssignedTunnel, 0, len(st.Tunnels))
			for _, t := range st.Tunnels {
				if t.Type == protocol.TunnelTCP {
					port, err := s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, t.RemotePort)
					if err != nil {
						port, err = s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, 0)
						if err != nil {
							return nil, nil, err
						}
					}
					t.RemotePort = port
					t.PublicAddr = fmt.Sprintf("%s:%d", s.cfg.PublicHost, port)
				}
				tunnels = append(tunnels, t)
			}
			ack := &protocol.HelloAck{
				Version:     protocol.Version,
				AgentID:     hello.AgentID,
				TenantID:    tenant.ID,
				Resumed:     true,
				Message:     "resumed",
				Tunnels:     tunnels,
				ResumeToken: s.resume.Issue(tenant.ID, hello.AgentID, tunnels),
			}
			return ack, tenant, nil
		}
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
	ack.ResumeToken = s.resume.Issue(tenant.ID, hello.AgentID, ack.Tunnels)
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
		// Keep port reserved in resume window — do not ReleasePort here.
		_ = t.RemotePort
	}
	_ = agentID
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
	_ = s.cluster.Close()
}

func (s *Server) Close() { s.shutdown() }

func (s *Server) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.cluster.Heartbeat(s.cfg.EdgeID, s.cfg.Cluster.AdvertiseHTTP)
			for _, route := range s.registry.List() {
				_ = s.cluster.Put(cluster.TunnelLocation{
					EdgeID:        s.cfg.EdgeID,
					AdvertiseHTTP: s.cfg.Cluster.AdvertiseHTTP,
					TenantID:      route.TenantID,
					TenantSlug:    route.TenantSlug,
					TunnelName:    route.TunnelName,
					AgentID:       route.AgentID,
					Type:          string(route.Type),
					Domain:        route.Domain,
					PublicAddr:    route.PublicAddr,
					RemotePort:    route.RemotePort,
				})
			}
		}
	}
}

func (s *Server) peerURLFor(edgeID string) string {
	if loc, ok := findPeer(s.cfg.Cluster.Peers, edgeID); ok {
		return loc
	}
	for _, e := range s.cluster.ListEdges() {
		if e.ID == edgeID {
			return e.AdvertiseHTTP
		}
	}
	return ""
}

func findPeer(peers []config.PeerConfig, id string) (string, bool) {
	for _, p := range peers {
		if p.ID == id {
			return p.HTTP, true
		}
	}
	return "", false
}
