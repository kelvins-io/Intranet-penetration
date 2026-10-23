package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/authoidc"
	"github.com/kelvins-io/Intranet-penetration/internal/cluster"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/controlclient"
	"github.com/kelvins-io/Intranet-penetration/internal/metrics"
	"github.com/kelvins-io/Intranet-penetration/internal/posture"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/resume"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tlsutil"
	"github.com/kelvins-io/Intranet-penetration/internal/traffic"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
	"github.com/quic-go/quic-go"
)

type policyCache struct {
	mu    sync.RWMutex
	byTen map[string][]store.AccessPolicy
	at    time.Time
}

type trafficCache struct {
	mu    sync.RWMutex
	byTen map[string][]store.TrafficPolicy
	at    time.Time
}

type Server struct {
	cfg      *config.ServerConfig
	registry *Registry
	store    *store.Store // nil for edge-only
	cluster  cluster.Registry
	resume   *resume.Store
	oidc     *authoidc.Provider
	tlsConf  *tls.Config
	agentTLS *tls.Config
	ca       *tlsutil.CA
	ctrl     *controlclient.Client // set for edge-only
	metrics  *metrics.Collector
	limiter  *traffic.Limiter
	log      *slog.Logger
	policies policyCache
	traffic  trafficCache
	revoked  struct {
		mu      sync.RWMutex
		serials map[string]struct{}
		at      time.Time
	}

	mu        sync.Mutex
	tcpStops  map[string]context.CancelFunc
	listeners []net.Listener
}

func New(cfg *config.ServerConfig, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	role := cfg.NormalizedRole()
	cfg.Role = role

	s := &Server{
		cfg:      cfg,
		registry: NewRegistry(),
		resume:   resume.New(cfg.ResumeTTL),
		metrics:  metrics.New(),
		limiter:  traffic.NewLimiter(),
		log:      log,
		tcpStops: make(map[string]context.CancelFunc),
	}
	s.policies.byTen = map[string][]store.AccessPolicy{}
	s.traffic.byTen = map[string][]store.TrafficPolicy{}
	s.revoked.serials = map[string]struct{}{}

	var err error
	if cfg.IsControl() {
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
		s.store = st

		oidcProv, err := authoidc.New(cfg.OIDC)
		if err != nil {
			return nil, fmt.Errorf("oidc: %w", err)
		}
		s.oidc = oidcProv
	}

	if cfg.IsEdgeOnly() {
		s.ctrl = controlclient.New(cfg.ControlURL, cfg.Cluster.Secret)
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
	s.cluster = clus

	mtlsMode := cfg.AgentMTLS
	if mtlsMode == "" {
		mtlsMode = "off"
	}
	cfg.AgentMTLS = mtlsMode

	needTLS := false
	if cfg.IsEdge() {
		needTLS = cfg.AutoTLS || cfg.QUICListen != "" || cfg.HTTPSGateway != "" || mtlsMode != "off"
	}
	if cfg.IsControlOnly() && (cfg.AutoTLS || strings.HasPrefix(cfg.APIListen, "https")) {
		needTLS = cfg.AutoTLS
	}
	if needTLS || (cfg.IsControl() && mtlsMode != "off" && !cfg.IsEdgeOnly()) {
		s.tlsConf, err = tlsutil.LoadOrGenerate(
			absPath(cfg.DataDir, cfg.TLSCert),
			absPath(cfg.DataDir, cfg.TLSKey),
			cfg.AutoTLS || cfg.TLSCert == "",
			[]string{cfg.PublicHost, "localhost", cfg.BaseDomain, "*." + cfg.BaseDomain},
		)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
	}

	if cfg.IsControl() {
		s.ca, err = tlsutil.LoadOrCreateCA(cfg.DataDir)
		if err != nil {
			return nil, fmt.Errorf("ca: %w", err)
		}
	}

	if mtlsMode != "off" && cfg.IsEdge() {
		if cfg.IsEdgeOnly() {
			if err := s.loadEdgeMTLSFromControl(); err != nil {
				return nil, fmt.Errorf("edge mtls: %w", err)
			}
		} else if s.ca != nil {
			s.agentTLS = tlsutil.ServerMTLSConfig(s.tlsConf, s.ca, mtlsMode)
		}
		log.Info("agent mTLS", "mode", mtlsMode, "role", role)
	}

	return s, nil
}

func (s *Server) loadEdgeMTLSFromControl() error {
	pemBytes, err := s.ctrl.CAPEM()
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("invalid ca from control")
	}
	base := s.tlsConf
	if base == nil {
		base, err = tlsutil.LoadOrGenerate(
			absPath(s.cfg.DataDir, s.cfg.TLSCert),
			absPath(s.cfg.DataDir, s.cfg.TLSKey),
			true,
			[]string{s.cfg.PublicHost, "localhost"},
		)
		if err != nil {
			return err
		}
		s.tlsConf = base
	}
	cfg := base.Clone()
	cfg.ClientCAs = pool
	switch s.cfg.AgentMTLS {
	case "require":
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"ip-tunnel"}
	}
	s.agentTLS = cfg
	_ = s.refreshRevoked(true)
	return nil
}

func (s *Server) Run(ctx context.Context) error {
	role := s.cfg.NormalizedRole()
	go func() {
		<-ctx.Done()
		s.shutdown()
	}()

	if s.cfg.IsControl() {
		if err := s.startControlHTTP(ctx); err != nil {
			return err
		}
	}

	if !s.cfg.IsEdge() {
		s.log.Info("control plane ready",
			"role", role,
			"api_listen", s.cfg.APIListen,
			"edge_id", s.cfg.EdgeID,
			"region", s.cfg.Region,
			"oidc", s.oidc != nil,
			"admin_api_key_hint", maskKey(s.store.AdminAPIKey()),
		)
		<-ctx.Done()
		return nil
	}

	return s.runEdge(ctx)
}

func (s *Server) startControlHTTP(ctx context.Context) error {
	apiAddr := s.cfg.APIListen
	mountOnGateway := apiAddr == "" && s.cfg.NormalizedRole() == config.RoleAll

	if mountOnGateway {
		// API will be mounted on gateway mux in serveHTTPGateway.
		return nil
	}
	if apiAddr == "" {
		apiAddr = ":8090"
	}
	ln, err := net.Listen("tcp", apiAddr)
	if err != nil {
		return fmt.Errorf("listen api: %w", err)
	}
	s.trackListener(ln)
	s.log.Info("control api listening", "addr", ln.Addr().String())
	go s.serveControlAPI(ctx, ln)
	return nil
}

func (s *Server) serveControlAPI(ctx context.Context, ln net.Listener) {
	mux := http.NewServeMux()
	s.mountAPI(mux)
	s.mountDashboard(mux)
	s.mountInternalAPI(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.log.Debug("control api stopped", "err", err)
	}
}

func (s *Server) runEdge(ctx context.Context) error {
	rawAgentLn, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen agent tcp: %w", err)
	}
	var agentLn net.Listener = rawAgentLn
	if s.agentTLS != nil {
		agentLn = tls.NewListener(rawAgentLn, s.agentTLS)
		s.log.Info("agent mux listening", "transport", "tcp+tls", "mtls", s.cfg.AgentMTLS, "addr", agentLn.Addr().String())
	} else {
		s.log.Info("agent mux listening", "transport", "tcp", "addr", agentLn.Addr().String())
	}
	s.trackListener(agentLn)

	if s.cfg.QUICListen != "" {
		qTLS := s.tlsConf
		if s.agentTLS != nil {
			qTLS = s.agentTLS
		}
		if qTLS == nil {
			return fmt.Errorf("quic requires tls config")
		}
		qln, err := tunnel.ListenQUIC(s.cfg.QUICListen, qTLS)
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

	_ = s.cluster.Heartbeat(s.cfg.EdgeID, s.cfg.Cluster.AdvertiseHTTP, s.cfg.Region)
	go s.heartbeatLoop(ctx)
	if s.cfg.IsEdgeOnly() {
		go s.edgeSyncLoop(ctx)
	}

	s.log.Info("edge plane ready",
		"role", s.cfg.Role,
		"edge_id", s.cfg.EdgeID,
		"region", s.cfg.Region,
		"e2e", s.cfg.EnableE2E,
		"agent_mtls", s.cfg.AgentMTLS,
		"access_default_deny", s.cfg.AccessDefaultDeny,
		"control_url", s.cfg.ControlURL,
	)

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

func (s *Server) edgeSyncLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.refreshRevoked(false)
			s.invalidatePolicyCache()
		}
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
	peerCN := ""
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			s.log.Warn("agent tls handshake", "err", err, "remote", remote)
			_ = conn.Close()
			return
		}
		peerCN = tlsutil.PeerAgentID(tc.ConnectionState())
		if s.cfg.AgentMTLS == "require" && peerCN == "" {
			s.log.Warn("agent mTLS required but no client cert", "remote", remote)
			_ = conn.Close()
			return
		}
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
			serial := st.PeerCertificates[0].SerialNumber.Text(16)
			if s.isCertRevoked(serial) {
				s.log.Warn("agent cert revoked", "serial", serial, "remote", remote)
				_ = conn.Close()
				return
			}
		}
	} else if s.cfg.AgentMTLS == "require" {
		s.log.Warn("agent mTLS required but connection is plaintext", "remote", remote)
		_ = conn.Close()
		return
	}
	s.log.Info("agent connected", "remote", remote, "transport", "tcp", "peer_cn", peerCN)
	defer conn.Close()
	sess, err := tunnel.ServerSession(conn)
	if err != nil {
		s.log.Debug("yamux server", "err", err, "remote", remote)
		return
	}
	s.serveAgentSession(ctx, sess, remote, peerCN)
}

func (s *Server) handleAgentQUIC(ctx context.Context, conn *quic.Conn) {
	remote := conn.RemoteAddr().String()
	peerCN := ""
	if st := conn.ConnectionState().TLS; len(st.PeerCertificates) > 0 {
		peerCN = st.PeerCertificates[0].Subject.CommonName
		serial := st.PeerCertificates[0].SerialNumber.Text(16)
		if s.isCertRevoked(serial) {
			s.log.Warn("agent cert revoked", "serial", serial, "remote", remote)
			_ = conn.CloseWithError(1, "revoked")
			return
		}
	} else if s.cfg.AgentMTLS == "require" {
		s.log.Warn("agent mTLS required but no client cert on quic", "remote", remote)
		_ = conn.CloseWithError(1, "mtls required")
		return
	}
	s.log.Info("agent connected", "remote", remote, "transport", "quic", "peer_cn", peerCN)
	defer conn.CloseWithError(0, "done")
	sess, err := tunnel.ServerQUICSession(conn)
	if err != nil {
		s.log.Debug("quic session", "err", err, "remote", remote)
		return
	}
	s.serveAgentSession(ctx, sess, remote, peerCN)
}

func (s *Server) serveAgentSession(ctx context.Context, sess *tunnel.Session, remote, peerCN string) {
	defer sess.Close()

	var tenant *store.Tenant
	hello, ack, err := sess.HandshakeAsServer(func(h protocol.Hello) (*protocol.HelloAck, error) {
		if s.cfg.AgentMTLS == "require" {
			if peerCN == "" {
				return nil, fmt.Errorf("client certificate required")
			}
			if peerCN != h.AgentID {
				return nil, fmt.Errorf("certificate CN %q does not match agent_id %q", peerCN, h.AgentID)
			}
		} else if peerCN != "" && peerCN != h.AgentID {
			return nil, fmt.Errorf("certificate CN %q does not match agent_id %q", peerCN, h.AgentID)
		}
		a, t, err := s.validateHello(h)
		if err != nil {
			return nil, err
		}
		tenant = t
		a.Transport = sess.Transport()
		a.EdgeID = s.cfg.EdgeID
		a.Region = s.cfg.Region
		a.E2E = s.cfg.EnableE2E && h.PreferE2E
		return a, nil
	})
	if err != nil {
		s.log.Warn("handshake failed", "remote", remote, "err", err)
		return
	}
	sess.SetE2E(ack.E2E)
	s.metrics.IncAgent()
	s.log.Info("agent registered",
		"agent_id", ack.AgentID,
		"tenant", tenant.Slug,
		"tunnels", len(ack.Tunnels),
		"resumed", ack.Resumed,
		"transport", ack.Transport,
		"e2e", ack.E2E,
		"region", ack.Region,
	)
	s.reportAgentOnline(tenant, ack, *hello, remote)

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
		_ = s.cluster.Put(cluster.TunnelLocation{
			EdgeID:        s.cfg.EdgeID,
			AdvertiseHTTP: s.cfg.Cluster.AdvertiseHTTP,
			Region:        s.cfg.Region,
			TenantID:      tenant.ID,
			TenantSlug:    tenant.Slug,
			TunnelName:    assigned.Name,
			AgentID:       ack.AgentID,
			Type:          string(assigned.Type),
			Domain:        assigned.Domain,
			PublicAddr:    assigned.PublicAddr,
			RemotePort:    assigned.RemotePort,
		})
		switch assigned.Type {
		case protocol.TunnelTCP:
			s.startTCPListener(ctx, route.Key(), assigned.RemotePort, tenant.ID, assigned.Name)
		case protocol.TunnelUDP:
			s.startUDPListener(ctx, route.Key(), assigned.RemotePort, tenant.ID, assigned.Name)
		}
		s.log.Info("tunnel online",
			"tenant", tenant.Slug,
			"name", assigned.Name,
			"type", assigned.Type,
			"public", assigned.PublicAddr,
			"domain", assigned.Domain,
		)
	}

	select {
	case <-ctx.Done():
	case <-sess.CloseChan():
	}

	_ = s.resume.SoftHold(tenant.ID, ack.AgentID, ack.Tunnels)
	s.registry.UnregisterAgent(tenant.ID, ack.AgentID)
	_ = s.cluster.DeleteAgent(tenant.ID, ack.AgentID)
	s.stopTCPListenersForAgent(tenant.ID, ack.AgentID, ack.Tunnels)
	s.reportAgentOffline(tenant.ID, ack.AgentID)
	s.log.Info("agent offline", "agent_id", ack.AgentID, "tenant", tenant.Slug)
}

func (s *Server) reportAgentOnline(tenant *store.Tenant, ack *protocol.HelloAck, hello protocol.Hello, remote string) {
	hints := map[string]string{}
	for _, t := range hello.Tunnels {
		hints[t.Name] = t.LocalAddr
	}
	if s.cfg.IsEdgeOnly() && s.ctrl != nil {
		_ = s.ctrl.AgentOnline(controlclient.OnlineRequest{
			TenantID: tenant.ID,
			AgentID:  ack.AgentID,
			Remote:   remote + " " + ack.Transport + " e2e=" + fmt.Sprint(ack.E2E),
			Tunnels:  ack.Tunnels,
			Hints:    hints,
		})
		return
	}
	if s.store == nil {
		return
	}
	s.store.Audit(tenant.ID, ack.AgentID, "agent.connect", ack.AgentID, remote+" "+ack.Transport+" e2e="+fmt.Sprint(ack.E2E))
	for _, assigned := range ack.Tunnels {
		_, _ = s.store.UpsertTunnel(store.TunnelRecord{
			TenantID:   tenant.ID,
			Name:       assigned.Name,
			Type:       string(assigned.Type),
			LocalHint:  hints[assigned.Name],
			Domain:     assigned.Domain,
			PublicAddr: assigned.PublicAddr,
			RemotePort: assigned.RemotePort,
			AgentID:    ack.AgentID,
			Online:     true,
		})
		s.store.Audit(tenant.ID, ack.AgentID, "tunnel.online", assigned.Name, assigned.PublicAddr)
	}
}

func (s *Server) reportAgentOffline(tenantID, agentID string) {
	if s.cfg.IsEdgeOnly() && s.ctrl != nil {
		_ = s.ctrl.AgentOffline(controlclient.OfflineRequest{TenantID: tenantID, AgentID: agentID})
		return
	}
	if s.store == nil {
		return
	}
	s.store.MarkAgentOffline(tenantID, agentID)
	s.store.Audit(tenantID, agentID, "agent.disconnect", agentID, "resume_held")
}

func (s *Server) validateHello(hello protocol.Hello) (*protocol.HelloAck, *store.Tenant, error) {
	// Local resume always handled on Edge.
	if hello.ResumeToken != "" {
		if tenant, ack, ok := s.tryResume(hello); ok {
			return ack, tenant, nil
		}
	}

	if s.cfg.IsEdgeOnly() {
		return s.validateHelloRemote(hello)
	}
	return s.validateHelloLocal(hello)
}

func (s *Server) tryResume(hello protocol.Hello) (*store.Tenant, *protocol.HelloAck, bool) {
	st, ok := s.resume.Consume(hello.ResumeToken)
	if !ok || st.AgentID != hello.AgentID {
		return nil, nil, false
	}
	var tenant *store.Tenant
	if s.store != nil {
		t, err := s.store.GetTenant(st.TenantID)
		if err != nil {
			return nil, nil, false
		}
		tenant = t
	} else {
		tenant = &store.Tenant{ID: st.TenantID, Slug: "remote"}
	}
	tunnels := make([]protocol.AssignedTunnel, 0, len(st.Tunnels))
	for _, t := range st.Tunnels {
		if t.Type == protocol.TunnelTCP || t.Type == protocol.TunnelUDP {
			port, err := s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, t.RemotePort)
			if err != nil {
				port, err = s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, 0)
				if err != nil {
					return nil, nil, false
				}
			}
			t.RemotePort = port
			t.PublicAddr = fmt.Sprintf("%s:%d/%s", s.cfg.PublicHost, port, t.Type)
		}
		tunnels = append(tunnels, t)
	}
	ack := &protocol.HelloAck{
		Version:     protocol.Version,
		AgentID:     hello.AgentID,
		TenantID:    st.TenantID,
		Resumed:     true,
		Message:     "resumed",
		Tunnels:     tunnels,
		ResumeToken: s.resume.Issue(st.TenantID, hello.AgentID, tunnels),
	}
	return tenant, ack, true
}

func (s *Server) validateHelloRemote(hello protocol.Hello) (*protocol.HelloAck, *store.Tenant, error) {
	resp, err := s.ctrl.AgentHello(controlclient.HelloRequest{
		Hello:      hello,
		PublicHost: s.cfg.PublicHost,
		BaseDomain: s.cfg.BaseDomain,
		EdgeID:     s.cfg.EdgeID,
	})
	if err != nil {
		return nil, nil, err
	}
	ack := resp.Ack
	tenant := resp.Tenant
	// Allocate TCP ports locally.
	for i := range ack.Tunnels {
		t := &ack.Tunnels[i]
		if t.Type != protocol.TunnelTCP && t.Type != protocol.TunnelUDP {
			continue
		}
		port, err := s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, t.RemotePort)
		if err != nil {
			return nil, nil, err
		}
		t.RemotePort = port
		t.PublicAddr = fmt.Sprintf("%s:%d/%s", s.cfg.PublicHost, port, t.Type)
	}
	ack.ResumeToken = s.resume.Issue(tenant.ID, hello.AgentID, ack.Tunnels)
	return &ack, &tenant, nil
}

func (s *Server) validateHelloLocal(hello protocol.Hello) (*protocol.HelloAck, *store.Tenant, error) {
	if hello.Version != 0 && hello.Version != protocol.Version && hello.Version != 1 && hello.Version != 3 {
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
	if err := s.enforcePosture(tenant.ID, hello.AgentID, hello.Posture); err != nil {
		return nil, nil, err
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
		case protocol.TunnelTCP, protocol.TunnelUDP:
			port, err := s.registry.AllocatePort(s.cfg.TCPPortMin, s.cfg.TCPPortMax, t.RemotePort)
			if err != nil {
				return nil, nil, err
			}
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       t.Type,
				RemotePort: port,
				PublicAddr: fmt.Sprintf("%s:%d/%s", s.cfg.PublicHost, port, t.Type),
			})
		default:
			return nil, nil, fmt.Errorf("unsupported tunnel type %q", t.Type)
		}
	}
	ack.ResumeToken = s.resume.Issue(tenant.ID, hello.AgentID, ack.Tunnels)
	return ack, tenant, nil
}

func (s *Server) enforcePosture(tenantID, agentID string, p protocol.DevicePosture) error {
	if s.store == nil {
		return nil // edge remote hello already enforced on control
	}
	d := posture.Evaluate(s.store.ListPosturePolicies(tenantID), tenantID, p)
	_ = s.store.UpsertAgentPosture(posture.ToRecord(tenantID, agentID, p))
	if !d.Allowed {
		s.store.Audit(tenantID, agentID, "posture.deny", agentID, d.Reason+" policy="+d.Policy)
		return fmt.Errorf("device posture denied: %s", d.Reason)
	}
	if d.Policy != "" && d.Policy != "no posture policy" {
		s.store.Audit(tenantID, agentID, "posture.ok", agentID, d.Policy)
	}
	return nil
}

func (s *Server) publicHTTPURL(slug, name, domain string) string {
	return s.publicHTTPURLWith(s.cfg.PublicHost, slug, name, domain)
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
		if t.Type != protocol.TunnelTCP && t.Type != protocol.TunnelUDP {
			continue
		}
		key := store.RouteKey(tenantID, t.Name)
		if stop, ok := s.tcpStops[key]; ok {
			stop()
			delete(s.tcpStops, key)
		}
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
			_ = s.cluster.Heartbeat(s.cfg.EdgeID, s.cfg.Cluster.AdvertiseHTTP, s.cfg.Region)
			for _, route := range s.registry.List() {
				_ = s.cluster.Put(cluster.TunnelLocation{
					EdgeID:        s.cfg.EdgeID,
					AdvertiseHTTP: s.cfg.Cluster.AdvertiseHTTP,
					Region:        s.cfg.Region,
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

func (s *Server) isCertRevoked(serial string) bool {
	if s.store != nil {
		return s.store.IsAgentCertRevoked(serial)
	}
	_ = s.refreshRevoked(false)
	s.revoked.mu.RLock()
	defer s.revoked.mu.RUnlock()
	_, ok := s.revoked.serials[serial]
	return ok
}

func (s *Server) refreshRevoked(force bool) error {
	if s.ctrl == nil {
		return nil
	}
	s.revoked.mu.RLock()
	fresh := time.Since(s.revoked.at) < 30*time.Second
	s.revoked.mu.RUnlock()
	if fresh && !force {
		return nil
	}
	serials, err := s.ctrl.RevokedSerials()
	if err != nil {
		return err
	}
	m := make(map[string]struct{}, len(serials))
	for _, ser := range serials {
		m[ser] = struct{}{}
	}
	s.revoked.mu.Lock()
	s.revoked.serials = m
	s.revoked.at = time.Now()
	s.revoked.mu.Unlock()
	return nil
}

func (s *Server) listPolicies(tenantID string) []store.AccessPolicy {
	if s.store != nil {
		return s.store.ListPolicies(tenantID)
	}
	s.policies.mu.RLock()
	if time.Since(s.policies.at) < 15*time.Second {
		if p, ok := s.policies.byTen[tenantID]; ok {
			s.policies.mu.RUnlock()
			return p
		}
	}
	s.policies.mu.RUnlock()
	if s.ctrl == nil {
		return nil
	}
	p, err := s.ctrl.ListPolicies(tenantID)
	if err != nil {
		s.log.Debug("policy fetch", "err", err)
		s.policies.mu.RLock()
		defer s.policies.mu.RUnlock()
		return s.policies.byTen[tenantID]
	}
	s.policies.mu.Lock()
	s.policies.byTen[tenantID] = p
	s.policies.at = time.Now()
	s.policies.mu.Unlock()
	return p
}

func (s *Server) listTrafficPolicies(tenantID string) []store.TrafficPolicy {
	if s.store != nil {
		return s.store.ListTrafficPolicies(tenantID)
	}
	s.traffic.mu.RLock()
	if time.Since(s.traffic.at) < 15*time.Second {
		if p, ok := s.traffic.byTen[tenantID]; ok {
			s.traffic.mu.RUnlock()
			return p
		}
	}
	s.traffic.mu.RUnlock()
	if s.ctrl == nil {
		return nil
	}
	p, err := s.ctrl.ListTrafficPolicies(tenantID)
	if err != nil {
		s.log.Debug("traffic policy fetch", "err", err)
		s.traffic.mu.RLock()
		defer s.traffic.mu.RUnlock()
		return s.traffic.byTen[tenantID]
	}
	s.traffic.mu.Lock()
	s.traffic.byTen[tenantID] = p
	s.traffic.at = time.Now()
	s.traffic.mu.Unlock()
	return p
}

func (s *Server) invalidatePolicyCache() {
	s.policies.mu.Lock()
	s.policies.byTen = map[string][]store.AccessPolicy{}
	s.policies.at = time.Time{}
	s.policies.mu.Unlock()
	s.traffic.mu.Lock()
	s.traffic.byTen = map[string][]store.TrafficPolicy{}
	s.traffic.at = time.Time{}
	s.traffic.mu.Unlock()
}

func (s *Server) auditEvent(tenantID, actor, action, target, detail string) {
	if s.store != nil {
		s.store.Audit(tenantID, actor, action, target, detail)
		return
	}
	if s.ctrl != nil {
		_ = s.ctrl.Audit(controlclient.AuditRequest{
			TenantID: tenantID, Actor: actor, Action: action, Target: target, Detail: detail,
		})
	}
}
