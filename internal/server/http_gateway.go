package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/traffic"
)

func (s *Server) serveHTTPGateway(ctx context.Context, ln net.Listener) {
	mux := http.NewServeMux()
	// role=all with empty api_listen: keep API on gateway for local demo compat.
	if s.cfg.NormalizedRole() == config.RoleAll && s.cfg.APIListen == "" {
		s.mountAPI(mux)
		s.mountDashboard(mux)
		s.mountAccessClient(mux)
		s.mountInternalAPI(mux)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.metrics.WritePrometheus(w)
	})
	mux.HandleFunc("/agent/ws", s.handleAgentWS)
	mux.HandleFunc("/api/v1/regions/discover", s.handleRegionDiscover)
	mux.HandleFunc("/internal/forward/", s.handleInternalForward)
	mux.HandleFunc("/", s.handlePublicHTTP)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.log.Debug("http gateway stopped", "err", err)
	}
}

func (s *Server) handlePublicHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID, name, rest, ok := s.resolveHTTPTarget(r)
	if !ok {
		http.Error(w, "tunnel not found; use /{tenant}/{tunnel}/... or Host {tunnel}.{tenant}."+s.cfg.BaseDomain, http.StatusNotFound)
		return
	}
	if !s.enforceAccess(w, r, tenantID, name, "http.access") {
		return
	}
	release, bw, ok := s.enforceTraffic(w, tenantID, name, r.RemoteAddr)
	if !ok {
		return
	}
	defer release()

	if route, exists := s.registry.Get(tenantID, name); exists && route.Type == protocol.TunnelHTTP {
		s.proxyLocalHTTP(w, r, tenantID, name, rest, bw)
		return
	}

	if loc, found := s.cluster.Get(tenantID, name); found && loc.EdgeID != s.cfg.EdgeID {
		peer := loc.AdvertiseHTTP
		if peer == "" {
			peer = s.peerURLFor(loc.EdgeID)
		}
		if err := s.forwardToPeerLoc(w, r, peer, tenantID, name, rest); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
		return
	}

	http.Error(w, fmt.Sprintf("tunnel %q offline", name), http.StatusBadGateway)
}

func (s *Server) proxyLocalHTTP(w http.ResponseWriter, r *http.Request, tenantID, name, rest string, bandwidthBPS int64) {
	stream, err := s.registry.OpenToAgent(tenantID, name, r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	stream = traffic.WrapConn(stream, bandwidthBPS)
	s.metrics.IncHTTP()
	if route, ok := s.registry.Get(tenantID, name); ok && route.Session != nil && route.Session.E2E() {
		s.metrics.IncE2E()
	}

	s.auditEvent(tenantID, "public", "http.access", name, r.Method+" "+r.URL.Path+" from "+r.RemoteAddr)

	outReq := r.Clone(r.Context())
	outReq.URL = &url.URL{
		Scheme:   "http",
		Host:     "tunnel",
		Path:     rest,
		RawQuery: r.URL.RawQuery,
	}
	outReq.RequestURI = ""

	proxy := &httputil.ReverseProxy{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return stream, nil
			},
			DisableKeepAlives: true,
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, e error) {
			s.log.Warn("http proxy error", "tunnel", name, "err", e)
			http.Error(rw, "bad gateway", http.StatusBadGateway)
			_ = stream.Close()
		},
	}
	proxy.Director = func(req *http.Request) {
		*req = *outReq
		req.Host = outReq.Host
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) forwardToPeerLoc(w http.ResponseWriter, r *http.Request, advertiseHTTP, tenantID, name, rest string) error {
	base := strings.TrimRight(advertiseHTTP, "/")
	if base == "" {
		return fmt.Errorf("peer advertise url empty")
	}
	target, err := url.Parse(fmt.Sprintf("%s/internal/forward/%s/%s%s", base, tenantID, name, rest))
	if err != nil {
		return err
	}
	if r.URL.RawQuery != "" {
		target.RawQuery = r.URL.RawQuery
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	secret := s.cfg.Cluster.Secret
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.Host = target.Host
		if secret != "" {
			req.Header.Set("X-Cluster-Secret", secret)
		}
		req.Header.Set("X-Forwarded-For", r.RemoteAddr)
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, e error) {
		s.log.Warn("peer forward error", "peer", base, "err", e)
		http.Error(rw, "peer bad gateway", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
	return nil
}

func (s *Server) handleInternalForward(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Cluster.Secret != "" && r.Header.Get("X-Cluster-Secret") != s.cfg.Cluster.Secret {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/internal/forward/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	tenantID, name := parts[0], parts[1]
	rest := "/"
	if len(parts) == 3 {
		rest = "/" + parts[2]
	}
	if _, exists := s.registry.Get(tenantID, name); !exists {
		http.Error(w, "tunnel not on this edge", http.StatusBadGateway)
		return
	}
	s.proxyLocalHTTP(w, r, tenantID, name, rest, 0)
}

func (s *Server) resolveHTTPTarget(r *http.Request) (tenantID, name, rest string, ok bool) {
	host := stripHostPort(r.Host)

	if route, found := s.registry.GetByHost(host); found {
		return route.TenantID, route.TunnelName, ensurePath(r.URL.Path), true
	}
	if loc, found := s.cluster.GetByDomain(host); found {
		return loc.TenantID, loc.TunnelName, ensurePath(r.URL.Path), true
	}
	if s.store != nil {
		if rec, err := s.store.FindTunnelByDomain(host); err == nil {
			return rec.TenantID, rec.Name, ensurePath(r.URL.Path), true
		}
	} else if s.ctrl != nil {
		if res, err := s.ctrl.ResolveDomain(host); err == nil {
			return res.TenantID, res.TunnelName, ensurePath(r.URL.Path), true
		}
	}

	base := strings.ToLower(s.cfg.BaseDomain)
	if base != "" && strings.HasSuffix(host, "."+base) {
		prefix := strings.TrimSuffix(host, "."+base)
		parts := strings.Split(prefix, ".")
		if len(parts) == 2 {
			tunName, slug := parts[0], parts[1]
			if tid, ok := s.resolveTenantSlug(slug); ok {
				return tid, tunName, ensurePath(r.URL.Path), true
			}
		}
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || strings.HasPrefix(path, "api/") || strings.HasPrefix(path, "dashboard") ||
		strings.HasPrefix(path, "internal/") || strings.HasPrefix(path, "access") ||
		strings.HasPrefix(path, "metrics") || strings.HasPrefix(path, "agent/") {
		return "", "", "", false
	}
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	slug, tunName := parts[0], parts[1]
	if pathReserved(slug) {
		return "", "", "", false
	}
	tid, ok := s.resolveTenantSlug(slug)
	if !ok {
		return "", "", "", false
	}
	rest = "/"
	if len(parts) == 3 {
		rest = "/" + parts[2]
	}
	return tid, tunName, rest, true
}

func (s *Server) resolveTenantSlug(slug string) (string, bool) {
	if s.store != nil {
		ten, err := s.store.GetTenantBySlug(slug)
		if err != nil {
			return "", false
		}
		return ten.ID, true
	}
	if s.ctrl != nil {
		res, err := s.ctrl.ResolveSlug(slug, "_")
		if err != nil {
			return "", false
		}
		return res.TenantID, true
	}
	return "", false
}

func stripHostPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

func ensurePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}
