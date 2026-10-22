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

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

func (s *Server) serveHTTPGateway(ctx context.Context, ln net.Listener) {
	mux := http.NewServeMux()
	s.mountAPI(mux)
	s.mountDashboard(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
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

	route, exists := s.registry.Get(tenantID, name)
	if !exists || route.Type != protocol.TunnelHTTP {
		http.Error(w, fmt.Sprintf("tunnel %q offline or not http", name), http.StatusBadGateway)
		return
	}

	stream, err := s.registry.OpenToAgent(tenantID, name, r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	s.store.Audit(tenantID, "public", "http.access", name, r.Method+" "+r.URL.Path+" from "+r.RemoteAddr)

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

func (s *Server) resolveHTTPTarget(r *http.Request) (tenantID, name, rest string, ok bool) {
	host := stripHostPort(r.Host)

	// 1) Custom / assigned domain exact match
	if route, found := s.registry.GetByHost(host); found {
		return route.TenantID, route.TunnelName, ensurePath(r.URL.Path), true
	}
	if rec, err := s.store.FindTunnelByDomain(host); err == nil {
		return rec.TenantID, rec.Name, ensurePath(r.URL.Path), true
	}

	// 2) Subdomain: {tunnel}.{tenant}.{base}
	base := strings.ToLower(s.cfg.BaseDomain)
	if base != "" && strings.HasSuffix(host, "."+base) {
		prefix := strings.TrimSuffix(host, "."+base)
		parts := strings.Split(prefix, ".")
		if len(parts) == 2 {
			tunName, slug := parts[0], parts[1]
			if ten, err := s.store.GetTenantBySlug(slug); err == nil {
				return ten.ID, tunName, ensurePath(r.URL.Path), true
			}
		}
	}

	// 3) Path: /{tenant_slug}/{tunnel}/...
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || strings.HasPrefix(path, "api/") || strings.HasPrefix(path, "dashboard") {
		return "", "", "", false
	}
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	slug, tunName := parts[0], parts[1]
	if slug == "healthz" || slug == "api" || slug == "dashboard" {
		return "", "", "", false
	}
	ten, err := s.store.GetTenantBySlug(slug)
	if err != nil {
		return "", "", "", false
	}
	rest = "/"
	if len(parts) == 3 {
		rest = "/" + parts[2]
	}
	return ten.ID, tunName, rest, true
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
