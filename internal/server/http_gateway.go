package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

func (s *Server) serveHTTPGateway(ctx context.Context, ln net.Listener) {
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handleHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.log.Error("http gateway stopped", "err", err)
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	if r.URL.Path == "/api/tunnels" {
		s.handleListTunnels(w, r)
		return
	}

	name, rest, ok := splitTunnelPath(r.URL.Path)
	if !ok {
		// Host-based routing: demo.localhost / demo.tunnel.local
		if hostName := tunnelFromHost(r.Host); hostName != "" {
			name = hostName
			rest = r.URL.Path
			if rest == "" {
				rest = "/"
			}
			ok = true
		}
	}
	if !ok {
		http.Error(w, "usage: /{tunnel_name}/... or Host {name}.tunnel.local", http.StatusNotFound)
		return
	}

	route, exists := s.registry.Get(name)
	if !exists || route.Type != protocol.TunnelHTTP {
		http.Error(w, fmt.Sprintf("tunnel %q not found or not http", name), http.StatusNotFound)
		return
	}

	stream, err := s.registry.OpenToAgent(name, r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Rewrite path so upstream sees the residual path.
	outReq := r.Clone(r.Context())
	outReq.URL = &url.URL{
		Scheme:   "http",
		Host:     "tunnel",
		Path:     rest,
		RawQuery: r.URL.RawQuery,
	}
	outReq.RequestURI = ""

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {},
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
		ModifyResponse: func(resp *http.Response) error {
			return nil
		},
	}
	// Force director to use rewritten URL.
	proxy.Director = func(req *http.Request) {
		*req = *outReq
		req.Host = outReq.Host
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	routes := s.registry.List()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "[")
	for i, route := range routes {
		if i > 0 {
			_, _ = io.WriteString(w, ",")
		}
		_, _ = fmt.Fprintf(w,
			`{"name":%q,"type":%q,"agent_id":%q,"public_addr":%q,"local":%q}`,
			route.TunnelName, route.Type, route.AgentID, route.PublicAddr, route.LocalHint,
		)
	}
	_, _ = io.WriteString(w, "]")
}

func splitTunnelPath(path string) (name, rest string, ok bool) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", "", false
	}
	parts := strings.SplitN(path, "/", 2)
	name = parts[0]
	if name == "" || name == "healthz" || name == "api" {
		return "", "", false
	}
	rest = "/"
	if len(parts) == 2 {
		rest = "/" + parts[1]
	}
	return name, rest, true
}

func tunnelFromHost(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.ToLower(h)
	for _, suffix := range []string{".tunnel.local", ".localhost", ".tunnel"} {
		if strings.HasSuffix(h, suffix) {
			return strings.TrimSuffix(h, suffix)
		}
	}
	return ""
}
