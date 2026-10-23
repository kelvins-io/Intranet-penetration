package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/kelvins-io/Intranet-penetration/internal/controlclient"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func (s *Server) mountInternalAPI(mux *http.ServeMux) {
	mux.HandleFunc("/internal/v1/agent/hello", s.withClusterSecret(s.handleInternalHello))
	mux.HandleFunc("/internal/v1/agent/online", s.withClusterSecret(s.handleInternalOnline))
	mux.HandleFunc("/internal/v1/agent/offline", s.withClusterSecret(s.handleInternalOffline))
	mux.HandleFunc("/internal/v1/policies", s.withClusterSecret(s.handleInternalPolicies))
	mux.HandleFunc("/internal/v1/ca", s.withClusterSecret(s.handleInternalCA))
	mux.HandleFunc("/internal/v1/certs/revoked", s.withClusterSecret(s.handleInternalRevoked))
	mux.HandleFunc("/internal/v1/resolve", s.withClusterSecret(s.handleInternalResolve))
	mux.HandleFunc("/internal/v1/identity", s.withClusterSecret(s.handleInternalIdentity))
	mux.HandleFunc("/internal/v1/audit", s.withClusterSecret(s.handleInternalAudit))
}

func (s *Server) withClusterSecret(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Cluster.Secret != "" && r.Header.Get("X-Cluster-Secret") != s.cfg.Cluster.Secret {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleInternalHello(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req controlclient.HelloRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	publicHost := req.PublicHost
	if publicHost == "" {
		publicHost = s.cfg.PublicHost
	}
	baseDomain := req.BaseDomain
	if baseDomain == "" {
		baseDomain = s.cfg.BaseDomain
	}
	ack, tenant, err := s.validateHelloForControl(req.Hello, publicHost, baseDomain)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, controlclient.HelloResponse{Ack: *ack, Tenant: *tenant})
}

// validateHelloForControl assigns domains/quota without allocating TCP ports (Edge does that).
func (s *Server) validateHelloForControl(hello protocol.Hello, publicHost, baseDomain string) (*protocol.HelloAck, *store.Tenant, error) {
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
				domain = fmt.Sprintf("%s.%s.%s", name, tenant.Slug, baseDomain)
			}
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       protocol.TunnelHTTP,
				Domain:     domain,
				PublicAddr: s.publicHTTPURLWith(publicHost, tenant.Slug, name, domain),
			})
		case protocol.TunnelTCP:
			// Edge allocates the real port; pass through preferred port as hint.
			ack.Tunnels = append(ack.Tunnels, protocol.AssignedTunnel{
				Name:       name,
				Type:       protocol.TunnelTCP,
				RemotePort: t.RemotePort,
				PublicAddr: fmt.Sprintf("%s:%d", publicHost, t.RemotePort),
			})
		default:
			return nil, nil, fmt.Errorf("unsupported tunnel type %q", t.Type)
		}
	}
	return ack, tenant, nil
}

func (s *Server) publicHTTPURLWith(publicHost, slug, name, domain string) string {
	host := publicHost
	_, port, err := net.SplitHostPort(s.cfg.HTTPGateway)
	if err != nil {
		port = strings.TrimPrefix(s.cfg.HTTPGateway, ":")
	}
	if port != "" && port != "80" {
		host = net.JoinHostPort(publicHost, port)
	}
	pathURL := fmt.Sprintf("http://%s/%s/%s/", host, slug, name)
	if domain == "" {
		return pathURL
	}
	if s.cfg.HTTPSGateway != "" {
		hp := domain
		if p := httpsPort(s.cfg.HTTPSGateway); p != "" && p != "443" {
			hp = net.JoinHostPort(domain, p)
		}
		return fmt.Sprintf("https://%s/ (also %s)", hp, pathURL)
	}
	return fmt.Sprintf("http://%s/ (also %s)", domain, pathURL)
}

func (s *Server) handleInternalOnline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req controlclient.OnlineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	for _, t := range req.Tunnels {
		hint := ""
		if req.Hints != nil {
			hint = req.Hints[t.Name]
		}
		_, _ = s.store.UpsertTunnel(store.TunnelRecord{
			TenantID:   req.TenantID,
			Name:       t.Name,
			Type:       string(t.Type),
			LocalHint:  hint,
			Domain:     t.Domain,
			PublicAddr: t.PublicAddr,
			RemotePort: t.RemotePort,
			AgentID:    req.AgentID,
			Online:     true,
		})
		s.store.Audit(req.TenantID, req.AgentID, "tunnel.online", t.Name, t.PublicAddr)
	}
	s.store.Audit(req.TenantID, req.AgentID, "agent.connect", req.AgentID, req.Remote)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleInternalOffline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req controlclient.OfflineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	s.store.MarkAgentOffline(req.TenantID, req.AgentID)
	s.store.Audit(req.TenantID, req.AgentID, "agent.disconnect", req.AgentID, "edge_report")
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleInternalPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant")
	writeJSON(w, http.StatusOK, s.store.ListPolicies(tenantID))
}

func (s *Server) handleInternalCA(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeErr(w, http.StatusServiceUnavailable, "ca not available")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.ca.CertPEM)
}

func (s *Server) handleInternalRevoked(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"serials": s.store.ListRevokedSerials()})
}

func (s *Server) handleInternalResolve(w http.ResponseWriter, r *http.Request) {
	if domain := r.URL.Query().Get("domain"); domain != "" {
		if rec, err := s.store.FindTunnelByDomain(strings.ToLower(domain)); err == nil {
			ten, _ := s.store.GetTenant(rec.TenantID)
			slug := ""
			if ten != nil {
				slug = ten.Slug
			}
			writeJSON(w, http.StatusOK, controlclient.ResolveResponse{
				TenantID: rec.TenantID, TenantSlug: slug, TunnelName: rec.Name, Domain: rec.Domain,
			})
			return
		}
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	slug := r.URL.Query().Get("tenant_slug")
	tunnel := r.URL.Query().Get("tunnel")
	if slug == "" || tunnel == "" {
		writeErr(w, http.StatusBadRequest, "domain or tenant_slug+tunnel required")
		return
	}
	ten, err := s.store.GetTenantBySlug(slug)
	if err != nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, controlclient.ResolveResponse{
		TenantID: ten.ID, TenantSlug: ten.Slug, TunnelName: tunnel,
	})
}

func (s *Server) handleInternalIdentity(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("api_key")
	if key == "" {
		writeErr(w, http.StatusBadRequest, "api_key required")
		return
	}
	u, _, err := s.store.ResolveUserAPIKey(key)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, controlclient.IdentityResponse{
		Email: u.Email, Role: u.Role, UserID: u.ID,
	})
}

func (s *Server) handleInternalAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req controlclient.AuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	s.store.Audit(req.TenantID, req.Actor, req.Action, req.Target, req.Detail)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
