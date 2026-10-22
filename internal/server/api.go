package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

type apiUser struct {
	User   *store.User
	Tenant *store.Tenant
}

func (s *Server) mountAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("/api/v1/auth/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/api/v1/auth/oidc/status", s.handleOIDCStatus)
	mux.HandleFunc("/api/v1/me", s.withAuth(s.handleMe))
	mux.HandleFunc("/api/v1/tenants", s.withAuth(s.handleTenants))
	mux.HandleFunc("/api/v1/tokens", s.withAuth(s.handleTokens))
	mux.HandleFunc("/api/v1/tunnels", s.withAuth(s.handleTunnelsAPI))
	mux.HandleFunc("/api/v1/tunnels/domain", s.withAuth(s.handleTunnelDomain))
	mux.HandleFunc("/api/v1/audit", s.withAuth(s.handleAudit))
	mux.HandleFunc("/api/v1/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("/api/v1/cluster", s.withAuth(s.handleCluster))
	mux.HandleFunc("/api/v1/regions", s.withAuth(s.handleRegions))
	mux.HandleFunc("/api/v1/sla/report", s.withAuth(s.handleSLAReport))
	mux.HandleFunc("/api/v1/compliance/export", s.withAuth(s.handleComplianceExport))
	// backward compatible
	mux.HandleFunc("/api/tunnels", s.handleLegacyTunnels)
}

func (s *Server) withAuth(next func(http.ResponseWriter, *http.Request, *apiUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.authenticate(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, user)
	}
}

func (s *Server) authenticate(r *http.Request) (*apiUser, error) {
	auth := r.Header.Get("Authorization")
	key := ""
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		key = strings.TrimSpace(auth[7:])
	}
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	if key == "" {
		return nil, store.ErrUnauthorized
	}
	u, ten, err := s.store.ResolveUserAPIKey(key)
	if err != nil {
		return nil, err
	}
	return &apiUser{User: u, Tenant: ten}, nil
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, ten, err := s.store.AuthenticatePassword(body.Email, body.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.store.Audit(ten.ID, u.Email, "auth.login", u.ID, r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{
		"api_key": u.APIKey,
		"user":    u,
		"tenant":  ten,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, au *apiUser) {
	writeJSON(w, http.StatusOK, map[string]any{"user": au.User, "tenant": au.Tenant})
}

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request, au *apiUser) {
	switch r.Method {
	case http.MethodGet:
		if au.User.Role == store.RoleAdmin {
			writeJSON(w, http.StatusOK, s.store.ListTenants())
			return
		}
		writeJSON(w, http.StatusOK, []store.Tenant{*au.Tenant})
	case http.MethodPost:
		if au.User.Role != store.RoleAdmin {
			writeErr(w, http.StatusForbidden, "admin only")
			return
		}
		var body struct {
			Name  string      `json:"name"`
			Slug  string      `json:"slug"`
			Quota store.Quota `json:"quota"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		ten, err := s.store.CreateTenant(body.Name, body.Slug, body.Quota)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.Audit(ten.ID, au.User.Email, "tenant.create", ten.Slug, "")
		writeJSON(w, http.StatusCreated, ten)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request, au *apiUser) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListAgentTokens(au.Tenant.ID))
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name == "" {
			body.Name = "agent"
		}
		tok, err := s.store.CreateAgentToken(au.Tenant.ID, body.Name)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.Audit(au.Tenant.ID, au.User.Email, "token.create", tok.ID, tok.Name)
		writeJSON(w, http.StatusCreated, tok)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeErr(w, http.StatusBadRequest, "id required")
			return
		}
		if err := s.store.RevokeAgentToken(id); err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		s.store.Audit(au.Tenant.ID, au.User.Email, "token.revoke", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleTunnelsAPI(w http.ResponseWriter, r *http.Request, au *apiUser) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := au.Tenant.ID
	if au.User.Role == store.RoleAdmin && r.URL.Query().Get("all") == "1" {
		tenantID = ""
	}
	writeJSON(w, http.StatusOK, s.store.ListTunnels(tenantID))
}

func (s *Server) handleTunnelDomain(w http.ResponseWriter, r *http.Request, au *apiUser) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	rec, err := s.store.SetTunnelDomain(au.Tenant.ID, body.Name, body.Domain)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "domain conflict")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tunnel not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.registry.BindDomain(au.Tenant.ID, body.Name, body.Domain)
	s.store.Audit(au.Tenant.ID, au.User.Email, "tunnel.domain", body.Name, body.Domain)
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, au *apiUser) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	tenantID := au.Tenant.ID
	if au.User.Role == store.RoleAdmin && r.URL.Query().Get("all") == "1" {
		tenantID = ""
	}
	writeJSON(w, http.StatusOK, s.store.ListAudits(tenantID, limit))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, au *apiUser) {
	total, tcp := s.store.CountTunnels(au.Tenant.ID)
	snap := s.metrics.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant":        au.Tenant,
		"online_agents": s.store.CountOnlineAgents(au.Tenant.ID),
		"tunnels":       total,
		"tcp_tunnels":   tcp,
		"live_routes":   len(s.registry.List()),
		"quota":         au.Tenant.Quota,
		"edge_id":       s.cfg.EdgeID,
		"region":        s.cfg.Region,
		"e2e_enabled":   s.cfg.EnableE2E,
		"oidc_enabled":  s.oidc != nil,
		"sla":           snap,
	})
}

func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request, au *apiUser) {
	writeJSON(w, http.StatusOK, map[string]any{
		"edge_id":        s.cfg.EdgeID,
		"region":         s.cfg.Region,
		"advertise_http": s.cfg.Cluster.AdvertiseHTTP,
		"edges":          s.cluster.ListEdges(),
		"tunnels":        s.cluster.ListTunnels(),
		"redis":          s.cfg.Cluster.RedisURL != "",
	})
}

func (s *Server) handleRegions(w http.ResponseWriter, r *http.Request, au *apiUser) {
	type regionView struct {
		Name          string `json:"name"`
		AdvertiseHTTP string `json:"advertise_http,omitempty"`
		Local         bool   `json:"local,omitempty"`
		Edges         int    `json:"edges"`
	}
	byName := map[string]*regionView{}
	byName[s.cfg.Region] = &regionView{Name: s.cfg.Region, AdvertiseHTTP: s.cfg.Cluster.AdvertiseHTTP, Local: true, Edges: 1}
	for _, rp := range s.cfg.Regions {
		if _, ok := byName[rp.Name]; !ok {
			byName[rp.Name] = &regionView{Name: rp.Name, AdvertiseHTTP: rp.AdvertiseHTTP}
		}
	}
	for _, e := range s.cluster.ListEdges() {
		name := e.Region
		if name == "" {
			name = "unknown"
		}
		if _, ok := byName[name]; !ok {
			byName[name] = &regionView{Name: name, AdvertiseHTTP: e.AdvertiseHTTP}
		}
		if name != s.cfg.Region {
			byName[name].Edges++
		}
	}
	out := make([]regionView, 0, len(byName))
	for _, v := range byName {
		out = append(out, *v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSLAReport(w http.ResponseWriter, r *http.Request, au *apiUser) {
	snap := s.metrics.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":   au.Tenant.ID,
		"tenant_slug": au.Tenant.Slug,
		"edge_id":     s.cfg.EdgeID,
		"region":      s.cfg.Region,
		"generated":   snap.StartedAt,
		"report":      snap,
		"target_sla":  "99.95%",
		"note":        "Availability derived from process uptime; wire synthetic probes for production SLA.",
	})
}

func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request, au *apiUser) {
	tenantID := au.Tenant.ID
	if au.User.Role == store.RoleAdmin && r.URL.Query().Get("all") == "1" {
		tenantID = ""
	}
	payload := map[string]any{
		"exported_at": time.Now().UTC(),
		"actor":       au.User.Email,
		"tenant_id":   au.Tenant.ID,
		"tunnels":     s.store.ListTunnels(tenantID),
		"audits":      s.store.ListAudits(tenantID, 1000),
		"users":       s.store.ListUsers(tenantID),
		"tokens":      s.store.ListAgentTokens(tenantID),
		"sla":         s.metrics.Snapshot(),
		"region":      s.cfg.Region,
		"edge_id":     s.cfg.EdgeID,
		"e2e":         s.cfg.EnableE2E,
	}
	s.store.Audit(au.Tenant.ID, au.User.Email, "compliance.export", au.Tenant.ID, "json")
	w.Header().Set("Content-Disposition", "attachment; filename=compliance-export.json")
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleOIDCStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.oidc != nil,
		"issuer": func() string {
			if s.cfg.OIDC.Enabled {
				return s.cfg.OIDC.Issuer
			}
			return ""
		}(),
	})
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeErr(w, http.StatusNotImplemented, "oidc disabled")
		return
	}
	state := randomState()
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, s.oidc.AuthCodeURL(state), http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeErr(w, http.StatusNotImplemented, "oidc disabled")
		return
	}
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("oidc_state")
	if err != nil || cookie.Value == "" || cookie.Value != state || !s.oidc.ValidateState(state) {
		writeErr(w, http.StatusBadRequest, "invalid oidc state")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeErr(w, http.StatusBadRequest, "missing code")
		return
	}
	claims, err := s.oidc.Exchange(r.Context(), code)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	u, ten, err := s.store.UpsertOIDCUser(claims.Email, claims.Name, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.store.Audit(ten.ID, u.Email, "auth.oidc", u.ID, claims.Sub)
	// Redirect to dashboard with api key fragment for SPA pickup.
	http.Redirect(w, r, "/dashboard/#api_key="+u.APIKey, http.StatusFound)
}

func randomState() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handleLegacyTunnels(w http.ResponseWriter, r *http.Request) {
	routes := s.registry.List()
	type item struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Tenant     string `json:"tenant"`
		AgentID    string `json:"agent_id"`
		PublicAddr string `json:"public_addr"`
		Domain     string `json:"domain,omitempty"`
		Local      string `json:"local"`
	}
	out := make([]item, 0, len(routes))
	for _, route := range routes {
		out = append(out, item{
			Name:       route.TunnelName,
			Type:       string(route.Type),
			Tenant:     route.TenantSlug,
			AgentID:    route.AgentID,
			PublicAddr: route.PublicAddr,
			Domain:     route.Domain,
			Local:      route.LocalHint,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
