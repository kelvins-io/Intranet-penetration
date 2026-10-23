package server

import (
	"net/http"
	"strings"

	"github.com/kelvins-io/Intranet-penetration/internal/policy"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func (s *Server) resolveAccessIdentity(r *http.Request) policy.Identity {
	key := ""
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		key = strings.TrimSpace(auth[7:])
	}
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	if key == "" {
		key = r.URL.Query().Get("access_token")
	}
	if key == "" {
		if c, err := r.Cookie("ip_access_key"); err == nil {
			key = c.Value
		}
	}
	if key == "" {
		return policy.Identity{Anonymous: true}
	}
	u, _, err := s.store.ResolveUserAPIKey(key)
	if err != nil {
		return policy.Identity{Anonymous: true}
	}
	return policy.Identity{
		Email:  u.Email,
		Role:   u.Role,
		UserID: u.ID,
	}
}

func (s *Server) enforceAccess(w http.ResponseWriter, r *http.Request, tenantID, tunnel, action string) bool {
	id := s.resolveAccessIdentity(r)
	d := policy.Evaluate(
		s.store.ListPolicies(tenantID),
		tenantID,
		tunnel,
		action,
		r.RemoteAddr,
		id,
		s.cfg.AccessDefaultDeny,
	)
	if d.Allowed {
		return true
	}
	actor := "anonymous"
	if !id.Anonymous {
		actor = id.Email
	}
	s.store.Audit(tenantID, actor, "access.deny", tunnel, d.Reason+" action="+action)
	if id.Anonymous && (strings.Contains(d.Reason, "identity") ||
		strings.Contains(d.Reason, "authenticated") ||
		strings.Contains(d.Reason, "no policy matched")) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunnel"`)
		http.Error(w, "unauthorized: "+d.Reason, http.StatusUnauthorized)
		return false
	}
	http.Error(w, "forbidden: "+d.Reason, http.StatusForbidden)
	return false
}

func (s *Server) enforceTCPAccess(tenantID, tunnel, remoteAddr string) error {
	d := policy.Evaluate(
		s.store.ListPolicies(tenantID),
		tenantID,
		tunnel,
		policy.ActionTCP,
		remoteAddr,
		policy.Identity{Anonymous: true},
		s.cfg.AccessDefaultDeny,
	)
	if d.Allowed {
		return nil
	}
	s.store.Audit(tenantID, "public", "access.deny", tunnel, d.Reason+" action=tcp.access")
	return store.ErrUnauthorized
}
