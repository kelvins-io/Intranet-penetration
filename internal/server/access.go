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
	if s.store != nil {
		u, _, err := s.store.ResolveUserAPIKey(key)
		if err != nil {
			return policy.Identity{Anonymous: true}
		}
		return policy.Identity{Email: u.Email, Role: u.Role, UserID: u.ID}
	}
	if s.ctrl != nil {
		id, err := s.ctrl.ResolveIdentity(key)
		if err != nil {
			return policy.Identity{Anonymous: true}
		}
		return policy.Identity{Email: id.Email, Role: id.Role, UserID: id.UserID}
	}
	return policy.Identity{Anonymous: true}
}

func (s *Server) enforceAccess(w http.ResponseWriter, r *http.Request, tenantID, tunnel, action string) bool {
	id := s.resolveAccessIdentity(r)
	d := policy.Evaluate(
		s.listPolicies(tenantID),
		tenantID,
		tunnel,
		action,
		r.RemoteAddr,
		id,
		s.cfg.AccessDefaultDeny,
	)
	if !d.Allowed {
		actor := "anonymous"
		if !id.Anonymous {
			actor = id.Email
		}
		s.auditEvent(tenantID, actor, "access.deny", tunnel, d.Reason+" action="+action)
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
	return true
}

// enforceTraffic returns a release func that must be deferred by the caller,
// plus optional bandwidth cap (bytes/sec, 0 = unlimited).
func (s *Server) enforceTraffic(w http.ResponseWriter, tenantID, tunnel, remoteAddr string) (release func(), bandwidthBPS int64, ok bool) {
	td := s.limiter.Allow(s.listTrafficPolicies(tenantID), tenantID, tunnel, remoteAddr)
	if td.Allowed {
		return td.Release, td.BandwidthBPS, true
	}
	s.auditEvent(tenantID, "public", "traffic.deny", tunnel, td.Reason+" policy="+td.Policy)
	w.Header().Set("Retry-After", "1")
	http.Error(w, "too many requests: "+td.Reason, http.StatusTooManyRequests)
	return func() {}, 0, false
}

func (s *Server) enforceTCPAccess(tenantID, tunnel, remoteAddr string) error {
	d := policy.Evaluate(
		s.listPolicies(tenantID),
		tenantID,
		tunnel,
		policy.ActionTCP,
		remoteAddr,
		policy.Identity{Anonymous: true},
		s.cfg.AccessDefaultDeny,
	)
	if !d.Allowed {
		s.auditEvent(tenantID, "public", "access.deny", tunnel, d.Reason+" action=tcp.access")
		return store.ErrUnauthorized
	}
	return nil
}

func (s *Server) enforceTCPTraffic(tenantID, tunnel, remoteAddr string) (release func(), bandwidthBPS int64, err error) {
	td := s.limiter.Allow(s.listTrafficPolicies(tenantID), tenantID, tunnel, remoteAddr)
	if td.Allowed {
		return td.Release, td.BandwidthBPS, nil
	}
	s.auditEvent(tenantID, "public", "traffic.deny", tunnel, td.Reason+" policy="+td.Policy)
	return func() {}, 0, store.ErrUnauthorized
}
