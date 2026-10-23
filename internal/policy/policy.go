package policy

import (
	"net"
	"sort"
	"strings"

	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

const (
	ActionHTTP = "http.access"
	ActionTCP  = "tcp.access"
)

// Identity is the caller of a public tunnel access.
type Identity struct {
	Anonymous bool
	Email     string
	Role      store.Role
	UserID    string
}

// Decision is the result of policy evaluation.
type Decision struct {
	Allowed bool
	Reason  string
	Policy  string
}

// Evaluate checks policies for a tenant tunnel action.
// Rules:
//  1. Only enabled policies for matching tunnel+action are considered
//  2. Higher Priority first; first match wins
//  3. If no matching policy exists for tunnel+action → allow unless defaultDeny
//  4. If policies exist but none match identity/CIDR → deny
func Evaluate(policies []store.AccessPolicy, tenantID, tunnel, action, remoteIP string, id Identity, defaultDeny bool) Decision {
	type scored struct {
		p store.AccessPolicy
	}
	var matched []scored
	for _, p := range policies {
		if !p.Enabled || p.TenantID != tenantID {
			continue
		}
		if !matchList(p.Tunnels, tunnel) || !matchList(p.Actions, action) {
			continue
		}
		matched = append(matched, scored{p: p})
	}
	if len(matched) == 0 {
		if defaultDeny {
			return Decision{Allowed: false, Reason: "default deny (no policy)"}
		}
		return Decision{Allowed: true, Reason: "no policy (compat allow)"}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].p.Priority > matched[j].p.Priority
	})

	anySubjectEligible := false
	for _, m := range matched {
		p := m.p
		if !matchCIDRs(p.SourceCIDRs, remoteIP) {
			continue
		}
		if !matchSubject(p.Subjects, id) {
			continue
		}
		anySubjectEligible = true
		if strings.EqualFold(p.Effect, "deny") {
			return Decision{Allowed: false, Reason: "matched deny policy", Policy: p.Name}
		}
		return Decision{Allowed: true, Reason: "matched allow policy", Policy: p.Name}
	}
	if !anySubjectEligible {
		return Decision{Allowed: false, Reason: "no policy matched identity/cidr"}
	}
	return Decision{Allowed: false, Reason: "denied"}
}

func matchList(list []string, value string) bool {
	if len(list) == 0 {
		return true
	}
	value = strings.ToLower(value)
	for _, item := range list {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "*" || item == value {
			return true
		}
	}
	return false
}

func matchSubject(subjects []string, id Identity) bool {
	if len(subjects) == 0 {
		return true
	}
	for _, s := range subjects {
		s = strings.ToLower(strings.TrimSpace(s))
		switch {
		case s == "anyone" || s == "*":
			return true
		case s == "authenticated":
			if !id.Anonymous {
				return true
			}
		case strings.HasPrefix(s, "email:"):
			if strings.EqualFold(id.Email, strings.TrimPrefix(s, "email:")) {
				return true
			}
		case strings.HasPrefix(s, "role:"):
			if string(id.Role) == strings.TrimPrefix(s, "role:") {
				return true
			}
		}
	}
	return false
}

func matchCIDRs(cidrs []string, remoteIP string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(stripPort(remoteIP))
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			_, network, err := net.ParseCIDR(c)
			if err == nil && network.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(c); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
