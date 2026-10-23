package posture

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

// Decision is the result of posture evaluation.
type Decision struct {
	Allowed bool
	Reason  string
	Policy  string
}

// Evaluate checks enabled posture policies (highest priority first). All matching
// enabled policies must pass; if none exist, allow.
func Evaluate(policies []store.PosturePolicy, tenantID string, p protocol.DevicePosture) Decision {
	var matched []store.PosturePolicy
	for _, pol := range policies {
		if !pol.Enabled || pol.TenantID != tenantID {
			continue
		}
		matched = append(matched, pol)
	}
	if len(matched) == 0 {
		return Decision{Allowed: true, Reason: "no posture policy"}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Priority > matched[j].Priority
	})
	for _, pol := range matched {
		if err := checkOne(pol, p); err != nil {
			return Decision{Allowed: false, Reason: err.Error(), Policy: pol.Name}
		}
	}
	return Decision{Allowed: true, Reason: "ok", Policy: matched[0].Name}
}

func checkOne(pol store.PosturePolicy, p protocol.DevicePosture) error {
	if len(pol.RequireOS) > 0 {
		ok := false
		os := strings.ToLower(p.OS)
		for _, want := range pol.RequireOS {
			if strings.ToLower(want) == os {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("os %q not allowed", p.OS)
		}
	}
	if pol.MinAgentVersion != "" {
		if cmpVersion(p.AgentVersion, pol.MinAgentVersion) < 0 {
			return fmt.Errorf("agent version %q < required %q", p.AgentVersion, pol.MinAgentVersion)
		}
	}
	if pol.RequireEncrypted {
		if p.Encrypted == nil || !*p.Encrypted {
			return fmt.Errorf("disk encryption required")
		}
	}
	if pol.RequireFirewall {
		if p.Firewall == nil || !*p.Firewall {
			return fmt.Errorf("firewall required")
		}
	}
	if pol.RequireScreenLock {
		if p.ScreenLock == nil || !*p.ScreenLock {
			return fmt.Errorf("screen lock required")
		}
	}
	for k, want := range pol.RequireAttrs {
		got, ok := p.Attrs[k]
		if !ok || got != want {
			return fmt.Errorf("attr %s=%q required (got %q)", k, want, got)
		}
	}
	return nil
}

// cmpVersion compares dotted numeric versions; missing parts treated as 0.
func cmpVersion(a, b string) int {
	as := splitVer(a)
	bs := splitVer(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
		if i < len(as) {
			ai = as[i]
		}
		if i < len(bs) {
			bi = bs[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func splitVer(v string) []int {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// strip non-numeric suffix (e.g. 1.2.3-beta)
		num := p
		for i, c := range p {
			if c < '0' || c > '9' {
				num = p[:i]
				break
			}
		}
		n, _ := strconv.Atoi(num)
		out = append(out, n)
	}
	return out
}

func ToRecord(tenantID, agentID string, p protocol.DevicePosture) store.AgentPosture {
	return store.AgentPosture{
		TenantID:   tenantID,
		AgentID:    agentID,
		OS:         p.OS,
		Arch:       p.Arch,
		Hostname:   p.Hostname,
		Version:    p.AgentVersion,
		DeviceID:   p.DeviceID,
		Encrypted:  p.Encrypted,
		Firewall:   p.Firewall,
		ScreenLock: p.ScreenLock,
		Attrs:      p.Attrs,
	}
}
