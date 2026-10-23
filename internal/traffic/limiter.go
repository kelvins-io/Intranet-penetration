package traffic

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

// Decision is the result of a rate-limit check.
type Decision struct {
	Allowed      bool
	Reason       string
	Policy       string
	BandwidthBPS int64  // from matched policy; 0 = unlimited
	Release      func() // call when connection/request finishes (concurrent)
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// Limiter applies TrafficPolicy RPS + concurrency limits in-process.
type Limiter struct {
	mu          sync.Mutex
	buckets     map[string]*tokenBucket
	concurrent  map[string]int
	lastCleanup time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{
		buckets:    map[string]*tokenBucket{},
		concurrent: map[string]int{},
	}
}

// Allow evaluates the highest-priority matching policy for tenant/tunnel.
// remoteAddr may be host:port; IP is extracted.
func (l *Limiter) Allow(policies []store.TrafficPolicy, tenantID, tunnel, remoteAddr string) Decision {
	p := selectPolicy(policies, tenantID, tunnel)
	if p == nil {
		return Decision{Allowed: true, Reason: "no traffic policy", Release: func() {}}
	}
	bw := p.MaxBandwidthBPS
	key := scopeKey(p.Scope, tenantID, tunnel, remoteIP(remoteAddr))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeCleanupLocked()

	if p.RateRPS > 0 {
		burst := float64(p.Burst)
		if burst <= 0 {
			burst = p.RateRPS
			if burst < 1 {
				burst = 1
			}
		}
		b := l.buckets[key]
		now := time.Now()
		if b == nil {
			b = &tokenBucket{tokens: burst, last: now}
			l.buckets[key] = b
		} else {
			elapsed := now.Sub(b.last).Seconds()
			b.tokens += elapsed * p.RateRPS
			if b.tokens > burst {
				b.tokens = burst
			}
			b.last = now
		}
		if b.tokens < 1 {
			return Decision{
				Allowed:      false,
				Reason:       fmt.Sprintf("rate limit %.2f rps", p.RateRPS),
				Policy:       p.Name,
				BandwidthBPS: bw,
				Release:      func() {},
			}
		}
		b.tokens--
	}

	if p.MaxConcurrent > 0 {
		if l.concurrent[key] >= p.MaxConcurrent {
			return Decision{
				Allowed:      false,
				Reason:       fmt.Sprintf("max concurrent %d", p.MaxConcurrent),
				Policy:       p.Name,
				BandwidthBPS: bw,
				Release:      func() {},
			}
		}
		l.concurrent[key]++
		k := key
		return Decision{
			Allowed:      true,
			Reason:       "ok",
			Policy:       p.Name,
			BandwidthBPS: bw,
			Release: func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				if l.concurrent[k] > 0 {
					l.concurrent[k]--
				}
			},
		}
	}
	return Decision{Allowed: true, Reason: "ok", Policy: p.Name, BandwidthBPS: bw, Release: func() {}}
}

func selectPolicy(policies []store.TrafficPolicy, tenantID, tunnel string) *store.TrafficPolicy {
	var matched []store.TrafficPolicy
	for _, p := range policies {
		if !p.Enabled || p.TenantID != tenantID {
			continue
		}
		if p.RateRPS <= 0 && p.MaxConcurrent <= 0 && p.MaxBandwidthBPS <= 0 {
			continue
		}
		if !matchTunnel(p.Tunnels, tunnel) {
			continue
		}
		matched = append(matched, p)
	}
	if len(matched) == 0 {
		return nil
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Priority > matched[j].Priority
	})
	p := matched[0]
	return &p
}

func matchTunnel(list []string, name string) bool {
	if len(list) == 0 {
		return true
	}
	for _, t := range list {
		if t == "*" || t == name {
			return true
		}
	}
	return false
}

func scopeKey(scope, tenantID, tunnel, ip string) string {
	switch strings.ToLower(scope) {
	case "ip":
		return tenantID + "|ip|" + ip
	case "tunnel":
		return tenantID + "|tun|" + tunnel
	default: // ip+tunnel
		return tenantID + "|" + tunnel + "|" + ip
	}
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (l *Limiter) maybeCleanupLocked() {
	if time.Since(l.lastCleanup) < time.Minute {
		return
	}
	l.lastCleanup = time.Now()
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
	for k, n := range l.concurrent {
		if n <= 0 {
			delete(l.concurrent, k)
		}
	}
}
