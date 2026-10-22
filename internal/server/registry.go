package server

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Route struct {
	TenantID   string
	TenantSlug string
	AgentID    string
	TunnelName string
	Type       protocol.TunnelType
	LocalHint  string
	PublicAddr string
	Domain     string
	RemotePort int
	Session    *tunnel.Session
}

func (r *Route) Key() string {
	return store.RouteKey(r.TenantID, r.TunnelName)
}

type Registry struct {
	mu       sync.RWMutex
	byKey    map[string]*Route // tenantID/name
	byDomain map[string]*Route // custom domain / subdomain host
	ports    map[int]string    // allocated tcp ports -> route key
}

func NewRegistry() *Registry {
	return &Registry{
		byKey:    make(map[string]*Route),
		byDomain: make(map[string]*Route),
		ports:    make(map[int]string),
	}
}

func (r *Registry) Register(route *Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := route.Key()
	if existing, ok := r.byKey[key]; ok {
		if existing.Session != nil && !existing.Session.IsClosed() && existing.AgentID != route.AgentID {
			return fmt.Errorf("tunnel %q already registered by agent %s", key, existing.AgentID)
		}
		if existing.RemotePort > 0 {
			delete(r.ports, existing.RemotePort)
		}
		if existing.Domain != "" {
			delete(r.byDomain, existing.Domain)
		}
	}
	if route.RemotePort > 0 {
		if owner, ok := r.ports[route.RemotePort]; ok && owner != "" && owner != key {
			return fmt.Errorf("port %d already used by tunnel %q", route.RemotePort, owner)
		}
		r.ports[route.RemotePort] = key
	}
	if route.Domain != "" {
		d := strings.ToLower(route.Domain)
		if owner, ok := r.byDomain[d]; ok && owner.Key() != key {
			return fmt.Errorf("domain %q already used by tunnel %q", d, owner.Key())
		}
		route.Domain = d
		r.byDomain[d] = route
	}
	r.byKey[key] = route
	return nil
}

func (r *Registry) UnregisterAgent(tenantID, agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, route := range r.byKey {
		if route.TenantID != tenantID || route.AgentID != agentID {
			continue
		}
		if route.RemotePort > 0 {
			delete(r.ports, route.RemotePort)
		}
		if route.Domain != "" {
			delete(r.byDomain, route.Domain)
		}
		delete(r.byKey, key)
	}
}

func (r *Registry) Get(tenantID, name string) (*Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	route, ok := r.byKey[store.RouteKey(tenantID, name)]
	return route, ok
}

func (r *Registry) GetByHost(host string) (*Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h := strings.ToLower(host)
	if route, ok := r.byDomain[h]; ok {
		return route, true
	}
	return nil, false
}

func (r *Registry) List() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Route, 0, len(r.byKey))
	for _, route := range r.byKey {
		out = append(out, route)
	}
	return out
}

func (r *Registry) AllocatePort(min, max, preferred int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if preferred > 0 {
		if preferred < min || preferred > max {
			return 0, fmt.Errorf("preferred port %d out of range [%d,%d]", preferred, min, max)
		}
		if owner, ok := r.ports[preferred]; ok {
			return 0, fmt.Errorf("port %d already used by tunnel %q", preferred, owner)
		}
		r.ports[preferred] = ""
		return preferred, nil
	}
	for p := min; p <= max; p++ {
		if _, ok := r.ports[p]; !ok {
			r.ports[p] = ""
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port in [%d,%d]", min, max)
}

func (r *Registry) ReleasePort(port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ports, port)
}

func (r *Registry) OpenToAgent(tenantID, tunnelName, meta string) (net.Conn, error) {
	route, ok := r.Get(tenantID, tunnelName)
	if !ok || route.Session == nil || route.Session.IsClosed() {
		return nil, fmt.Errorf("tunnel %q offline", store.RouteKey(tenantID, tunnelName))
	}
	return route.Session.OpenDataStream(tunnelName, meta)
}

func (r *Registry) BindDomain(tenantID, name, domain string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := store.RouteKey(tenantID, name)
	route, ok := r.byKey[key]
	if !ok {
		return fmt.Errorf("tunnel offline")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if route.Domain != "" {
		delete(r.byDomain, route.Domain)
	}
	if domain != "" {
		if owner, ok := r.byDomain[domain]; ok && owner.Key() != key {
			return fmt.Errorf("domain %q already used", domain)
		}
		r.byDomain[domain] = route
	}
	route.Domain = domain
	return nil
}
