package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Route struct {
	AgentID    string
	TunnelName string
	Type       protocol.TunnelType
	LocalHint  string
	PublicAddr string
	RemotePort int
	Session    *tunnel.Session
}

type Registry struct {
	mu     sync.RWMutex
	byName map[string]*Route // tunnel name -> route
	ports  map[int]string    // allocated tcp ports
}

func NewRegistry() *Registry {
	return &Registry{
		byName: make(map[string]*Route),
		ports:  make(map[int]string),
	}
}

func (r *Registry) Register(route *Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.byName[route.TunnelName]; ok {
		if existing.Session != nil && !existing.Session.IsClosed() && existing.AgentID != route.AgentID {
			return fmt.Errorf("tunnel %q already registered by agent %s", route.TunnelName, existing.AgentID)
		}
		if existing.RemotePort > 0 {
			delete(r.ports, existing.RemotePort)
		}
	}
	if route.RemotePort > 0 {
		if owner, ok := r.ports[route.RemotePort]; ok && owner != "" && owner != route.TunnelName {
			return fmt.Errorf("port %d already used by tunnel %q", route.RemotePort, owner)
		}
		r.ports[route.RemotePort] = route.TunnelName
	}
	r.byName[route.TunnelName] = route
	return nil
}

func (r *Registry) UnregisterAgent(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, route := range r.byName {
		if route.AgentID != agentID {
			continue
		}
		if route.RemotePort > 0 {
			delete(r.ports, route.RemotePort)
		}
		delete(r.byName, name)
	}
}

func (r *Registry) Get(name string) (*Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	route, ok := r.byName[name]
	return route, ok
}

func (r *Registry) List() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Route, 0, len(r.byName))
	for _, route := range r.byName {
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
		// mark reserved temporarily with empty owner; Register will set real owner
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

// OpenToAgent opens a data stream to the agent owning the tunnel.
func (r *Registry) OpenToAgent(tunnelName, meta string) (net.Conn, error) {
	route, ok := r.Get(tunnelName)
	if !ok || route.Session == nil || route.Session.IsClosed() {
		return nil, fmt.Errorf("tunnel %q offline", tunnelName)
	}
	return route.Session.OpenDataStream(tunnelName, meta)
}
