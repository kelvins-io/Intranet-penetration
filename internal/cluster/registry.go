package cluster

import (
	"encoding/json"
	"sync"
	"time"
)

type TunnelLocation struct {
	EdgeID       string    `json:"edge_id"`
	AdvertiseHTTP string   `json:"advertise_http"`
	TenantID     string    `json:"tenant_id"`
	TenantSlug   string    `json:"tenant_slug"`
	TunnelName   string    `json:"tunnel_name"`
	AgentID      string    `json:"agent_id"`
	Type         string    `json:"type"`
	Domain       string    `json:"domain,omitempty"`
	PublicAddr   string    `json:"public_addr,omitempty"`
	RemotePort   int       `json:"remote_port,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type EdgeInfo struct {
	ID            string    `json:"id"`
	AdvertiseHTTP string    `json:"advertise_http"`
	LastSeen      time.Time `json:"last_seen"`
}

// Registry is a shared (or local) map of tunnel -> owning edge.
type Registry interface {
	Put(loc TunnelLocation) error
	Get(tenantID, name string) (*TunnelLocation, bool)
	GetByDomain(domain string) (*TunnelLocation, bool)
	DeleteAgent(tenantID, agentID string) error
	Heartbeat(edgeID, advertiseHTTP string) error
	ListEdges() []EdgeInfo
	ListTunnels() []TunnelLocation
	Close() error
}

type MemoryRegistry struct {
	mu      sync.RWMutex
	byKey   map[string]TunnelLocation
	byDomain map[string]string // domain -> key
	edges   map[string]EdgeInfo
}

func NewMemory() *MemoryRegistry {
	return &MemoryRegistry{
		byKey:    make(map[string]TunnelLocation),
		byDomain: make(map[string]string),
		edges:    make(map[string]EdgeInfo),
	}
}

func key(tenantID, name string) string { return tenantID + "/" + name }

func (m *MemoryRegistry) Put(loc TunnelLocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	loc.UpdatedAt = time.Now().UTC()
	k := key(loc.TenantID, loc.TunnelName)
	if old, ok := m.byKey[k]; ok && old.Domain != "" {
		delete(m.byDomain, old.Domain)
	}
	m.byKey[k] = loc
	if loc.Domain != "" {
		m.byDomain[loc.Domain] = k
	}
	return nil
}

func (m *MemoryRegistry) Get(tenantID, name string) (*TunnelLocation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	loc, ok := m.byKey[key(tenantID, name)]
	if !ok {
		return nil, false
	}
	cp := loc
	return &cp, true
}

func (m *MemoryRegistry) GetByDomain(domain string) (*TunnelLocation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.byDomain[domain]
	if !ok {
		return nil, false
	}
	loc, ok := m.byKey[k]
	if !ok {
		return nil, false
	}
	cp := loc
	return &cp, true
}

func (m *MemoryRegistry) DeleteAgent(tenantID, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, loc := range m.byKey {
		if loc.TenantID == tenantID && loc.AgentID == agentID {
			if loc.Domain != "" {
				delete(m.byDomain, loc.Domain)
			}
			delete(m.byKey, k)
		}
	}
	return nil
}

func (m *MemoryRegistry) Heartbeat(edgeID, advertiseHTTP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.edges[edgeID] = EdgeInfo{ID: edgeID, AdvertiseHTTP: advertiseHTTP, LastSeen: time.Now().UTC()}
	return nil
}

func (m *MemoryRegistry) ListEdges() []EdgeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EdgeInfo, 0, len(m.edges))
	for _, e := range m.edges {
		out = append(out, e)
	}
	return out
}

func (m *MemoryRegistry) ListTunnels() []TunnelLocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]TunnelLocation, 0, len(m.byKey))
	for _, loc := range m.byKey {
		out = append(out, loc)
	}
	return out
}

func (m *MemoryRegistry) Close() error { return nil }

// MarshalSnapshot helps tests / debugging.
func (m *MemoryRegistry) MarshalSnapshot() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.Marshal(map[string]any{"tunnels": m.byKey, "edges": m.edges})
}
