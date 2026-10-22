package resume

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

type State struct {
	Token     string
	TenantID  string
	AgentID   string
	Tunnels   []protocol.AssignedTunnel
	ExpiresAt time.Time
}

type Store struct {
	mu   sync.RWMutex
	ttl  time.Duration
	byToken map[string]*State
	byAgent map[string]string // tenant/agent -> token
}

func New(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	s := &Store{
		ttl:     ttl,
		byToken: make(map[string]*State),
		byAgent: make(map[string]string),
	}
	go s.reaper()
	return s
}

func agentKey(tenantID, agentID string) string { return tenantID + "/" + agentID }

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Store) Issue(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byAgent[agentKey(tenantID, agentID)]; ok {
		delete(s.byToken, old)
	}
	tok := newToken()
	st := &State{
		Token:     tok,
		TenantID:  tenantID,
		AgentID:   agentID,
		Tunnels:   append([]protocol.AssignedTunnel(nil), tunnels...),
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.byToken[tok] = st
	s.byAgent[agentKey(tenantID, agentID)] = tok
	return tok
}

func (s *Store) KeepAlive(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ak := agentKey(tenantID, agentID)
	if tok, ok := s.byAgent[ak]; ok {
		if st, ok := s.byToken[tok]; ok {
			st.Tunnels = append([]protocol.AssignedTunnel(nil), tunnels...)
			st.ExpiresAt = time.Now().Add(s.ttl)
			return tok
		}
	}
	tok := newToken()
	s.byToken[tok] = &State{
		Token:     tok,
		TenantID:  tenantID,
		AgentID:   agentID,
		Tunnels:   append([]protocol.AssignedTunnel(nil), tunnels...),
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.byAgent[ak] = tok
	return tok
}

func (s *Store) Lookup(token string) (*State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.byToken[token]
	if !ok || time.Now().After(st.ExpiresAt) {
		return nil, false
	}
	cp := *st
	cp.Tunnels = append([]protocol.AssignedTunnel(nil), st.Tunnels...)
	return &cp, true
}

func (s *Store) Consume(token string) (*State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.byToken[token]
	if !ok || time.Now().After(st.ExpiresAt) {
		return nil, false
	}
	delete(s.byToken, token)
	delete(s.byAgent, agentKey(st.TenantID, st.AgentID))
	cp := *st
	cp.Tunnels = append([]protocol.AssignedTunnel(nil), st.Tunnels...)
	return &cp, true
}

// SoftHold extends TTL on disconnect so agent can resume.
func (s *Store) SoftHold(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string {
	return s.KeepAlive(tenantID, agentID, tunnels)
}

func (s *Store) reaper() {
	t := time.NewTicker(30 * time.Second)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for tok, st := range s.byToken {
			if now.After(st.ExpiresAt) {
				delete(s.byToken, tok)
				delete(s.byAgent, agentKey(st.TenantID, st.AgentID))
			}
		}
		s.mu.Unlock()
	}
}
