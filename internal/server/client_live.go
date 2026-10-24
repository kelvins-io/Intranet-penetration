package server

import (
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

// LiveClientSession is an active user Access Client connection on this Edge.
type LiveClientSession struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	DeviceID  string    `json:"device_id"`
	Remote    string    `json:"remote"`
	EdgeID    string    `json:"edge_id"`
	Region    string    `json:"region"`
	Connected time.Time `json:"connected_at"`

	sess *tunnel.Session
}

type clientLiveRegistry struct {
	mu   sync.RWMutex
	byID map[string]*LiveClientSession
}

func newClientLiveRegistry() *clientLiveRegistry {
	return &clientLiveRegistry{byID: map[string]*LiveClientSession{}}
}

func (r *clientLiveRegistry) Register(ls *LiveClientSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[ls.ID] = ls
}

func (r *clientLiveRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
}

func (r *clientLiveRegistry) List(tenantID string) []LiveClientSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]LiveClientSession, 0, len(r.byID))
	for _, ls := range r.byID {
		if tenantID != "" && ls.TenantID != tenantID {
			continue
		}
		cp := *ls
		cp.sess = nil
		out = append(out, cp)
	}
	return out
}

func (r *clientLiveRegistry) Kick(id, reason string) error {
	r.mu.Lock()
	ls := r.byID[id]
	r.mu.Unlock()
	if ls == nil || ls.sess == nil {
		return store.ErrNotFound
	}
	_ = protocol.WriteJSON(ls.sess.Control(), protocol.MsgKick, protocol.KickBody{
		SessionID: id,
		Reason:    reason,
	})
	_ = ls.sess.Close()
	r.Unregister(id)
	return nil
}

func (r *clientLiveRegistry) KickUser(tenantID, userID, reason string) int {
	r.mu.RLock()
	ids := make([]string, 0)
	for id, ls := range r.byID {
		if ls.TenantID == tenantID && (userID == "" || ls.UserID == userID) {
			ids = append(ids, id)
		}
	}
	r.mu.RUnlock()
	n := 0
	for _, id := range ids {
		if err := r.Kick(id, reason); err == nil {
			n++
		}
	}
	return n
}
