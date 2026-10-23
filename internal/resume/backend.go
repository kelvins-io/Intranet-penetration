package resume

import "github.com/kelvins-io/Intranet-penetration/internal/protocol"

// Backend stores resume tokens. Memory or Redis-backed for multi-edge share.
type Backend interface {
	Issue(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string
	KeepAlive(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string
	Lookup(token string) (*State, bool)
	Consume(token string) (*State, bool)
	SoftHold(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string
}

// Ensure memory Store implements Backend.
var _ Backend = (*Store)(nil)
