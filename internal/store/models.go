package store

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

type Quota struct {
	MaxAgents  int `json:"max_agents"`
	MaxTunnels int `json:"max_tunnels"`
	MaxTCP     int `json:"max_tcp"`
}

func DefaultQuota() Quota {
	return Quota{MaxAgents: 10, MaxTunnels: 50, MaxTCP: 20}
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Quota     Quota     `json:"quota"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"password_hash,omitempty"`
	APIKey       string    `json:"api_key"`
	CreatedAt    time.Time `json:"created_at"`
}

// AgentToken is an enrollment credential for agents of a tenant.
type AgentToken struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

type TunnelRecord struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // http | tcp
	LocalHint  string    `json:"local_hint,omitempty"`
	Domain     string    `json:"domain,omitempty"` // custom domain
	PublicAddr string    `json:"public_addr,omitempty"`
	RemotePort int       `json:"remote_port,omitempty"`
	AgentID    string    `json:"agent_id,omitempty"`
	Online     bool      `json:"online"`
	UpdatedAt  time.Time `json:"updated_at"`
	CreatedAt  time.Time `json:"created_at"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Snapshot struct {
	Tenants     []Tenant       `json:"tenants"`
	Users       []User         `json:"users"`
	AgentTokens []AgentToken   `json:"agent_tokens"`
	Tunnels     []TunnelRecord `json:"tunnels"`
	Audits      []AuditEvent   `json:"audits"`
}
