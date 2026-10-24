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

// PosturePolicy requires agent device posture before handshake succeeds.
// RequireOS: list of allowed OS (empty = any). RequireAttrs: key=value exact match.
// RequireEncrypted/Firewall/ScreenLock: when true, posture must report true.
type PosturePolicy struct {
	ID               string            `json:"id"`
	TenantID         string            `json:"tenant_id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	Priority         int               `json:"priority"`
	RequireOS        []string          `json:"require_os,omitempty"`
	MinAgentVersion  string            `json:"min_agent_version,omitempty"` // semver-ish major.minor.patch
	RequireEncrypted bool              `json:"require_encrypted,omitempty"`
	RequireFirewall  bool              `json:"require_firewall,omitempty"`
	RequireScreenLock bool             `json:"require_screen_lock,omitempty"`
	RequireAttrs     map[string]string `json:"require_attrs,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

// AgentPosture is the last reported posture for an agent.
type AgentPosture struct {
	TenantID  string    `json:"tenant_id"`
	AgentID   string    `json:"agent_id"`
	OS        string    `json:"os,omitempty"`
	Arch      string    `json:"arch,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Version   string    `json:"agent_version,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	Encrypted *bool     `json:"encrypted,omitempty"`
	Firewall  *bool     `json:"firewall,omitempty"`
	ScreenLock *bool    `json:"screen_lock,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
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

// AccessPolicy controls who can reach which tunnels.
// Subjects: anyone | authenticated | email:<addr> | role:<admin|member>
// Tunnels: exact name or "*"
// Actions: http.access | tcp.access | "*"
type AccessPolicy struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	Effect      string    `json:"effect"` // allow | deny
	Subjects    []string  `json:"subjects"`
	Tunnels     []string  `json:"tunnels"`
	Actions     []string  `json:"actions"`
	SourceCIDRs []string  `json:"source_cidrs,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// AgentCert is metadata for an issued mTLS client certificate.
type AgentCert struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	AgentID   string    `json:"agent_id"`
	Serial    string    `json:"serial"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	// Kind distinguishes agent vs user-client certificates (empty = agent).
	Kind string `json:"kind,omitempty"` // agent | client
}

// BoundDevice ties a user Access Client device_id to a tenant user (device binding).
type BoundDevice struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email,omitempty"`
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname,omitempty"`
	OS        string    `json:"os,omitempty"`
	Arch      string    `json:"arch,omitempty"`
	BoundAt   time.Time `json:"bound_at"`
	LastSeen  time.Time `json:"last_seen"`
	Revoked   bool      `json:"revoked"`
}

// TrafficPolicy limits public traffic to tunnels after AccessPolicy allows.
// Scope: ip | tunnel | ip+tunnel (default ip+tunnel).
// RateRPS=0, MaxConcurrent=0, MaxBandwidthBPS=0 means no limit for that dimension.
type TrafficPolicy struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Enabled          bool      `json:"enabled"`
	Priority         int       `json:"priority"`
	Tunnels          []string  `json:"tunnels"` // exact or "*"
	Scope            string    `json:"scope"`   // ip | tunnel | ip+tunnel
	RateRPS          float64   `json:"rate_rps"`
	Burst            int       `json:"burst"`
	MaxConcurrent    int       `json:"max_concurrent"`
	MaxBandwidthBPS  int64     `json:"max_bandwidth_bps"` // bytes/sec per scope key; 0 = unlimited
	CreatedAt        time.Time `json:"created_at"`
}

type Snapshot struct {
	Tenants         []Tenant         `json:"tenants"`
	Users           []User           `json:"users"`
	AgentTokens     []AgentToken     `json:"agent_tokens"`
	Tunnels         []TunnelRecord   `json:"tunnels"`
	Audits          []AuditEvent     `json:"audits"`
	Policies        []AccessPolicy   `json:"policies"`
	AgentCerts      []AgentCert      `json:"agent_certs"`
	TrafficPolicies []TrafficPolicy  `json:"traffic_policies"`
	PosturePolicies []PosturePolicy  `json:"posture_policies"`
	AgentPostures   []AgentPosture   `json:"agent_postures"`
	BoundDevices    []BoundDevice    `json:"bound_devices"`
}
