package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RoleAll     = "all"
	RoleControl = "control"
	RoleEdge    = "edge"
)

type PeerConfig struct {
	ID     string `yaml:"id"`
	HTTP   string `yaml:"http"`
	Region string `yaml:"region"`
}

type RegionPeer struct {
	Name          string `yaml:"name"`
	AdvertiseHTTP string `yaml:"advertise_http"`
}

type ClusterConfig struct {
	RedisURL      string       `yaml:"redis_url"`
	Secret        string       `yaml:"secret"`
	AdvertiseHTTP string       `yaml:"advertise_http"`
	Peers         []PeerConfig `yaml:"peers"`
}

type OIDCConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Issuer         string   `yaml:"issuer"`
	ClientID       string   `yaml:"client_id"`
	ClientSecret   string   `yaml:"client_secret"`
	RedirectURL    string   `yaml:"redirect_url"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

type ServerConfig struct {
	// Role: all | control | edge (empty = all).
	Role string `yaml:"role"`
	// APIListen is the control-plane HTTP listen addr (API/Dashboard/internal RPC).
	// For role=all, empty keeps API mounted on http_gateway (compat).
	APIListen string `yaml:"api_listen"`
	// ControlURL is required for role=edge (e.g. http://control:8090).
	ControlURL string `yaml:"control_url"`

	Listen        string        `yaml:"listen"`
	QUICListen    string        `yaml:"quic_listen"`
	HTTPGateway   string        `yaml:"http_gateway"`
	HTTPSGateway  string        `yaml:"https_gateway"`
	Token         string        `yaml:"token"`
	TCPPortMin    int           `yaml:"tcp_port_min"`
	TCPPortMax    int           `yaml:"tcp_port_max"`
	PublicHost    string        `yaml:"public_host"`
	BaseDomain    string        `yaml:"base_domain"`
	DataDir       string        `yaml:"data_dir"`
	AdminEmail    string        `yaml:"admin_email"`
	AdminPassword string        `yaml:"admin_password"`
	AdminAPIKey   string        `yaml:"admin_api_key"`
	TLSCert       string        `yaml:"tls_cert"`
	TLSKey        string        `yaml:"tls_key"`
	AutoTLS       bool          `yaml:"auto_tls"`
	EdgeID        string        `yaml:"edge_id"`
	Region        string        `yaml:"region"`
	EnableE2E         bool          `yaml:"enable_e2e"`
	AgentMTLS         string        `yaml:"agent_mtls"` // off | optional | require
	AccessDefaultDeny bool          `yaml:"access_default_deny"`
	ResumeTTL         time.Duration `yaml:"resume_ttl"`
	Regions           []RegionPeer  `yaml:"regions"`
	Cluster           ClusterConfig `yaml:"cluster"`
	OIDC              OIDCConfig    `yaml:"oidc"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
}

func (c *ServerConfig) NormalizedRole() string {
	r := strings.ToLower(strings.TrimSpace(c.Role))
	if r == "" {
		return RoleAll
	}
	return r
}

func (c *ServerConfig) IsControl() bool {
	r := c.NormalizedRole()
	return r == RoleControl || r == RoleAll
}

func (c *ServerConfig) IsEdge() bool {
	r := c.NormalizedRole()
	return r == RoleEdge || r == RoleAll
}

func (c *ServerConfig) IsEdgeOnly() bool {
	return c.NormalizedRole() == RoleEdge
}

func (c *ServerConfig) IsControlOnly() bool {
	return c.NormalizedRole() == RoleControl
}

type AgentTunnel struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	LocalAddr  string `yaml:"local_addr"`
	RemotePort int    `yaml:"remote_port"`
	Domain     string `yaml:"domain"`
}

type AgentMTLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type AgentConfig struct {
	ServerAddr      string          `yaml:"server_addr"`
	QUICAddr        string          `yaml:"quic_addr"`
	PreferQUIC      bool            `yaml:"prefer_quic"`
	PreferE2E       bool            `yaml:"prefer_e2e"`
	Region          string          `yaml:"region"`
	Token           string          `yaml:"token"`
	AgentID         string          `yaml:"agent_id"`
	Tunnels         []AgentTunnel   `yaml:"tunnels"`
	Reconnect       time.Duration   `yaml:"reconnect"`
	ResumeTokenFile string          `yaml:"resume_token_file"`
	MTLS            AgentMTLSConfig `yaml:"mtls"`
}

func LoadServer(path string) (*ServerConfig, error) {
	cfg := &ServerConfig{
		Role:          RoleAll,
		Listen:        ":7700",
		QUICListen:    ":7700",
		HTTPGateway:   ":8088",
		HTTPSGateway:  ":8443",
		TCPPortMin:    20000,
		TCPPortMax:    30000,
		PublicHost:    "127.0.0.1",
		BaseDomain:    "tunnel.local",
		DataDir:       "data",
		AdminEmail:    "admin@localhost",
		AdminPassword: "admin123",
		AutoTLS:       true,
		EdgeID:        "edge-1",
		Region:        "local",
		EnableE2E:         true,
		AgentMTLS:         "off",
		AccessDefaultDeny: false,
		ResumeTTL:         5 * time.Minute,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}
	role := cfg.NormalizedRole()
	cfg.Role = role
	switch role {
	case RoleAll, RoleControl, RoleEdge:
	default:
		return nil, fmt.Errorf("role must be all|control|edge")
	}

	if role != RoleEdge && cfg.Token == "" {
		return nil, fmt.Errorf("server token is required (bootstrap agent token)")
	}
	if role == RoleEdge {
		if cfg.ControlURL == "" {
			return nil, fmt.Errorf("control_url is required for role=edge")
		}
		if cfg.Cluster.Secret == "" {
			return nil, fmt.Errorf("cluster.secret is required for role=edge")
		}
	}
	if role == RoleControl && cfg.APIListen == "" {
		cfg.APIListen = ":8090"
	}
	if cfg.TCPPortMin <= 0 || cfg.TCPPortMax <= cfg.TCPPortMin {
		return nil, fmt.Errorf("invalid tcp port range")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.EdgeID == "" {
		cfg.EdgeID = "edge-1"
	}
	if cfg.Region == "" {
		cfg.Region = "local"
	}
	switch cfg.AgentMTLS {
	case "", "off", "optional", "require":
		if cfg.AgentMTLS == "" {
			cfg.AgentMTLS = "off"
		}
	default:
		return nil, fmt.Errorf("agent_mtls must be off|optional|require")
	}
	if cfg.Cluster.AdvertiseHTTP == "" && role != RoleControl {
		cfg.Cluster.AdvertiseHTTP = "http://127.0.0.1" + normalizeListen(cfg.HTTPGateway)
	}
	if cfg.OIDC.RedirectURL == "" && cfg.OIDC.Enabled {
		base := cfg.Cluster.AdvertiseHTTP
		if cfg.APIListen != "" {
			base = "http://127.0.0.1" + normalizeListen(cfg.APIListen)
		}
		cfg.OIDC.RedirectURL = strings.TrimRight(base, "/") + "/api/v1/auth/oidc/callback"
	}
	return cfg, nil
}

func normalizeListen(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[0] == ':' {
		return addr
	}
	return ":" + addr
}

func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{
		ServerAddr:      "127.0.0.1:7700",
		PreferQUIC:      true,
		PreferE2E:       true,
		Region:          "local",
		Reconnect:       3 * time.Second,
		ResumeTokenFile: "data/agent_resume.token",
	}
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("agent token is required")
	}
	if cfg.AgentID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "agent"
		}
		cfg.AgentID = host
	}
	if cfg.QUICAddr == "" {
		cfg.QUICAddr = cfg.ServerAddr
	}
	if len(cfg.Tunnels) == 0 {
		return nil, fmt.Errorf("at least one tunnel is required")
	}
	for i, t := range cfg.Tunnels {
		if t.Name == "" || t.LocalAddr == "" {
			return nil, fmt.Errorf("tunnel[%d]: name and local_addr are required", i)
		}
		if t.Type == "" {
			cfg.Tunnels[i].Type = "http"
		}
		if cfg.Tunnels[i].Type != "tcp" && cfg.Tunnels[i].Type != "http" {
			return nil, fmt.Errorf("tunnel[%d]: type must be tcp or http", i)
		}
	}
	return cfg, nil
}

func loadYAML(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, dst)
}
