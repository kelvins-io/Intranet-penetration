package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type PeerConfig struct {
	ID   string `yaml:"id"`
	HTTP string `yaml:"http"`
}

type ClusterConfig struct {
	RedisURL      string       `yaml:"redis_url"`
	Secret        string       `yaml:"secret"`
	AdvertiseHTTP string       `yaml:"advertise_http"`
	Peers         []PeerConfig `yaml:"peers"`
}

type OIDCConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
	// Optional: restrict to these email domains (empty = allow all)
	AllowedDomains []string `yaml:"allowed_domains"`
}

type ServerConfig struct {
	Listen        string        `yaml:"listen"`
	QUICListen    string        `yaml:"quic_listen"` // UDP; empty disables QUIC
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
	ResumeTTL     time.Duration `yaml:"resume_ttl"`
	Cluster       ClusterConfig `yaml:"cluster"`
	OIDC          OIDCConfig    `yaml:"oidc"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
}

type AgentTunnel struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	LocalAddr  string `yaml:"local_addr"`
	RemotePort int    `yaml:"remote_port"`
	Domain     string `yaml:"domain"`
}

type AgentConfig struct {
	ServerAddr string        `yaml:"server_addr"`
	QUICAddr   string        `yaml:"quic_addr"` // defaults to server_addr
	PreferQUIC bool          `yaml:"prefer_quic"`
	Token      string        `yaml:"token"`
	AgentID    string        `yaml:"agent_id"`
	Tunnels    []AgentTunnel `yaml:"tunnels"`
	Reconnect  time.Duration `yaml:"reconnect"`
	// ResumeTokenFile persists resume token across agent restarts.
	ResumeTokenFile string `yaml:"resume_token_file"`
}

func LoadServer(path string) (*ServerConfig, error) {
	cfg := &ServerConfig{
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
		ResumeTTL:     5 * time.Minute,
		ReadTimeout:   30 * time.Second,
		WriteTimeout:  30 * time.Second,
	}
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("server token is required (bootstrap agent token)")
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
	if cfg.Cluster.AdvertiseHTTP == "" {
		cfg.Cluster.AdvertiseHTTP = "http://127.0.0.1" + normalizeListen(cfg.HTTPGateway)
	}
	if cfg.OIDC.RedirectURL == "" && cfg.OIDC.Enabled {
		cfg.OIDC.RedirectURL = cfg.Cluster.AdvertiseHTTP + "/api/v1/auth/oidc/callback"
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
