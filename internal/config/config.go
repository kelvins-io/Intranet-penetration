package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Listen       string        `yaml:"listen"`       // agent mux, e.g. :7700
	HTTPGateway  string        `yaml:"http_gateway"` // HTTP reverse proxy + dashboard
	HTTPSGateway string        `yaml:"https_gateway"`
	Token        string        `yaml:"token"` // bootstrap agent token (compat)
	TCPPortMin   int           `yaml:"tcp_port_min"`
	TCPPortMax   int           `yaml:"tcp_port_max"`
	PublicHost   string        `yaml:"public_host"`
	BaseDomain   string        `yaml:"base_domain"` // e.g. tunnel.local → {name}.{slug}.tunnel.local
	DataDir      string        `yaml:"data_dir"`
	AdminEmail   string        `yaml:"admin_email"`
	AdminPassword string       `yaml:"admin_password"`
	AdminAPIKey  string        `yaml:"admin_api_key"`
	TLSCert      string        `yaml:"tls_cert"`
	TLSKey       string        `yaml:"tls_key"`
	AutoTLS      bool          `yaml:"auto_tls"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type AgentTunnel struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"` // tcp | http
	LocalAddr  string `yaml:"local_addr"`
	RemotePort int    `yaml:"remote_port"`
	Domain     string `yaml:"domain"` // optional custom domain
}

type AgentConfig struct {
	ServerAddr string        `yaml:"server_addr"`
	Token      string        `yaml:"token"`
	AgentID    string        `yaml:"agent_id"`
	Tunnels    []AgentTunnel `yaml:"tunnels"`
	Reconnect  time.Duration `yaml:"reconnect"`
}

func LoadServer(path string) (*ServerConfig, error) {
	cfg := &ServerConfig{
		Listen:        ":7700",
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
	return cfg, nil
}

func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{
		ServerAddr: "127.0.0.1:7700",
		Reconnect:  3 * time.Second,
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
