package config

import (
	"fmt"
	"os"
	"time"
)

type ClientConfig struct {
	// ControlAPI is used for bootstrap/resources (e.g. http://127.0.0.1:8088).
	ControlAPI string `yaml:"control_api"`
	// ServerAddr is Edge agent/client mux (TCP), e.g. 127.0.0.1:7700.
	ServerAddr string `yaml:"server_addr"`
	QUICAddr   string `yaml:"quic_addr"`
	WSAddr     string `yaml:"ws_addr"`
	PreferQUIC bool   `yaml:"prefer_quic"`
	PreferWS   bool   `yaml:"prefer_ws_fallback"`

	Token    string `yaml:"token"` // user API key
	Region   string `yaml:"region"`
	DeviceID string `yaml:"device_id"`

	SOCKSListen string `yaml:"socks_listen"` // default 127.0.0.1:1080
	Mode        string `yaml:"mode"`         // socks | tun | both — P0: socks

	SystemProxy bool          `yaml:"system_proxy"` // set OS proxy to SOCKS
	Reconnect   time.Duration `yaml:"reconnect"`
}

func LoadClient(path string) (*ClientConfig, error) {
	cfg := &ClientConfig{
		ControlAPI:  "http://127.0.0.1:8088",
		ServerAddr:  "127.0.0.1:7700",
		PreferQUIC:  true,
		PreferWS:    true,
		SOCKSListen: "127.0.0.1:1080",
		Mode:        "socks",
		Reconnect:   3 * time.Second,
		Region:      "local",
	}
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv("IP_CLIENT_TOKEN")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("client token (user API key) is required (yaml token or IP_CLIENT_TOKEN)")
	}
	if cfg.DeviceID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "client"
		}
		cfg.DeviceID = host
	}
	if cfg.QUICAddr == "" {
		cfg.QUICAddr = cfg.ServerAddr
	}
	if cfg.WSAddr == "" && cfg.PreferWS {
		cfg.WSAddr = "ws://127.0.0.1:8088/agent/ws"
	}
	if cfg.SOCKSListen == "" {
		cfg.SOCKSListen = "127.0.0.1:1080"
	}
	switch cfg.Mode {
	case "", "socks", "tun", "both":
		if cfg.Mode == "" {
			cfg.Mode = "socks"
		}
	default:
		return nil, fmt.Errorf("mode must be socks|tun|both")
	}
	return cfg, nil
}
