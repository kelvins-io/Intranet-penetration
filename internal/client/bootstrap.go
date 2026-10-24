package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (c *Client) maybeBootstrap(ctx context.Context) error {
	if c.cfg.ControlAPI == "" {
		return nil
	}
	url := strings.TrimRight(c.cfg.ControlAPI, "/") + "/api/v1/client/bootstrap"
	if c.cfg.Region != "" {
		url += "?prefer=" + c.cfg.Region
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.log.Warn("bootstrap failed", "err", err)
		return nil // non-fatal
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.log.Warn("bootstrap status", "status", resp.StatusCode)
		return nil
	}
	var body struct {
		WSURL string `json:"ws_url"`
		Edge  struct {
			AdvertiseHTTP string `json:"advertise_http"`
			WSURL         string `json:"ws_url"`
			AgentListen   string `json:"agent_listen"`
			QUICListen    string `json:"quic_listen"`
			Region        string `json:"region"`
		} `json:"edge"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("bootstrap decode: %w", err)
	}
	host := hostFromHTTP(body.Edge.AdvertiseHTTP)
	if host != "" && body.Edge.AgentListen != "" {
		port := portOnly(body.Edge.AgentListen)
		if port != "" {
			c.cfg.ServerAddr = host + ":" + port
		}
	}
	if host != "" && body.Edge.QUICListen != "" {
		port := portOnly(body.Edge.QUICListen)
		if port != "" {
			c.cfg.QUICAddr = host + ":" + port
		}
	}
	if body.WSURL != "" {
		c.cfg.WSAddr = body.WSURL
	} else if body.Edge.WSURL != "" {
		c.cfg.WSAddr = body.Edge.WSURL
	}
	if body.Edge.Region != "" {
		c.cfg.Region = body.Edge.Region
	}
	c.log.Info("bootstrapped", "server", c.cfg.ServerAddr, "quic", c.cfg.QUICAddr, "ws", c.cfg.WSAddr)
	return nil
}

func hostFromHTTP(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimRight(u, "/")
	if i := strings.IndexByte(u, ':'); i > 0 {
		return u[:i]
	}
	if i := strings.IndexByte(u, '/'); i > 0 {
		return u[:i]
	}
	return u
}

func portOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return addr[i+1:]
	}
	return ""
}
