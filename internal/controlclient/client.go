package controlclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

type Client struct {
	base   string
	secret string
	http   *http.Client
}

func New(baseURL, secret string) *Client {
	return &Client{
		base:   strings.TrimRight(baseURL, "/"),
		secret: secret,
		http:   &http.Client{Timeout: 15 * time.Second},
	}
}

type HelloRequest struct {
	Hello      protocol.Hello `json:"hello"`
	PublicHost string         `json:"public_host,omitempty"`
	BaseDomain string         `json:"base_domain,omitempty"`
	EdgeID     string         `json:"edge_id,omitempty"`
}

type HelloResponse struct {
	Ack    protocol.HelloAck `json:"ack"`
	Tenant store.Tenant      `json:"tenant"`
}

type OnlineRequest struct {
	TenantID string                   `json:"tenant_id"`
	AgentID  string                   `json:"agent_id"`
	Remote   string                   `json:"remote,omitempty"`
	Tunnels  []protocol.AssignedTunnel `json:"tunnels"`
	Hints    map[string]string        `json:"hints,omitempty"` // tunnel name -> local hint
}

type OfflineRequest struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
}

type AuditRequest struct {
	TenantID string `json:"tenant_id"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type ResolveResponse struct {
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug,omitempty"`
	TunnelName string `json:"tunnel_name"`
	Domain     string `json:"domain,omitempty"`
}

type IdentityResponse struct {
	Email      string     `json:"email"`
	Role       store.Role `json:"role"`
	UserID     string     `json:"user_id"`
	TenantID   string     `json:"tenant_id,omitempty"`
	TenantSlug string     `json:"tenant_slug,omitempty"`
}

func (c *Client) AgentHello(req HelloRequest) (*HelloResponse, error) {
	var out HelloResponse
	if err := c.doJSON(http.MethodPost, "/internal/v1/agent/hello", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AgentOnline(req OnlineRequest) error {
	return c.doJSON(http.MethodPost, "/internal/v1/agent/online", req, nil)
}

func (c *Client) AgentOffline(req OfflineRequest) error {
	return c.doJSON(http.MethodPost, "/internal/v1/agent/offline", req, nil)
}

func (c *Client) ListPolicies(tenantID string) ([]store.AccessPolicy, error) {
	var out []store.AccessPolicy
	path := "/internal/v1/policies"
	if tenantID != "" {
		path += "?tenant=" + url.QueryEscape(tenantID)
	}
	if err := c.doJSON(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ListTrafficPolicies(tenantID string) ([]store.TrafficPolicy, error) {
	var out []store.TrafficPolicy
	path := "/internal/v1/traffic-policies"
	if tenantID != "" {
		path += "?tenant=" + url.QueryEscape(tenantID)
	}
	if err := c.doJSON(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CAPEM() ([]byte, error) {
	return c.doBytes(http.MethodGet, "/internal/v1/ca")
}

func (c *Client) RevokedSerials() ([]string, error) {
	var out struct {
		Serials []string `json:"serials"`
	}
	if err := c.doJSON(http.MethodGet, "/internal/v1/certs/revoked", nil, &out); err != nil {
		return nil, err
	}
	return out.Serials, nil
}

func (c *Client) ResolveDomain(domain string) (*ResolveResponse, error) {
	var out ResolveResponse
	path := "/internal/v1/resolve?domain=" + url.QueryEscape(domain)
	if err := c.doJSON(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResolveSlug(slug, tunnel string) (*ResolveResponse, error) {
	var out ResolveResponse
	q := url.Values{}
	q.Set("tenant_slug", slug)
	q.Set("tunnel", tunnel)
	if err := c.doJSON(http.MethodGet, "/internal/v1/resolve?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResolveIdentity(apiKey string) (*IdentityResponse, error) {
	var out IdentityResponse
	path := "/internal/v1/identity?api_key=" + url.QueryEscape(apiKey)
	if err := c.doJSON(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Audit(req AuditRequest) error {
	return c.doJSON(http.MethodPost, "/internal/v1/audit", req, nil)
}

func (c *Client) doJSON(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		req.Header.Set("X-Cluster-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var er struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &er)
		if er.Error == "" {
			er.Error = string(data)
		}
		return fmt.Errorf("control %s: %s", resp.Status, er.Error)
	}
	if out == nil || len(data) == 0 || string(data) == "null\n" || string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) doBytes(method, path string) ([]byte, error) {
	req, err := http.NewRequest(method, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("X-Cluster-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("control %s: %s", resp.Status, string(data))
	}
	return data, nil
}
