package server_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/agent"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/server"
)

func TestHTTPTunnelE2E(t *testing.T) {
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localLn.Close()
	localAddr := localLn.Addr().String()

	go http.Serve(localLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "ok:%s", r.URL.Path)
	}))

	agentPort := freePort(t)
	httpPort := freePort(t)

	srvCfg := &config.ServerConfig{
		Listen:        fmt.Sprintf("127.0.0.1:%d", agentPort),
		HTTPGateway:   fmt.Sprintf("127.0.0.1:%d", httpPort),
		Token:         "test-token",
		PublicHost:    "127.0.0.1",
		BaseDomain:    "tunnel.local",
		DataDir:       "", // in-memory store for tests
		AdminEmail:    "admin@test",
		AdminPassword: "admin123",
		AdminAPIKey:   "test-admin-key",
		TCPPortMin:    21000,
		TCPPortMax:    21010,
		AutoTLS:       false,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
	}()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := server.New(srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()

	waitHTTP(t, fmt.Sprintf("http://%s/healthz", srvCfg.HTTPGateway), 2*time.Second)

	agentCfg := &config.AgentConfig{
		ServerAddr: srvCfg.Listen,
		Token:      "test-token",
		AgentID:    "test-agent",
		Reconnect:  time.Second,
		Tunnels: []config.AgentTunnel{
			{Name: "demo", Type: "http", LocalAddr: localAddr},
		},
	}
	go func() { _ = agent.New(agentCfg, log).Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	var body string
	url := fmt.Sprintf("http://%s/default/demo/hello", srvCfg.HTTPGateway)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body = string(b)
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if body != "ok:/hello" {
		t.Fatalf("unexpected body %q", body)
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/api/v1/stats", srvCfg.HTTPGateway), nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyStats, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("stats status %d %s", resp.StatusCode, bodyStats)
	}

	dash, err := http.Get(fmt.Sprintf("http://%s/dashboard/", srvCfg.HTTPGateway))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(dash.Body)
	_ = dash.Body.Close()
	if dash.StatusCode != 200 {
		t.Fatalf("dashboard status %d", dash.StatusCode)
	}
}

func TestLoginAPI(t *testing.T) {
	agentPort := freePort(t)
	httpPort := freePort(t)
	srvCfg := &config.ServerConfig{
		Listen:        fmt.Sprintf("127.0.0.1:%d", agentPort),
		HTTPGateway:   fmt.Sprintf("127.0.0.1:%d", httpPort),
		Token:         "tok",
		PublicHost:    "127.0.0.1",
		BaseDomain:    "tunnel.local",
		DataDir:       "",
		AdminEmail:    "admin@test",
		AdminPassword: "secret",
		AdminAPIKey:   "key1",
		TCPPortMin:    22000,
		TCPPortMax:    22010,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
	}()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := server.New(srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitHTTP(t, fmt.Sprintf("http://%s/healthz", srvCfg.HTTPGateway), 2*time.Second)

	resp, err := http.Post(
		fmt.Sprintf("http://%s/api/v1/auth/login", srvCfg.HTTPGateway),
		"application/json",
		strings.NewReader(`{"email":"admin@test","password":"secret"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login %d %s", resp.StatusCode, b)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", url)
}
