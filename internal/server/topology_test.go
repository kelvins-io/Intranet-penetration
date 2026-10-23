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

func TestControlEdgeTopology(t *testing.T) {
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localLn.Close()
	go http.Serve(localLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "split:%s", r.URL.Path)
	}))

	apiPort := freePort(t)
	agentPort := freePort(t)
	httpPort := freePort(t)
	secret := "test-cluster-secret"

	ctrlDir := t.TempDir()
	edgeDir := t.TempDir()
	ctrlCfg := &config.ServerConfig{
		Role:          config.RoleControl,
		APIListen:     fmt.Sprintf("127.0.0.1:%d", apiPort),
		Token:         "topo-token",
		PublicHost:    "127.0.0.1",
		BaseDomain:    "tunnel.local",
		DataDir:       ctrlDir,
		AdminEmail:    "admin@test",
		AdminPassword: "admin123",
		AdminAPIKey:   "topo-admin-key",
		TCPPortMin:    23000,
		TCPPortMax:    23010,
		AutoTLS:       false,
		Region:        "test",
		Cluster:       config.ClusterConfig{Secret: secret},
	}
	edgeCfg := &config.ServerConfig{
		Role:          config.RoleEdge,
		ControlURL:    fmt.Sprintf("http://127.0.0.1:%d", apiPort),
		Listen:        fmt.Sprintf("127.0.0.1:%d", agentPort),
		HTTPGateway:   fmt.Sprintf("127.0.0.1:%d", httpPort),
		PublicHost:    "127.0.0.1",
		BaseDomain:    "tunnel.local",
		DataDir:       edgeDir,
		EdgeID:        "edge-topo-1",
		Region:        "test",
		TCPPortMin:    23100,
		TCPPortMax:    23110,
		AutoTLS:       false,
		EnableE2E:     false,
		AgentMTLS:     "off",
		Cluster: config.ClusterConfig{
			Secret:        secret,
			AdvertiseHTTP: fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
	}()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	ctrl, err := server.New(ctrlCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ctrl.Run(ctx) }()
	waitHTTP(t, fmt.Sprintf("http://%s/healthz", ctrlCfg.APIListen), 3*time.Second)

	// Control API should serve dashboard/login; Edge gateway should not expose /api without all-mode.
	loginURL := fmt.Sprintf("http://%s/api/v1/auth/login", ctrlCfg.APIListen)
	resp, err := http.Post(loginURL, "application/json",
		strings.NewReader(`{"email":"admin@test","password":"admin123"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("control login %d", resp.StatusCode)
	}

	edge, err := server.New(edgeCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = edge.Run(ctx) }()
	waitHTTP(t, fmt.Sprintf("http://%s/healthz", edgeCfg.HTTPGateway), 3*time.Second)

	go func() {
		_ = agent.New(&config.AgentConfig{
			ServerAddr: edgeCfg.Listen,
			Token:      "topo-token",
			AgentID:    "topo-agent",
			Reconnect:  time.Second,
			PreferQUIC: false,
			PreferE2E:  false,
			Tunnels: []config.AgentTunnel{
				{Name: "demo", Type: "http", LocalAddr: localLn.Addr().String()},
			},
		}, log).Run(ctx)
	}()

	url := fmt.Sprintf("http://%s/default/demo/hello", edgeCfg.HTTPGateway)
	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		r, err := http.Get(url)
		if err == nil && r.StatusCode == 200 {
			b, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			body = string(b)
			break
		}
		if r != nil {
			_ = r.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if body != "split:/hello" {
		t.Fatalf("unexpected body %q", body)
	}

	// Edge public port must not serve control login API in edge-only mode.
	bad, err := http.Get(fmt.Sprintf("http://%s/api/v1/me", edgeCfg.HTTPGateway))
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode == 200 {
		t.Fatal("edge gateway should not expose control API")
	}
}
