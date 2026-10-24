package server

import (
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/cluster"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/policy"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func TestResolveClientDial(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{BaseDomain: "tunnel.local"}}
	resources := []protocol.ClientResource{
		{ID: "t1/demo", Name: "demo", Type: protocol.TunnelTCP, Hostname: "demo.default.tunnel.local"},
	}
	r, err := s.resolveClientDial(resources, protocol.DialRequest{Host: "demo.default.tunnel.local", Port: 80})
	if err != nil || r.Name != "demo" {
		t.Fatalf("got %#v err=%v", r, err)
	}
	r, err = s.resolveClientDial(resources, protocol.DialRequest{ResourceID: "t1/demo"})
	if err != nil || r.ID != "t1/demo" {
		t.Fatalf("by id %#v err=%v", r, err)
	}
}

func TestProjectClientResourcesAllowAuthenticated(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Bootstrap("admin@localhost", "admin123", "test-key", "dev-token"); err != nil {
		t.Fatal(err)
	}
	ten := st.ListTenants()[0]
	_, err = st.CreatePolicy(store.AccessPolicy{
		TenantID: ten.ID, Name: "staff", Enabled: true, Priority: 10,
		Effect: "allow", Subjects: []string{"authenticated"}, Tunnels: []string{"*"}, Actions: []string{"*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg: &config.ServerConfig{
			BaseDomain: "tunnel.local", AccessDefaultDeny: true,
			Cluster: config.ClusterConfig{AdvertiseHTTP: "http://127.0.0.1:8088"},
		},
		store:    st,
		registry: NewRegistry(),
		cluster:  cluster.NewMemory(),
	}
	_ = s.registry.Register(&Route{
		TenantID: ten.ID, TenantSlug: ten.Slug, TunnelName: "demo", Type: protocol.TunnelHTTP, AgentID: "a",
	})
	anon := policy.Identity{Anonymous: true}
	if res := s.projectClientResources(&ten, anon); len(res) != 0 {
		t.Fatalf("anon should see none, got %#v", res)
	}
	user := policy.Identity{Email: "admin@localhost", Role: store.RoleAdmin, UserID: "u"}
	res := s.projectClientResources(&ten, user)
	if len(res) != 1 || res[0].BrowserURL == "" {
		t.Fatalf("expected http resource with browser url, got %#v", res)
	}
}
