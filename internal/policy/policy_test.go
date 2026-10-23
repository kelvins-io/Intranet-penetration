package policy

import (
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func TestEvaluateAllowAuthenticated(t *testing.T) {
	pols := []store.AccessPolicy{{
		TenantID: "t1", Name: "auth-only", Enabled: true, Priority: 10,
		Effect: "allow", Subjects: []string{"authenticated"}, Tunnels: []string{"demo"}, Actions: []string{"http.access"},
	}}
	d := Evaluate(pols, "t1", "demo", ActionHTTP, "1.2.3.4:123", Identity{Anonymous: true}, false)
	if d.Allowed {
		t.Fatal("anonymous should deny when only authenticated allowed")
	}
	d = Evaluate(pols, "t1", "demo", ActionHTTP, "1.2.3.4:123", Identity{Email: "a@b.c", Role: store.RoleMember}, false)
	if !d.Allowed {
		t.Fatal("authenticated should allow")
	}
}

func TestEvaluateDenyWinsByPriority(t *testing.T) {
	pols := []store.AccessPolicy{
		{TenantID: "t1", Name: "allow-all", Enabled: true, Priority: 1, Effect: "allow", Subjects: []string{"anyone"}, Tunnels: []string{"*"}, Actions: []string{"*"}},
		{TenantID: "t1", Name: "deny-admin", Enabled: true, Priority: 100, Effect: "deny", Subjects: []string{"role:admin"}, Tunnels: []string{"secret"}, Actions: []string{"http.access"}},
	}
	d := Evaluate(pols, "t1", "secret", ActionHTTP, "10.0.0.1:1", Identity{Email: "a@b.c", Role: store.RoleAdmin}, false)
	if d.Allowed || d.Policy != "deny-admin" {
		t.Fatalf("expected deny-admin, got %#v", d)
	}
}

func TestCIDRMatch(t *testing.T) {
	pols := []store.AccessPolicy{{
		TenantID: "t1", Name: "office", Enabled: true, Priority: 1, Effect: "allow",
		Subjects: []string{"anyone"}, Tunnels: []string{"*"}, Actions: []string{"*"},
		SourceCIDRs: []string{"10.0.0.0/8"},
	}}
	if Evaluate(pols, "t1", "x", ActionTCP, "10.1.2.3:9", Identity{Anonymous: true}, false).Allowed != true {
		t.Fatal("cidr should allow")
	}
	if Evaluate(pols, "t1", "x", ActionTCP, "8.8.8.8:9", Identity{Anonymous: true}, false).Allowed {
		t.Fatal("outside cidr should deny")
	}
}
