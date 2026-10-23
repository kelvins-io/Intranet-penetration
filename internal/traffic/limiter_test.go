package traffic

import (
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func TestRateLimitRPS(t *testing.T) {
	l := NewLimiter()
	pols := []store.TrafficPolicy{{
		TenantID: "t1", Name: "slow", Enabled: true, Priority: 1,
		Tunnels: []string{"demo"}, Scope: "ip+tunnel", RateRPS: 1, Burst: 1,
	}}
	d1 := l.Allow(pols, "t1", "demo", "1.2.3.4:9")
	if !d1.Allowed {
		t.Fatal("first should allow")
	}
	d1.Release()
	d2 := l.Allow(pols, "t1", "demo", "1.2.3.4:9")
	if d2.Allowed {
		t.Fatal("second should deny within same second")
	}
}

func TestMaxConcurrent(t *testing.T) {
	l := NewLimiter()
	pols := []store.TrafficPolicy{{
		TenantID: "t1", Name: "conc", Enabled: true, Priority: 1,
		Tunnels: []string{"*"}, Scope: "tunnel", MaxConcurrent: 1,
	}}
	d1 := l.Allow(pols, "t1", "a", "10.0.0.1:1")
	if !d1.Allowed {
		t.Fatal("first allow")
	}
	d2 := l.Allow(pols, "t1", "a", "10.0.0.2:1")
	if d2.Allowed {
		t.Fatal("second should hit concurrent")
	}
	d1.Release()
	d3 := l.Allow(pols, "t1", "a", "10.0.0.2:1")
	if !d3.Allowed {
		t.Fatal("after release should allow")
	}
	d3.Release()
}

func TestPriorityWins(t *testing.T) {
	l := NewLimiter()
	pols := []store.TrafficPolicy{
		{TenantID: "t1", Name: "loose", Enabled: true, Priority: 1, Tunnels: []string{"*"}, RateRPS: 100, Burst: 100},
		{TenantID: "t1", Name: "strict", Enabled: true, Priority: 10, Tunnels: []string{"demo"}, RateRPS: 1, Burst: 1},
	}
	_ = l.Allow(pols, "t1", "demo", "1.1.1.1:1")
	d := l.Allow(pols, "t1", "demo", "1.1.1.1:1")
	if d.Allowed || d.Policy != "strict" {
		t.Fatalf("expected strict deny, got %#v", d)
	}
}
