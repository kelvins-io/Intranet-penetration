package client

import (
	"net"
	"testing"
)

func TestAssignVIPStableAndInCGNAT(t *testing.T) {
	a := AssignVIP("tenant/demo")
	b := AssignVIP("tenant/demo")
	if a != b {
		t.Fatalf("not stable: %s vs %s", a, b)
	}
	ip := net.ParseIP(a).To4()
	if ip == nil {
		t.Fatalf("not ipv4: %s", a)
	}
	n := parseVIPNet(defaultVIPNet)
	if !n.Contains(ip) {
		t.Fatalf("%s not in %s", a, defaultVIPNet)
	}
	if ip[3] < 2 {
		t.Fatalf("reserved low octet: %s", a)
	}
	if AssignVIP("other") == a {
		t.Fatal("different ids should hash differently (collision unlikely)")
	}
}

func TestAssignVIPMatchesServerAlgo(t *testing.T) {
	// Mirror of server.assignResourceVIP — keep in sync.
	want := func(resourceID string) string {
		var h uint32 = 2166136261
		for i := 0; i < len(resourceID); i++ {
			h ^= uint32(resourceID[i])
			h *= 16777619
		}
		v := h & 0x3fffff
		base := uint32(100)<<24 | uint32(64)<<16
		addr := base + v
		if addr&0xff < 2 {
			addr += 2
		}
		return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).String()
	}
	for _, id := range []string{"a", "default/http", "t1/db:5432"} {
		if got := AssignVIP(id); got != want(id) {
			t.Fatalf("id=%s got=%s want=%s", id, got, want(id))
		}
	}
}
