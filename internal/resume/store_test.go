package resume

import (
	"testing"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

func TestResumeRoundTrip(t *testing.T) {
	s := New(time.Minute)
	tunnels := []protocol.AssignedTunnel{{Name: "demo", Type: protocol.TunnelHTTP, Domain: "demo.local"}}
	tok := s.Issue("ten1", "agent1", tunnels)
	st, ok := s.Lookup(tok)
	if !ok || st.AgentID != "agent1" {
		t.Fatalf("lookup failed %#v", st)
	}
	st2, ok := s.Consume(tok)
	if !ok || len(st2.Tunnels) != 1 {
		t.Fatal("consume failed")
	}
	if _, ok := s.Consume(tok); ok {
		t.Fatal("token should be single-use")
	}
}
