package resume

import (
	"testing"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

func TestMemoryBackendRoundTrip(t *testing.T) {
	var b Backend = New(time.Minute)
	tok := b.Issue("t1", "a1", []protocol.AssignedTunnel{{Name: "demo", Type: protocol.TunnelTCP, RemotePort: 20001}})
	st, ok := b.Lookup(tok)
	if !ok || st.AgentID != "a1" {
		t.Fatalf("lookup %#v", st)
	}
	_ = b.SoftHold("t1", "a1", st.Tunnels)
	got, ok := b.Consume(tok)
	if !ok || got.Tunnels[0].RemotePort != 20001 {
		t.Fatalf("consume %#v", got)
	}
	if _, ok := b.Lookup(tok); ok {
		t.Fatal("expected consumed")
	}
}
