package posture

import (
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func TestEvaluateRequireOSAndVersion(t *testing.T) {
	pols := []store.PosturePolicy{{
		TenantID: "t1", Name: "corp", Enabled: true, Priority: 1,
		RequireOS: []string{"linux", "darwin"}, MinAgentVersion: "1.2.0",
	}}
	enc := true
	d := Evaluate(pols, "t1", protocol.DevicePosture{OS: "windows", AgentVersion: "2.0.0", Encrypted: &enc})
	if d.Allowed {
		t.Fatal("windows should deny")
	}
	d = Evaluate(pols, "t1", protocol.DevicePosture{OS: "linux", AgentVersion: "1.1.9"})
	if d.Allowed {
		t.Fatal("old version should deny")
	}
	d = Evaluate(pols, "t1", protocol.DevicePosture{OS: "linux", AgentVersion: "1.2.0"})
	if !d.Allowed {
		t.Fatal("should allow")
	}
}

func TestRequireEncrypted(t *testing.T) {
	pols := []store.PosturePolicy{{
		TenantID: "t1", Name: "enc", Enabled: true, Priority: 1, RequireEncrypted: true,
	}}
	d := Evaluate(pols, "t1", protocol.DevicePosture{})
	if d.Allowed {
		t.Fatal("missing encrypted should deny")
	}
	yes := true
	d = Evaluate(pols, "t1", protocol.DevicePosture{Encrypted: &yes})
	if !d.Allowed {
		t.Fatal("encrypted should allow")
	}
}
