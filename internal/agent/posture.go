package agent

import (
	"os"
	"runtime"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

const agentVersion = "0.4.0"

func (a *Agent) collectPosture() protocol.DevicePosture {
	host, _ := os.Hostname()
	p := protocol.DevicePosture{
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Hostname:     host,
		AgentVersion: agentVersion,
		DeviceID:     a.cfg.Posture.DeviceID,
		Encrypted:    a.cfg.Posture.Encrypted,
		Firewall:     a.cfg.Posture.Firewall,
		ScreenLock:   a.cfg.Posture.ScreenLock,
		Attrs:        a.cfg.Posture.Attrs,
	}
	if a.cfg.Posture.Version != "" {
		p.AgentVersion = a.cfg.Posture.Version
	}
	if p.DeviceID == "" {
		p.DeviceID = a.cfg.AgentID
	}
	return p
}
