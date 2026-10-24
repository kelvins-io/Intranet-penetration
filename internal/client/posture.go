package client

import (
	"os"
	"runtime"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

func (c *Client) buildPosture() protocol.DevicePosture {
	host, _ := os.Hostname()
	p := protocol.DevicePosture{
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Hostname:     host,
		DeviceID:     c.cfg.DeviceID,
		AgentVersion: "0.6.0",
	}
	if c.cfg.Posture.DeviceID != "" {
		p.DeviceID = c.cfg.Posture.DeviceID
	}
	if c.cfg.Posture.Version != "" {
		p.AgentVersion = c.cfg.Posture.Version
	}
	p.Encrypted = c.cfg.Posture.Encrypted
	p.Firewall = c.cfg.Posture.Firewall
	p.ScreenLock = c.cfg.Posture.ScreenLock
	if len(c.cfg.Posture.Attrs) > 0 {
		p.Attrs = c.cfg.Posture.Attrs
	}
	return p
}
