//go:build !darwin && !linux

package client

import "fmt"

// SystemProxy is a no-op stub on unsupported platforms.
type SystemProxy struct {
	socks string
}

func NewSystemProxy(socksAddr string) *SystemProxy {
	return &SystemProxy{socks: socksAddr}
}

func (p *SystemProxy) Enable() error {
	return fmt.Errorf("system proxy not supported on this OS; point apps at socks5://%s manually", p.socks)
}

func (p *SystemProxy) Disable() error { return nil }
