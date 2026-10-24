//go:build !darwin && !linux && !windows

package client

import (
	"context"
	"fmt"
	"runtime"
)

type stubTun struct{ baseTun }

// NewTunEngine returns a no-op stub on unsupported platforms.
func NewTunEngine(c *Client) TunEngine {
	return &stubTun{baseTun: baseTun{c: c}}
}

func (t *stubTun) Start(ctx context.Context) error {
	t.c.log.Warn("tun not supported on this OS", "os", runtime.GOOS)
	<-ctx.Done()
	return fmt.Errorf("tun unsupported on %s", runtime.GOOS)
}
