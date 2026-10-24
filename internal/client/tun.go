package client

import "context"

// TunEngine is the P1 virtual NIC interface. P0 returns unsupported.
type TunEngine interface {
	Start(ctx context.Context) error
	Stop() error
}

// NewTunEngine returns a platform TUN engine when mode includes tun.
func NewTunEngine(c *Client) TunEngine {
	return &stubTun{c: c}
}

type stubTun struct{ c *Client }

func (t *stubTun) Start(ctx context.Context) error {
	t.c.log.Warn("TUN mode not implemented in P0; use socks (system proxy). Planned for P1 with VIP/DNS.")
	<-ctx.Done()
	return ctx.Err()
}

func (t *stubTun) Stop() error { return nil }
