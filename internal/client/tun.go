package client

import (
	"context"
	"sync"
)

// TunEngine is the virtual NIC interface (P1).
type TunEngine interface {
	Start(ctx context.Context) error
	Stop() error
}

type baseTun struct {
	c      *Client
	dns    *DNSEngine
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (t *baseTun) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	if t.dns != nil {
		return t.dns.Cleanup()
	}
	return nil
}

func (c *Client) waitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.Ready():
		return nil
	}
}
