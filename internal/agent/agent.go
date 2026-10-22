package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Agent struct {
	cfg *config.AgentConfig
	log *slog.Logger
}

func New(cfg *config.AgentConfig, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.Default()
	}
	return &Agent{cfg: cfg, log: log}
}

func (a *Agent) Run(ctx context.Context) error {
	backoff := a.cfg.Reconnect
	if backoff <= 0 {
		backoff = 3 * time.Second
	}
	for {
		err := a.connectOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.log.Warn("disconnected, reconnecting", "err", err, "after", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

func (a *Agent) connectOnce(ctx context.Context) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", a.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	defer conn.Close()

	sess, err := tunnel.ClientSession(conn)
	if err != nil {
		return err
	}
	defer sess.Close()

	hello := protocol.Hello{
		Version: protocol.Version,
		Token:   a.cfg.Token,
		AgentID: a.cfg.AgentID,
	}
	for _, t := range a.cfg.Tunnels {
		hello.Tunnels = append(hello.Tunnels, protocol.TunnelSpec{
			Name:       t.Name,
			Type:       protocol.TunnelType(t.Type),
			LocalAddr:  t.LocalAddr,
			RemotePort: t.RemotePort,
			Domain:     t.Domain,
		})
	}

	ack, err := sess.HandshakeAsClient(hello)
	if err != nil {
		return err
	}
	for _, t := range ack.Tunnels {
		a.log.Info("tunnel assigned", "name", t.Name, "type", t.Type, "public", t.PublicAddr)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- a.serveStreams(ctx, sess)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sess.CloseChan():
		return fmt.Errorf("session closed")
	case err := <-errCh:
		return err
	}
}

func (a *Agent) serveStreams(ctx context.Context, sess *tunnel.Session) error {
	for {
		stream, req, err := sess.AcceptDataStream()
		if err != nil {
			return err
		}
		go a.handleStream(ctx, stream, req)
	}
}

func (a *Agent) handleStream(ctx context.Context, stream net.Conn, req protocol.OpenRequest) {
	localAddr := a.localAddrFor(req.Tunnel)
	if localAddr == "" {
		_ = tunnel.AckOpen(stream, false, "unknown tunnel")
		_ = stream.Close()
		return
	}

	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", localAddr)
	if err != nil {
		_ = tunnel.AckOpen(stream, false, err.Error())
		_ = stream.Close()
		a.log.Warn("dial local failed", "tunnel", req.Tunnel, "local", localAddr, "err", err)
		return
	}
	if err := tunnel.AckOpen(stream, true, ""); err != nil {
		_ = upstream.Close()
		_ = stream.Close()
		return
	}
	a.log.Info("stream opened", "tunnel", req.Tunnel, "meta", req.Meta, "local", localAddr)
	tunnel.Proxy(stream, upstream)
}

func (a *Agent) localAddrFor(name string) string {
	for _, t := range a.cfg.Tunnels {
		if t.Name == name {
			return t.LocalAddr
		}
	}
	return ""
}
