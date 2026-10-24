package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Client struct {
	cfg *config.ClientConfig
	log *slog.Logger

	mu        sync.RWMutex
	sess      *tunnel.Session
	resources []protocol.ClientResource
	ack       *protocol.ClientHelloAck
}

func New(cfg *config.ClientConfig, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{cfg: cfg, log: log}
}

func (c *Client) Resources() []protocol.ClientResource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]protocol.ClientResource, len(c.resources))
	copy(out, c.resources)
	return out
}

func (c *Client) Run(ctx context.Context) error {
	backoff := c.cfg.Reconnect
	if backoff <= 0 {
		backoff = 3 * time.Second
	}
	for {
		err := c.connectOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.log.Warn("client disconnected", "err", err, "after", backoff)
		c.mu.Lock()
		c.sess = nil
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

func (c *Client) connectOnce(ctx context.Context) error {
	_ = c.maybeBootstrap(ctx)
	sess, transport, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()

	ack, err := sess.HandshakeAsUserClient(protocol.ClientHello{
		Version:   protocol.Version,
		Token:     c.cfg.Token,
		DeviceID:  c.cfg.DeviceID,
		Region:    c.cfg.Region,
		ClientVer: "0.5.0",
		Posture: protocol.DevicePosture{
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			DeviceID:     c.cfg.DeviceID,
			AgentVersion: "0.5.0",
		},
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sess = sess
	c.ack = ack
	c.resources = append([]protocol.ClientResource(nil), ack.Resources...)
	c.mu.Unlock()
	c.log.Info("client session ready", "transport", transport, "user", ack.UserEmail,
		"tenant", ack.TenantSlug, "resources", len(ack.Resources), "edge", ack.EdgeID)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sess.CloseChan():
		return fmt.Errorf("session closed")
	}
}

func (c *Client) dial(ctx context.Context) (*tunnel.Session, string, error) {
	var errs []string
	if c.cfg.PreferQUIC {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		qTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"ip-tunnel"}}
		sess, err := tunnel.ClientQUICSession(qctx, c.cfg.QUICAddr, qTLS)
		cancel()
		if err == nil {
			return sess, "quic", nil
		}
		errs = append(errs, "quic: "+err.Error())
		c.log.Warn("quic dial failed", "err", err)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.cfg.ServerAddr)
	if err == nil {
		sess, err := tunnel.ClientSession(raw)
		if err == nil {
			return sess, "tcp", nil
		}
		_ = raw.Close()
		errs = append(errs, "yamux: "+err.Error())
	} else {
		errs = append(errs, "tcp: "+err.Error())
	}
	if c.cfg.WSAddr != "" && c.cfg.PreferWS {
		sess, err := tunnel.ClientWSSession(ctx, c.cfg.WSAddr, nil)
		if err == nil {
			return sess, "websocket", nil
		}
		errs = append(errs, "ws: "+err.Error())
	}
	return nil, "", fmt.Errorf("dial failed: %s", strings.Join(errs, "; "))
}

// DialResource opens a stream to Edge for the given resource/host.
func (c *Client) DialResource(ctx context.Context, host string, port int) (net.Conn, error) {
	c.mu.RLock()
	sess := c.sess
	resources := c.resources
	c.mu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return nil, fmt.Errorf("not connected")
	}
	req := protocol.DialRequest{Host: host, Port: port, Mode: protocol.TunnelTCP}
	for _, r := range resources {
		h := strings.ToLower(host)
		if strings.EqualFold(r.Hostname, h) || strings.EqualFold(r.Name, h) || r.VIP == h {
			req.ResourceID = r.ID
			if r.Type == protocol.TunnelUDP {
				req.Mode = protocol.TunnelUDP
			}
			break
		}
	}
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteJSON(stream, protocol.MsgDial, req); err != nil {
		_ = stream.Close()
		return nil, err
	}
	env, err := protocol.ReadJSON(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if env.Type != protocol.MsgDialAck {
		_ = stream.Close()
		return nil, fmt.Errorf("expected dial_ack, got %s", env.Type)
	}
	var ack protocol.DialAck
	if err := protocol.DecodeBody(env, &ack); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !ack.OK {
		_ = stream.Close()
		return nil, fmt.Errorf("dial rejected: %s", ack.Error)
	}
	return stream, nil
}
