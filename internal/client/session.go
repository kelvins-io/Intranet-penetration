package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/tlsutil"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Client struct {
	cfg *config.ClientConfig
	log *slog.Logger

	mu        sync.RWMutex
	sess      *tunnel.Session
	resources []protocol.ClientResource
	ack       *protocol.ClientHelloAck
	ready     chan struct{}
	readyOnce sync.Once
	kicked    atomic.Bool
}

func New(cfg *config.ClientConfig, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{cfg: cfg, log: log, ready: make(chan struct{})}
}

// Ready is closed after the first successful client_hello (resources available).
func (c *Client) Ready() <-chan struct{} { return c.ready }

func (c *Client) SessionReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sess != nil && !c.sess.IsClosed()
}

func (c *Client) LookupByVIP(vip string) (protocol.ClientResource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.resources {
		if r.VIP == vip {
			return r, true
		}
	}
	return protocol.ClientResource{}, false
}

func (c *Client) Ack() *protocol.ClientHelloAck {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ack
}

func (c *Client) Kicked() bool { return c.kicked.Load() }

func (c *Client) signalReady() {
	c.readyOnce.Do(func() { close(c.ready) })
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
		if c.kicked.Load() {
			if c.cfg.ExitOnKick {
				return fmt.Errorf("session kicked: %w", err)
			}
			c.log.Warn("session kicked; waiting before reconnect", "err", err, "after", backoff*5)
			c.kicked.Store(false)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff * 5):
			}
			continue
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

	posture := c.buildPosture()
	ack, err := sess.HandshakeAsUserClient(protocol.ClientHello{
		Version:   protocol.Version,
		Token:     c.cfg.Token,
		DeviceID:  c.cfg.DeviceID,
		Region:    c.cfg.Region,
		ClientVer: posture.AgentVersion,
		Posture:   posture,
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sess = sess
	c.ack = ack
	c.resources = append([]protocol.ClientResource(nil), ack.Resources...)
	c.mu.Unlock()
	c.signalReady()
	c.log.Info("client session ready", "transport", transport, "user", ack.UserEmail,
		"tenant", ack.TenantSlug, "session", ack.SessionID, "resources", len(ack.Resources), "edge", ack.EdgeID)
	for _, r := range ack.Resources {
		c.log.Info("resource", "id", r.ID, "host", r.Hostname, "vip", r.VIP, "type", r.Type, "browser", r.BrowserURL)
	}

	ctrlErr := make(chan error, 1)
	go func() { ctrlErr <- c.watchControl(sess) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sess.CloseChan():
		return fmt.Errorf("session closed")
	case err := <-ctrlErr:
		return err
	}
}

func (c *Client) watchControl(sess *tunnel.Session) error {
	for {
		env, err := sess.ReadControlEnvelope()
		if err != nil {
			return fmt.Errorf("control closed: %w", err)
		}
		switch env.Type {
		case protocol.MsgKick:
			var body protocol.KickBody
			_ = protocol.DecodeBody(env, &body)
			c.kicked.Store(true)
			c.log.Warn("kicked by edge", "session", body.SessionID, "reason", body.Reason)
			_ = sess.Close()
			return fmt.Errorf("kicked: %s", body.Reason)
		case protocol.MsgPing:
			_ = protocol.WriteJSON(sess.Control(), protocol.MsgPong, map[string]string{"ok": "1"})
		case protocol.MsgError:
			var body protocol.ErrorBody
			_ = protocol.DecodeBody(env, &body)
			c.log.Warn("control error", "code", body.Code, "msg", body.Message)
		default:
			c.log.Debug("control message", "type", env.Type)
		}
	}
}

func (c *Client) clientTLS() (*tls.Config, error) {
	m := c.cfg.MTLS
	if !m.Enabled && m.CertFile == "" {
		return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"ip-tunnel"}}, nil
	}
	return tlsutil.ClientMTLSConfig(m.CAFile, m.CertFile, m.KeyFile, m.InsecureSkipVerify || m.CAFile == "")
}

func (c *Client) dial(ctx context.Context) (*tunnel.Session, string, error) {
	var errs []string
	tlsConf, err := c.clientTLS()
	if err != nil {
		return nil, "", err
	}
	if c.cfg.PreferQUIC {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		sess, err := tunnel.ClientQUICSession(qctx, c.cfg.QUICAddr, tlsConf.Clone())
		cancel()
		if err == nil {
			return sess, "quic", nil
		}
		errs = append(errs, "quic: "+err.Error())
		c.log.Warn("quic dial failed", "err", err)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.cfg.ServerAddr)
	if err != nil {
		errs = append(errs, "tcp: "+err.Error())
	} else {
		conn := raw
		if c.cfg.MTLS.Enabled || c.cfg.MTLS.CertFile != "" {
			tlsConn := tls.Client(raw, tlsConf.Clone())
			if herr := tlsConn.HandshakeContext(ctx); herr != nil {
				_ = raw.Close()
				errs = append(errs, "tls: "+herr.Error())
				conn = nil
			} else {
				conn = tlsConn
			}
		}
		if conn != nil {
			sess, err := tunnel.ClientSession(conn)
			if err == nil {
				return sess, "tcp", nil
			}
			_ = conn.Close()
			errs = append(errs, "yamux: "+err.Error())
		}
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
