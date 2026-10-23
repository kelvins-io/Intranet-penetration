package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/tlsutil"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type Agent struct {
	cfg         *config.AgentConfig
	log         *slog.Logger
	resumeToken string
	tlsConf     *tls.Config
}

func New(cfg *config.AgentConfig, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.Default()
	}
	a := &Agent{cfg: cfg, log: log}
	a.resumeToken = a.loadResumeToken()
	if cfg.MTLS.Enabled {
		tc, err := tlsutil.ClientMTLSConfig(
			cfg.MTLS.CAFile,
			cfg.MTLS.CertFile,
			cfg.MTLS.KeyFile,
			cfg.MTLS.InsecureSkipVerify,
		)
		if err != nil {
			log.Error("load mtls config", "err", err)
		} else {
			a.tlsConf = tc
		}
	} else if cfg.MTLS.CAFile != "" {
		// TLS to server without client certificate (agent_mtls=optional).
		tc, err := tlsutil.ClientMTLSConfig(cfg.MTLS.CAFile, "", "", cfg.MTLS.InsecureSkipVerify)
		if err != nil {
			log.Error("load tls config", "err", err)
		} else {
			a.tlsConf = tc
		}
	}
	return a
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
	a.maybeDiscover(ctx)
	sess, transport, err := a.dial(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	a.log.Info("connected", "transport", transport, "mtls", a.tlsConf != nil)

	hello := protocol.Hello{
		Version:     protocol.Version,
		Token:       a.cfg.Token,
		AgentID:     a.cfg.AgentID,
		ResumeToken: a.resumeToken,
		PreferE2E:   a.cfg.PreferE2E,
		Region:      a.cfg.Region,
		Posture:     a.collectPosture(),
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
	sess.SetE2E(ack.E2E)
	if ack.ResumeToken != "" {
		a.resumeToken = ack.ResumeToken
		_ = a.saveResumeToken(ack.ResumeToken)
	}
	a.log.Info("session ready", "e2e", ack.E2E, "region", ack.Region, "edge", ack.EdgeID)
	for _, t := range ack.Tunnels {
		a.log.Info("tunnel assigned",
			"name", t.Name,
			"type", t.Type,
			"public", t.PublicAddr,
			"resumed", ack.Resumed,
			"edge", ack.EdgeID,
		)
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

func (a *Agent) dial(ctx context.Context) (*tunnel.Session, string, error) {
	var errs []string

	if a.cfg.PreferQUIC {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		qTLS := a.tlsConf
		if qTLS == nil {
			qTLS = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"ip-tunnel"}}
		}
		sess, err := tunnel.ClientQUICSession(qctx, a.cfg.QUICAddr, qTLS)
		cancel()
		if err == nil {
			return sess, "quic", nil
		}
		errs = append(errs, "quic: "+err.Error())
		a.log.Warn("quic dial failed, fallback tcp", "err", err)
	}

	if sess, name, err := a.dialTCP(ctx); err == nil {
		return sess, name, nil
	} else if err != nil {
		errs = append(errs, err.Error())
		a.log.Warn("tcp dial failed", "err", err)
	}

	if a.cfg.WSAddr != "" && a.cfg.PreferWSFallback {
		a.log.Info("trying websocket fallback", "addr", a.cfg.WSAddr)
		sess, err := tunnel.ClientWSSession(ctx, a.cfg.WSAddr, nil)
		if err == nil {
			return sess, "websocket", nil
		}
		errs = append(errs, "ws: "+err.Error())
		a.log.Warn("websocket dial failed", "err", err)
	}

	if len(errs) == 0 {
		return nil, "", fmt.Errorf("no transport available")
	}
	return nil, "", fmt.Errorf("all transports failed: %s", strings.Join(errs, "; "))
}

func (a *Agent) dialTCP(ctx context.Context) (*tunnel.Session, string, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", a.cfg.ServerAddr)
	if err != nil {
		return nil, "", fmt.Errorf("tcp: %w", err)
	}
	var conn net.Conn = raw
	name := "tcp"
	if a.tlsConf != nil {
		tc := tls.Client(raw, a.tlsConf)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, "", fmt.Errorf("tls: %w", err)
		}
		conn = tc
		name = "tcp+tls"
	}
	sess, err := tunnel.ClientSession(conn)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("yamux: %w", err)
	}
	return sess, name, nil
}

func (a *Agent) maybeDiscover(ctx context.Context) {
	if a.cfg.DiscoverURL == "" {
		return
	}
	url := a.cfg.DiscoverURL
	if a.cfg.Region != "" && !strings.Contains(url, "prefer=") {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url = url + sep + "prefer=" + a.cfg.Region
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.log.Warn("region discover failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.log.Warn("region discover bad status", "status", resp.StatusCode)
		return
	}
	var rec struct {
		Region        string `json:"region"`
		EdgeID        string `json:"edge_id"`
		AdvertiseHTTP string `json:"advertise_http"`
		AgentListen   string `json:"agent_listen"`
		QUICListen    string `json:"quic_listen"`
		WSURL         string `json:"ws_url"`
		Reason        string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		a.log.Warn("region discover decode", "err", err)
		return
	}
	host := hostFromAdvertise(rec.AdvertiseHTTP)
	if host != "" && rec.AgentListen != "" {
		_, port, _ := net.SplitHostPort(normalizeDial(rec.AgentListen))
		if port != "" {
			a.cfg.ServerAddr = net.JoinHostPort(host, port)
		}
	}
	if host != "" && rec.QUICListen != "" {
		_, port, _ := net.SplitHostPort(normalizeDial(rec.QUICListen))
		if port != "" {
			a.cfg.QUICAddr = net.JoinHostPort(host, port)
		}
	}
	if rec.WSURL != "" {
		a.cfg.WSAddr = rec.WSURL
	}
	if rec.Region != "" {
		a.cfg.Region = rec.Region
	}
	a.log.Info("region scheduled", "edge", rec.EdgeID, "region", rec.Region, "reason", rec.Reason,
		"server", a.cfg.ServerAddr, "quic", a.cfg.QUICAddr, "ws", a.cfg.WSAddr)
}

func hostFromAdvertise(advertise string) string {
	advertise = strings.TrimSpace(advertise)
	advertise = strings.TrimPrefix(advertise, "https://")
	advertise = strings.TrimPrefix(advertise, "http://")
	advertise = strings.TrimRight(advertise, "/")
	if advertise == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(advertise)
	if err == nil {
		return host
	}
	return advertise
}

func normalizeDial(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
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

	mode := req.Mode
	if mode == "" {
		mode = a.tunnelMode(req.Tunnel)
	}
	useE2E := req.E2E && a.cfg.PreferE2E

	if mode == protocol.TunnelUDP {
		if err := tunnel.AckOpenE2E(stream, true, "", useE2E); err != nil {
			_ = stream.Close()
			return
		}
		if useE2E {
			sealed, err := tunnel.MaybeSealServer(stream, req, true)
			if err != nil {
				_ = stream.Close()
				a.log.Warn("e2e handshake failed", "err", err)
				return
			}
			stream = sealed
		}
		a.log.Info("udp stream opened", "tunnel", req.Tunnel, "meta", req.Meta, "local", localAddr, "e2e", useE2E)
		if err := tunnel.ProxyUDPAgent(stream, localAddr, 60*time.Second); err != nil {
			a.log.Debug("udp proxy ended", "err", err)
		}
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
	if err := tunnel.AckOpenE2E(stream, true, "", useE2E); err != nil {
		_ = upstream.Close()
		_ = stream.Close()
		return
	}
	if useE2E {
		sealed, err := tunnel.MaybeSealServer(stream, req, true)
		if err != nil {
			_ = upstream.Close()
			_ = stream.Close()
			a.log.Warn("e2e handshake failed", "err", err)
			return
		}
		stream = sealed
	}
	a.log.Info("stream opened", "tunnel", req.Tunnel, "meta", req.Meta, "local", localAddr, "e2e", useE2E)
	tunnel.Proxy(stream, upstream)
}

func (a *Agent) tunnelMode(name string) protocol.TunnelType {
	for _, t := range a.cfg.Tunnels {
		if t.Name == name {
			return protocol.TunnelType(t.Type)
		}
	}
	return protocol.TunnelTCP
}

func (a *Agent) localAddrFor(name string) string {
	for _, t := range a.cfg.Tunnels {
		if t.Name == name {
			return t.LocalAddr
		}
	}
	return ""
}

func (a *Agent) loadResumeToken() string {
	path := a.cfg.ResumeTokenFile
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (a *Agent) saveResumeToken(tok string) error {
	path := a.cfg.ResumeTokenFile
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(tok), 0o600)
}
