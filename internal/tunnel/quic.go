package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type quicStreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

func wrapStream(s *quic.Stream, local, remote net.Addr) net.Conn {
	return &quicStreamConn{Stream: s, local: local, remote: remote}
}

// ServerQUICSession accepts a QUIC connection and waits for the client control stream.
func ServerQUICSession(conn *quic.Conn) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept control stream: %w", err)
	}
	s := &Session{
		quicConn:  conn,
		control:   wrapStream(stream, conn.LocalAddr(), conn.RemoteAddr()),
		closed:    make(chan struct{}),
		transport: "quic",
	}
	go s.watchQUIC()
	return s, nil
}

// ClientQUICSession dials and opens the control stream first.
func ClientQUICSession(ctx context.Context, addr string, tlsConf *tls.Config) (*Session, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"ip-tunnel"}}
	}
	if len(tlsConf.NextProtos) == 0 {
		tlsConf = tlsConf.Clone()
		tlsConf.NextProtos = []string{"ip-tunnel"}
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open control failed")
		return nil, err
	}
	s := &Session{
		quicConn:  conn,
		control:   wrapStream(stream, conn.LocalAddr(), conn.RemoteAddr()),
		closed:    make(chan struct{}),
		transport: "quic",
	}
	go s.watchQUIC()
	return s, nil
}

func (s *Session) watchQUIC() {
	<-s.quicConn.Context().Done()
	s.mu.Lock()
	if s.closed != nil {
		select {
		case <-s.closed:
		default:
			close(s.closed)
		}
	}
	s.mu.Unlock()
}

func (s *Session) openQUICStream() (net.Conn, error) {
	stream, err := s.quicConn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return wrapStream(stream, s.quicConn.LocalAddr(), s.quicConn.RemoteAddr()), nil
}

func (s *Session) acceptQUICStream() (net.Conn, error) {
	stream, err := s.quicConn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return wrapStream(stream, s.quicConn.LocalAddr(), s.quicConn.RemoteAddr()), nil
}

// ListenQUIC starts a QUIC listener.
func ListenQUIC(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	if tlsConf == nil {
		return nil, fmt.Errorf("tls config required for quic")
	}
	cfg := tlsConf.Clone()
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"ip-tunnel"}
	}
	return quic.ListenAddr(addr, cfg, &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	})
}
