package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/kelvins-io/Intranet-penetration/internal/e2e"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/quic-go/quic-go"
)

// Session wraps either a yamux (TCP) or QUIC multiplexed connection.
type Session struct {
	conn      net.Conn
	mux       *yamux.Session
	quicConn  *quic.Conn
	control   net.Conn
	closed    chan struct{}
	mu        sync.Mutex
	transport string // "tcp" | "quic"
	e2e       bool
}

func (s *Session) SetE2E(v bool) { s.e2e = v }
func (s *Session) E2E() bool     { return s.e2e }

func ServerSession(conn net.Conn) (*Session, error) {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	mux, err := yamux.Server(conn, cfg)
	if err != nil {
		return nil, err
	}
	control, err := mux.Accept()
	if err != nil {
		_ = mux.Close()
		return nil, fmt.Errorf("accept control stream: %w", err)
	}
	return &Session{conn: conn, mux: mux, control: control, transport: "tcp"}, nil
}

func ClientSession(conn net.Conn) (*Session, error) {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	mux, err := yamux.Client(conn, cfg)
	if err != nil {
		return nil, err
	}
	control, err := mux.Open()
	if err != nil {
		_ = mux.Close()
		return nil, fmt.Errorf("open control stream: %w", err)
	}
	return &Session{conn: conn, mux: mux, control: control, transport: "tcp"}, nil
}

func (s *Session) Transport() string {
	if s.transport != "" {
		return s.transport
	}
	if s.quicConn != nil {
		return "quic"
	}
	return "tcp"
}

func (s *Session) Control() net.Conn {
	return s.control
}

func (s *Session) OpenStream() (net.Conn, error) {
	if s.quicConn != nil {
		return s.openQUICStream()
	}
	return s.mux.Open()
}

func (s *Session) AcceptStream() (net.Conn, error) {
	if s.quicConn != nil {
		return s.acceptQUICStream()
	}
	return s.mux.Accept()
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.control != nil {
		_ = s.control.Close()
	}
	if s.mux != nil {
		_ = s.mux.Close()
	}
	if s.quicConn != nil {
		_ = s.quicConn.CloseWithError(0, "bye")
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *Session) IsClosed() bool {
	if s.quicConn != nil {
		select {
		case <-s.quicConn.Context().Done():
			return true
		default:
			return false
		}
	}
	return s.mux.IsClosed()
}

func (s *Session) CloseChan() <-chan struct{} {
	if s.quicConn != nil {
		if s.closed == nil {
			s.closed = make(chan struct{})
		}
		return s.closed
	}
	return s.mux.CloseChan()
}

// HandshakeAsServer reads Hello and writes HelloAck.
func (s *Session) HandshakeAsServer(validate func(protocol.Hello) (*protocol.HelloAck, error)) (*protocol.Hello, *protocol.HelloAck, error) {
	env, err := protocol.ReadJSON(s.control)
	if err != nil {
		return nil, nil, err
	}
	if env.Type != protocol.MsgHello {
		return nil, nil, fmt.Errorf("expected hello, got %s", env.Type)
	}
	var hello protocol.Hello
	if err := protocol.DecodeBody(env, &hello); err != nil {
		return nil, nil, err
	}
	ack, err := validate(hello)
	if err != nil {
		_ = protocol.WriteJSON(s.control, protocol.MsgError, protocol.ErrorBody{
			Code:    "auth_failed",
			Message: err.Error(),
		})
		return &hello, nil, err
	}
	if ack.Transport == "" {
		ack.Transport = s.Transport()
	}
	if err := protocol.WriteJSON(s.control, protocol.MsgHelloAck, ack); err != nil {
		return &hello, nil, err
	}
	return &hello, ack, nil
}

// HandshakeAsClient sends Hello and waits for HelloAck.
func (s *Session) HandshakeAsClient(hello protocol.Hello) (*protocol.HelloAck, error) {
	if err := protocol.WriteJSON(s.control, protocol.MsgHello, hello); err != nil {
		return nil, err
	}
	env, err := protocol.ReadJSON(s.control)
	if err != nil {
		return nil, err
	}
	switch env.Type {
	case protocol.MsgHelloAck:
		var ack protocol.HelloAck
		if err := protocol.DecodeBody(env, &ack); err != nil {
			return nil, err
		}
		return &ack, nil
	case protocol.MsgError:
		var eb protocol.ErrorBody
		_ = protocol.DecodeBody(env, &eb)
		if eb.Message == "" {
			eb.Message = "handshake rejected"
		}
		return nil, fmt.Errorf("%s: %s", eb.Code, eb.Message)
	default:
		return nil, fmt.Errorf("unexpected message %s", env.Type)
	}
}

// OpenDataStream opens a multiplexed stream and writes an OpenRequest header.
// When session E2E is enabled, performs ECDH after OpenAck and returns a sealed conn.
func (s *Session) OpenDataStream(tunnel, meta string) (net.Conn, error) {
	stream, err := s.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteJSON(stream, protocol.MsgOpen, protocol.OpenRequest{
		Tunnel: tunnel,
		Meta:   meta,
		E2E:    s.e2e,
	}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	env, err := protocol.ReadJSON(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if env.Type != protocol.MsgOpenAck {
		_ = stream.Close()
		return nil, fmt.Errorf("expected open_ack, got %s", env.Type)
	}
	var ack protocol.OpenAck
	if err := protocol.DecodeBody(env, &ack); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !ack.OK {
		_ = stream.Close()
		return nil, fmt.Errorf("open rejected: %s", ack.Error)
	}
	if s.e2e && ack.E2E {
		sealed, err := e2e.HandshakeAsClient(stream)
		if err != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("e2e handshake: %w", err)
		}
		return sealed, nil
	}
	return stream, nil
}

// AcceptDataStream accepts a stream and reads OpenRequest.
func (s *Session) AcceptDataStream() (net.Conn, protocol.OpenRequest, error) {
	stream, err := s.AcceptStream()
	if err != nil {
		return nil, protocol.OpenRequest{}, err
	}
	env, err := protocol.ReadJSON(stream)
	if err != nil {
		_ = stream.Close()
		return nil, protocol.OpenRequest{}, err
	}
	if env.Type != protocol.MsgOpen {
		_ = stream.Close()
		return nil, protocol.OpenRequest{}, fmt.Errorf("expected open, got %s", env.Type)
	}
	var req protocol.OpenRequest
	if err := protocol.DecodeBody(env, &req); err != nil {
		_ = stream.Close()
		return nil, protocol.OpenRequest{}, err
	}
	return stream, req, nil
}

func AckOpen(stream net.Conn, ok bool, errMsg string) error {
	return protocol.WriteJSON(stream, protocol.MsgOpenAck, protocol.OpenAck{OK: ok, Error: errMsg})
}

// AckOpenE2E acknowledges open and optionally enables E2E on the ack.
func AckOpenE2E(stream net.Conn, ok bool, errMsg string, useE2E bool) error {
	return protocol.WriteJSON(stream, protocol.MsgOpenAck, protocol.OpenAck{OK: ok, Error: errMsg, E2E: useE2E && ok})
}

// MaybeSealServer completes E2E handshake as responder when requested.
func MaybeSealServer(stream net.Conn, req protocol.OpenRequest, sessionE2E bool) (net.Conn, error) {
	if !(sessionE2E && req.E2E) {
		return stream, nil
	}
	return e2e.HandshakeAsServer(stream)
}

// Proxy bidirectional copy until either side closes.
func Proxy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = closeWrite(b)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c io.Closer) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
