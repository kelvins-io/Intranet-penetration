package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

// Session wraps a yamux session plus the dedicated control stream.
type Session struct {
	conn    net.Conn
	mux     *yamux.Session
	control net.Conn
	mu      sync.Mutex
}

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
	return &Session{conn: conn, mux: mux, control: control}, nil
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
	return &Session{conn: conn, mux: mux, control: control}, nil
}

func (s *Session) Control() net.Conn {
	return s.control
}

func (s *Session) OpenStream() (net.Conn, error) {
	return s.mux.Open()
}

func (s *Session) AcceptStream() (net.Conn, error) {
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
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *Session) IsClosed() bool {
	return s.mux.IsClosed()
}

func (s *Session) CloseChan() <-chan struct{} {
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

// OpenDataStream opens a yamux stream and writes an OpenRequest header.
func (s *Session) OpenDataStream(tunnel, meta string) (net.Conn, error) {
	stream, err := s.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteJSON(stream, protocol.MsgOpen, protocol.OpenRequest{
		Tunnel: tunnel,
		Meta:   meta,
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
