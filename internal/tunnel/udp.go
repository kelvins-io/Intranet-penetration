package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/e2e"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

const maxUDPDatagram = 64 << 10

// OpenUDPStream opens a multiplexed stream for UDP tunnel relay.
func (s *Session) OpenUDPStream(tunnel, meta string) (net.Conn, error) {
	stream, err := s.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteJSON(stream, protocol.MsgOpen, protocol.OpenRequest{
		Tunnel: tunnel,
		Meta:   meta,
		Mode:   protocol.TunnelUDP,
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

// WriteUDPFrame writes one length-prefixed datagram.
func WriteUDPFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxUDPDatagram {
		return fmt.Errorf("udp datagram too large: %d", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadUDPFrame reads one length-prefixed datagram.
func ReadUDPFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return []byte{}, nil
	}
	if n > maxUDPDatagram {
		return nil, fmt.Errorf("udp datagram too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ProxyUDPEdge relays packets for one public client address over a framed stream.
// First datagram is written by the caller before invoking this helper.
func ProxyUDPEdge(stream net.Conn, pc *net.UDPConn, clientAddr *net.UDPAddr, first []byte, idle time.Duration) {
	if idle <= 0 {
		idle = 60 * time.Second
	}
	var once sync.Once
	closeAll := func() { once.Do(func() { _ = stream.Close() }) }
	defer closeAll()

	if len(first) > 0 {
		if err := WriteUDPFrame(stream, first); err != nil {
			return
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxUDPDatagram)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(idle))
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if addr.String() != clientAddr.String() {
				// Hand off: cannot easily re-queue; drop other clients' packets here.
				// New associations are created by the accept loop separately.
				continue
			}
			if err := WriteUDPFrame(stream, buf[:n]); err != nil {
				return
			}
		}
	}()

	for {
		_ = stream.SetReadDeadline(time.Now().Add(idle))
		payload, err := ReadUDPFrame(stream)
		if err != nil {
			break
		}
		if _, err := pc.WriteToUDP(payload, clientAddr); err != nil {
			break
		}
	}
	<-done
}

// ProxyUDPAgent relays framed stream datagrams to a local UDP service.
func ProxyUDPAgent(stream net.Conn, localAddr string, idle time.Duration) error {
	if idle <= 0 {
		idle = 60 * time.Second
	}
	raddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxUDPDatagram)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idle))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if err := WriteUDPFrame(stream, buf[:n]); err != nil {
				return
			}
		}
	}()

	for {
		_ = stream.SetReadDeadline(time.Now().Add(idle))
		payload, err := ReadUDPFrame(stream)
		if err != nil {
			break
		}
		if _, err := conn.Write(payload); err != nil {
			break
		}
	}
	<-done
	return nil
}
