package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version = 1

	MaxFrameSize = 1 << 20 // 1 MiB
)

// Control message types exchanged on the yamux control stream (stream id 0 opens first).
const (
	MsgHello    = "hello"
	MsgHelloAck = "hello_ack"
	MsgOpen     = "open"
	MsgOpenAck  = "open_ack"
	MsgPing     = "ping"
	MsgPong     = "pong"
	MsgError    = "error"
)

type TunnelType string

const (
	TunnelTCP  TunnelType = "tcp"
	TunnelHTTP TunnelType = "http"
)

// TunnelSpec is declared by the agent during handshake.
type TunnelSpec struct {
	Name      string     `json:"name"`
	Type      TunnelType `json:"type"`
	LocalAddr string     `json:"local_addr"` // e.g. 127.0.0.1:3000
	// RemotePort is optional for TCP tunnels; 0 means server assigns.
	RemotePort int `json:"remote_port,omitempty"`
}

type Hello struct {
	Version int          `json:"version"`
	Token   string       `json:"token"`
	AgentID string       `json:"agent_id"`
	Tunnels []TunnelSpec `json:"tunnels"`
}

type AssignedTunnel struct {
	Name       string     `json:"name"`
	Type       TunnelType `json:"type"`
	PublicAddr string     `json:"public_addr"` // host:port or http host hint
	RemotePort int        `json:"remote_port,omitempty"`
}

type HelloAck struct {
	Version int              `json:"version"`
	AgentID string           `json:"agent_id"`
	Tunnels []AssignedTunnel `json:"tunnels"`
	Message string           `json:"message,omitempty"`
}

// OpenRequest is sent by the server on a new yamux stream before raw bytes.
type OpenRequest struct {
	Tunnel string `json:"tunnel"`
	Meta   string `json:"meta,omitempty"` // e.g. remote client addr
}

type OpenAck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type Envelope struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body,omitempty"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func EncodeEnvelope(msgType string, body any) ([]byte, error) {
	var raw json.RawMessage
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return json.Marshal(Envelope{Type: msgType, Body: raw})
}

func DecodeEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, err
	}
	if env.Type == "" {
		return Envelope{}, errors.New("missing envelope type")
	}
	return env, nil
}

func DecodeBody[T any](env Envelope, dst *T) error {
	if len(env.Body) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(env.Body, dst)
}

// WriteFrame writes a length-prefixed frame (4-byte big-endian length + payload).
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return []byte{}, nil
	}
	if n > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func WriteJSON(w io.Writer, msgType string, body any) error {
	payload, err := EncodeEnvelope(msgType, body)
	if err != nil {
		return err
	}
	return WriteFrame(w, payload)
}

func ReadJSON(r io.Reader) (Envelope, error) {
	payload, err := ReadFrame(r)
	if err != nil {
		return Envelope{}, err
	}
	return DecodeEnvelope(payload)
}
