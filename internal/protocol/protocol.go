package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version = 5

	MaxFrameSize = 1 << 20 // 1 MiB
)

// Control message types exchanged on the yamux control stream (stream id 0 opens first).
const (
	MsgHello          = "hello"
	MsgHelloAck       = "hello_ack"
	MsgClientHello    = "client_hello"
	MsgClientHelloAck = "client_hello_ack"
	MsgDial           = "dial"
	MsgDialAck        = "dial_ack"
	MsgOpen           = "open"
	MsgOpenAck        = "open_ack"
	MsgPing           = "ping"
	MsgPong           = "pong"
	MsgKick           = "kick" // Edge → Client: session terminated by admin
	MsgError          = "error"
)

const (
	RoleAgent  = "agent"
	RoleClient = "client"
)

type TunnelType string

const (
	TunnelTCP  TunnelType = "tcp"
	TunnelHTTP TunnelType = "http"
	TunnelUDP  TunnelType = "udp"
)

// DevicePosture is agent-reported device posture for Zero-Trust style checks.
type DevicePosture struct {
	OS           string            `json:"os,omitempty"`            // darwin|linux|windows
	Arch         string            `json:"arch,omitempty"`          // amd64|arm64|...
	Hostname     string            `json:"hostname,omitempty"`
	AgentVersion string            `json:"agent_version,omitempty"`
	DeviceID     string            `json:"device_id,omitempty"` // stable device fingerprint
	Encrypted    *bool             `json:"encrypted,omitempty"` // disk encryption
	Firewall     *bool             `json:"firewall,omitempty"`
	ScreenLock   *bool             `json:"screen_lock,omitempty"`
	Attrs        map[string]string `json:"attrs,omitempty"` // custom key=value
}

// TunnelSpec is declared by the agent during handshake.
type TunnelSpec struct {
	Name      string     `json:"name"`
	Type      TunnelType `json:"type"`
	LocalAddr string     `json:"local_addr"` // e.g. 127.0.0.1:3000
	// RemotePort is optional for TCP tunnels; 0 means server assigns.
	RemotePort int `json:"remote_port,omitempty"`
	// Domain is an optional custom hostname for HTTP tunnels.
	Domain string `json:"domain,omitempty"`
}

type Hello struct {
	Version     int           `json:"version"`
	Role        string        `json:"role,omitempty"` // agent (default) | client — agents omit
	Token       string        `json:"token"`
	AgentID     string        `json:"agent_id"`
	ResumeToken string        `json:"resume_token,omitempty"`
	PreferE2E   bool          `json:"prefer_e2e,omitempty"`
	Region      string        `json:"region,omitempty"`
	Posture     DevicePosture `json:"posture,omitempty"`
	Tunnels     []TunnelSpec  `json:"tunnels"`
}

// ClientHello is sent by the user Access Client on the control stream.
type ClientHello struct {
	Version   int           `json:"version"`
	Token     string        `json:"token"` // user API key or client session token
	DeviceID  string        `json:"device_id,omitempty"`
	Region    string        `json:"region,omitempty"`
	Posture   DevicePosture `json:"posture,omitempty"`
	ClientVer string        `json:"client_version,omitempty"`
}

// ClientResource is a policy-projected tunnel the user may dial.
type ClientResource struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Type       TunnelType `json:"type"`
	Hostname   string     `json:"hostname,omitempty"`    // e.g. demo.default.tunnel.local
	VIP        string     `json:"vip,omitempty"`         // CGNAT VIP in 100.64.0.0/10
	Port       int        `json:"port,omitempty"`        // tcp/udp public port hint
	BrowserURL string     `json:"browser_url,omitempty"` // preferred for http
	TenantSlug string     `json:"tenant_slug,omitempty"`
	TenantID   string     `json:"tenant_id,omitempty"`
}

type ClientHelloAck struct {
	Version     int              `json:"version"`
	SessionID   string           `json:"session_id,omitempty"`
	UserEmail   string           `json:"user_email,omitempty"`
	TenantID    string           `json:"tenant_id,omitempty"`
	TenantSlug  string           `json:"tenant_slug,omitempty"`
	EdgeID      string           `json:"edge_id,omitempty"`
	Region      string           `json:"region,omitempty"`
	SessionTTL  int              `json:"session_ttl_sec,omitempty"`
	Resources   []ClientResource `json:"resources"`
	SOCKSHint   string           `json:"socks_hint,omitempty"` // e.g. 127.0.0.1:1080
	VIPCIDR     string           `json:"vip_cidr,omitempty"`   // e.g. 100.64.0.0/10
	Message     string           `json:"message,omitempty"`
}

// KickBody is sent on the control stream to force-disconnect a user client.
type KickBody struct {
	SessionID string `json:"session_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// DialRequest is the first frame on a client-opened yamux stream.
type DialRequest struct {
	ResourceID string     `json:"resource_id,omitempty"`
	Host       string     `json:"host,omitempty"` // hostname or host:port
	Port       int        `json:"port,omitempty"`
	Mode       TunnelType `json:"mode,omitempty"` // tcp | udp; default tcp
}

type DialAck struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
}

type AssignedTunnel struct {
	Name       string     `json:"name"`
	Type       TunnelType `json:"type"`
	PublicAddr string     `json:"public_addr"` // host:port or http host hint
	RemotePort int        `json:"remote_port,omitempty"`
	Domain     string     `json:"domain,omitempty"`
}

type HelloAck struct {
	Version     int              `json:"version"`
	AgentID     string           `json:"agent_id"`
	TenantID    string           `json:"tenant_id,omitempty"`
	ResumeToken string           `json:"resume_token,omitempty"`
	Resumed     bool             `json:"resumed,omitempty"`
	Transport   string           `json:"transport,omitempty"` // quic | tcp
	EdgeID      string           `json:"edge_id,omitempty"`
	Region      string           `json:"region,omitempty"`
	E2E         bool             `json:"e2e,omitempty"` // backhaul AEAD enabled
	Tunnels     []AssignedTunnel `json:"tunnels"`
	Message     string           `json:"message,omitempty"`
}

// OpenRequest is sent by the server on a new yamux stream before raw bytes.
type OpenRequest struct {
	Tunnel string     `json:"tunnel"`
	Meta   string     `json:"meta,omitempty"` // e.g. remote client addr
	Mode   TunnelType `json:"mode,omitempty"` // tcp (default) | udp — datagrams framed on stream
	E2E    bool       `json:"e2e,omitempty"`
}

type OpenAck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	E2E   bool   `json:"e2e,omitempty"`
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
