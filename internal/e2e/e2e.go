package e2e

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	maxFrame = 1 << 16
	keyInfo  = "intranet-penetration-e2e-v1"
)

// Conn is an AEAD-framed net.Conn. Handshake must complete before use.
type Conn struct {
	net.Conn
	sendCipher interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
	}
	recvCipher interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	sendNonce uint64
	recvNonce uint64
	readBuf   []byte
	mu        sync.Mutex
}

// HandshakeAsClient performs X25519 ECDH then returns a sealed Conn (initiator).
func HandshakeAsClient(raw net.Conn) (*Conn, error) {
	priv, pub, err := generateKeypair()
	if err != nil {
		return nil, err
	}
	if err := writeRaw(raw, pub[:]); err != nil {
		return nil, err
	}
	peerPub, err := readExact(raw, 32)
	if err != nil {
		return nil, err
	}
	return newConn(raw, priv, peerPub, true)
}

// HandshakeAsServer performs X25519 ECDH then returns a sealed Conn (responder).
func HandshakeAsServer(raw net.Conn) (*Conn, error) {
	peerPub, err := readExact(raw, 32)
	if err != nil {
		return nil, err
	}
	priv, pub, err := generateKeypair()
	if err != nil {
		return nil, err
	}
	if err := writeRaw(raw, pub[:]); err != nil {
		return nil, err
	}
	return newConn(raw, priv, peerPub, false)
}

func generateKeypair() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func newConn(raw net.Conn, priv [32]byte, peerPub []byte, initiator bool) (*Conn, error) {
	if len(peerPub) != 32 {
		return nil, errors.New("bad peer key")
	}
	var shared [32]byte
	var peer [32]byte
	copy(peer[:], peerPub)
	curve25519.ScalarMult(&shared, &priv, &peer)

	secret := make([]byte, 32)
	r := hkdf.New(sha3.New256, shared[:], nil, []byte(keyInfo))
	if _, err := io.ReadFull(r, secret); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(secret)
	if err != nil {
		return nil, err
	}
	_ = initiator
	return &Conn{Conn: raw, sendCipher: aead, recvCipher: aead}, nil
}

func writeRaw(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrame-16 {
			chunk = p[:maxFrame-16]
		}
		nonce := make([]byte, chacha20poly1305.NonceSize)
		binary.BigEndian.PutUint64(nonce[4:], c.sendNonce)
		c.sendNonce++
		ct := c.sendCipher.Seal(nil, nonce, chunk, nil)
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
		if _, err := c.Conn.Write(hdr[:]); err != nil {
			return written, err
		}
		if _, err := c.Conn.Write(ct); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > maxFrame {
		return 0, fmt.Errorf("e2e bad frame len %d", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return 0, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], c.recvNonce)
	c.recvNonce++
	pt, err := c.recvCipher.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, err
	}
	copied := copy(p, pt)
	if copied < len(pt) {
		c.readBuf = pt[copied:]
	}
	return copied, nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
