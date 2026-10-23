package traffic

import (
	"io"
	"net"
	"sync"
	"time"
)

// WrapConn rate-limits Read/Write to roughly bytesPerSec. Zero or negative disables.
func WrapConn(conn net.Conn, bytesPerSec int64) net.Conn {
	if conn == nil || bytesPerSec <= 0 {
		return conn
	}
	return &bwConn{
		Conn: conn,
		bps:  float64(bytesPerSec),
		tok:  float64(bytesPerSec),
		last: time.Now(),
	}
}

type bwConn struct {
	net.Conn
	mu   sync.Mutex
	bps  float64
	tok  float64
	last time.Time
}

func (c *bwConn) refillLocked(n int) {
	now := time.Now()
	elapsed := now.Sub(c.last).Seconds()
	c.last = now
	c.tok += elapsed * c.bps
	if c.tok > c.bps {
		c.tok = c.bps
	}
	need := float64(n)
	if c.tok >= need {
		c.tok -= need
		return
	}
	deficit := need - c.tok
	c.tok = 0
	wait := time.Duration(deficit / c.bps * float64(time.Second))
	if wait > 0 {
		time.Sleep(wait)
	}
}

func (c *bwConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.refillLocked(n)
		c.mu.Unlock()
	}
	return n, err
}

func (c *bwConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		chunk := len(p) - written
		// Cap chunk so we don't sleep for huge buffers at once.
		maxChunk := int(c.bps)
		if maxChunk < 1024 {
			maxChunk = 1024
		}
		if maxChunk > 64*1024 {
			maxChunk = 64 * 1024
		}
		if chunk > maxChunk {
			chunk = maxChunk
		}
		c.mu.Lock()
		c.refillLocked(chunk)
		c.mu.Unlock()
		n, err := c.Conn.Write(p[written : written+chunk])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

var _ io.ReadWriter = (*bwConn)(nil)
