package traffic

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

func TestBandwidthPolicySelected(t *testing.T) {
	l := NewLimiter()
	pols := []store.TrafficPolicy{{
		TenantID: "t1", Name: "bw", Enabled: true, Priority: 1,
		Tunnels: []string{"*"}, Scope: "tunnel", MaxBandwidthBPS: 1024,
	}}
	d := l.Allow(pols, "t1", "demo", "1.1.1.1:1")
	if !d.Allowed || d.BandwidthBPS != 1024 {
		t.Fatalf("got %#v", d)
	}
	d.Release()
}

func TestWrapConnThrottle(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	limited := WrapConn(c1, 8*1024) // 8 KiB/s
	payload := bytes.Repeat([]byte("x"), 16*1024)
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, c2)
		done <- err
	}()
	start := time.Now()
	n, err := limited.Write(payload)
	elapsed := time.Since(start)
	if err != nil || n != len(payload) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	_ = c1.Close()
	<-done
	if elapsed < 800*time.Millisecond {
		t.Fatalf("expected throttle, elapsed=%v", elapsed)
	}
}
