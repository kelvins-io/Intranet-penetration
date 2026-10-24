package client

import (
	"net"
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
)

func TestNewClientDefaults(t *testing.T) {
	c := New(&config.ClientConfig{Token: "k", SOCKSListen: "127.0.0.1:1080"}, nil)
	if c == nil {
		t.Fatal("nil client")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
}
