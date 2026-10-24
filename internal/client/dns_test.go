package client

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

func TestDNSEngineAnswerA(t *testing.T) {
	d := NewDNSEngine(New(&config.ClientConfig{Token: "t"}, nil), "127.0.0.1:0", false)
	_ = d.Sync([]protocol.ClientResource{{
		ID: "1", Name: "demo", Hostname: "demo.example.local", VIP: "100.64.1.10",
	}})
	q := encodeDNSQuery("demo.example.local")
	resp, ok := d.answer(q)
	if !ok {
		t.Fatal("no answer")
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("QR not set")
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Fatalf("ancount=%d", ancount)
	}
	ip := net.IP(resp[len(resp)-4:])
	if ip.String() != "100.64.1.10" {
		t.Fatalf("vip=%s", ip)
	}
}

func TestDNSEngineNXDOMAIN(t *testing.T) {
	d := NewDNSEngine(New(&config.ClientConfig{Token: "t"}, nil), "127.0.0.1:0", false)
	_ = d.Sync(nil)
	resp, ok := d.answer(encodeDNSQuery("unknown.local"))
	if !ok {
		t.Fatal("expected nxdomain response")
	}
	rcode := resp[3] & 0x0f
	if rcode != 3 {
		t.Fatalf("rcode=%d want 3", rcode)
	}
}

func encodeDNSQuery(name string) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], 0x1234)
	out[2] = 0x01 // RD
	binary.BigEndian.PutUint16(out[4:6], 1)
	for _, p := range splitDNS(name) {
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	out = append(out, 0)
	out = append(out, 0x00, 0x01) // A
	out = append(out, 0x00, 0x01) // IN
	return out
}

func splitDNS(name string) [][]byte {
	var parts [][]byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			parts = append(parts, []byte(name[start:i]))
			start = i + 1
		}
	}
	return parts
}
