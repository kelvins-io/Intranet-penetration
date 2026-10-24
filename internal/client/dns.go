package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
)

const hostsMarker = "# ip-client-managed"

// DNSEngine serves A records for resource hostnames and optionally writes /etc/hosts.
type DNSEngine struct {
	c          *Client
	listen     string
	writeHosts bool
	mu         sync.RWMutex
	byHost     map[string]string // hostname -> VIP
	hostsPath  string
	ln         net.PacketConn
}

func NewDNSEngine(c *Client, listen string, writeHosts bool) *DNSEngine {
	if listen == "" {
		listen = "127.0.0.1:1053"
	}
	return &DNSEngine{
		c:          c,
		listen:     listen,
		writeHosts: writeHosts,
		byHost:     map[string]string{},
		hostsPath:  "/etc/hosts",
	}
}

func (d *DNSEngine) Sync(resources []protocol.ClientResource) error {
	d.mu.Lock()
	d.byHost = map[string]string{}
	for _, r := range resources {
		if r.VIP == "" || r.Hostname == "" {
			continue
		}
		d.byHost[strings.ToLower(r.Hostname)] = r.VIP
		d.byHost[strings.ToLower(r.Name)] = r.VIP
	}
	d.mu.Unlock()
	if d.writeHosts {
		return d.rewriteHosts(resources)
	}
	return nil
}

func (d *DNSEngine) Lookup(host string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	vip, ok := d.byHost[strings.ToLower(host)]
	return vip, ok
}

func (d *DNSEngine) Start(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", d.listen)
	if err != nil {
		return fmt.Errorf("dns listen %s: %w (try sudo or change dns_listen)", d.listen, err)
	}
	d.ln = pc
	d.c.log.Info("dns listening", "addr", d.listen, "write_hosts", d.writeHosts)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return d.Cleanup()
			default:
				return err
			}
		}
		resp, ok := d.answer(buf[:n])
		if !ok {
			continue
		}
		_, _ = pc.WriteTo(resp, addr)
	}
}

func (d *DNSEngine) Cleanup() error {
	if !d.writeHosts {
		return nil
	}
	return d.rewriteHosts(nil)
}

func (d *DNSEngine) rewriteHosts(resources []protocol.ClientResource) error {
	b, err := os.ReadFile(d.hostsPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var kept []string
	for _, line := range lines {
		if strings.Contains(line, hostsMarker) {
			continue
		}
		kept = append(kept, line)
	}
	for len(kept) > 0 && kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	for _, r := range resources {
		if r.VIP == "" || r.Hostname == "" {
			continue
		}
		kept = append(kept, fmt.Sprintf("%s\t%s %s", r.VIP, r.Hostname, hostsMarker))
	}
	kept = append(kept, "")
	tmp := d.hostsPath + ".ip-client.tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, d.hostsPath)
}

// Minimal DNS A-record responder (no recursion).
func (d *DNSEngine) answer(req []byte) ([]byte, bool) {
	if len(req) < 12 {
		return nil, false
	}
	// Only standard QUERY
	if req[2]&0x80 != 0 {
		return nil, false
	}
	qd := binary.BigEndian.Uint16(req[4:6])
	if qd != 1 {
		return nil, false
	}
	name, off, err := decodeDNSName(req, 12)
	if err != nil || off+4 > len(req) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(req[off : off+2])
	// qclass := binary.BigEndian.Uint16(req[off+2 : off+4])
	if qtype != 1 { // A
		return nil, false
	}
	vip, ok := d.Lookup(name)
	if !ok {
		// NXDOMAIN-ish empty answer with RA
		out := make([]byte, off+4)
		copy(out, req[:off+4])
		out[2] = 0x81 // QR RD
		out[3] = 0x83 // RA + NXDOMAIN
		binary.BigEndian.PutUint16(out[6:8], 0)
		return out, true
	}
	ip := net.ParseIP(vip).To4()
	if ip == nil {
		return nil, false
	}
	out := make([]byte, 0, off+4+16)
	out = append(out, req[:off+4]...)
	out[2] = 0x81
	out[3] = 0x80
	binary.BigEndian.PutUint16(out[6:8], 1) // ANCOUNT
	// answer: pointer to name at 12
	out = append(out, 0xc0, 0x0c)
	out = append(out, 0x00, 0x01) // TYPE A
	out = append(out, 0x00, 0x01) // CLASS IN
	out = append(out, 0x00, 0x00, 0x00, 0x3c) // TTL 60
	out = append(out, 0x00, 0x04)             // RDLENGTH
	out = append(out, ip...)
	return out, true
}

func decodeDNSName(msg []byte, off int) (string, int, error) {
	var parts []string
	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("truncated")
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 == 0xc0 {
			return "", 0, fmt.Errorf("compression in qname unsupported")
		}
		if off+l > len(msg) {
			return "", 0, fmt.Errorf("truncated label")
		}
		parts = append(parts, string(msg[off:off+l]))
		off += l
	}
	return strings.ToLower(strings.Join(parts, ".")), off, nil
}
