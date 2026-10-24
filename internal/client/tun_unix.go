//go:build darwin || linux || windows

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID     = 1
	tunMTU    = 1500
	chanSize  = 128
	maxFlight = 1024
)

// NewTunEngine returns a wireguard-tun + gVisor engine (darwin/linux).
func NewTunEngine(c *Client) TunEngine {
	return &unixTun{baseTun: baseTun{c: c}}
}

type unixTun struct {
	baseTun
	dev  tun.Device
	ep   *channel.Endpoint
	stk  *stack.Stack
	name string
}

func (t *unixTun) Start(ctx context.Context) error {
	if err := t.c.waitReady(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()

	resources := t.c.Resources()
	dnsListen := t.c.cfg.DNSListen
	if dnsListen == "" {
		dnsListen = "127.0.0.1:1053"
	}
	t.dns = NewDNSEngine(t.c, dnsListen, t.c.cfg.WriteHosts)
	if err := t.dns.Sync(resources); err != nil {
		t.c.log.Warn("dns sync", "err", err)
	}
	go func() {
		if err := t.dns.Start(ctx); err != nil && ctx.Err() == nil {
			t.c.log.Warn("dns server", "err", err)
		}
	}()
	go t.refreshDNS(ctx)

	name := t.c.cfg.TunName
	if name == "" {
		switch runtime.GOOS {
		case "darwin":
			name = "utun"
		case "windows":
			name = "IPClient"
		default:
			name = "ip0"
		}
	}
	dev, err := tun.CreateTUN(name, tunMTU)
	if err != nil {
		return fmt.Errorf("create tun %q: %w (need root/admin?)", name, err)
	}
	t.dev = dev
	ifName, _ := dev.Name()
	t.name = ifName
	t.c.log.Info("tun device", "name", ifName)

	offset := 0
	if runtime.GOOS == "darwin" {
		offset = 4 // AF_INET header
	}

	ep := channel.New(chanSize, uint32(tunMTU), "")
	t.ep = ep
	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.stk = stk
	if err := stk.CreateNIC(nicID, ep); err != nil {
		_ = dev.Close()
		return fmt.Errorf("create nic: %v", err)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{100, 64, 0, 1}),
			PrefixLen: 10,
		},
	}
	if err := stk.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		_ = dev.Close()
		return fmt.Errorf("add address: %v", err)
	}
	stk.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	tcpFwd := tcp.NewForwarder(stk, 0, maxFlight, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		vip := id.LocalAddress.String()
		port := int(id.LocalPort)
		res, ok := t.c.LookupByVIP(vip)
		if !ok {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		local := gonet.NewTCPConn(&wq, ep)
		go t.bridgeTCP(ctx, local, res, vip, port)
	})
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(stk, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		vip := id.LocalAddress.String()
		res, ok := t.c.LookupByVIP(vip)
		if !ok {
			return true
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return true
		}
		conn := gonet.NewUDPConn(&wq, ep)
		go t.bridgeUDP(ctx, conn, res, vip, int(id.LocalPort))
		return true
	})
	stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	if err := configureTUN(ifName, clientTUNIP, defaultVIPNet); err != nil {
		t.c.log.Warn("configure tun routes", "err", err)
	} else {
		t.c.log.Info("split tunnel routes installed", "cidr", defaultVIPNet, "dev", ifName)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		t.tunToStack(ctx, offset)
	}()
	go func() {
		defer wg.Done()
		t.stackToTun(ctx, offset)
	}()

	<-ctx.Done()
	_ = t.cleanupRoutes(ifName)
	_ = dev.Close()
	stk.Close()
	wg.Wait()
	return t.dns.Cleanup()
}

func (t *unixTun) refreshDNS(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if t.dns == nil {
				continue
			}
			if err := t.dns.Sync(t.c.Resources()); err != nil {
				t.c.log.Debug("dns refresh", "err", err)
			}
		}
	}
}

func (t *unixTun) bridgeTCP(ctx context.Context, local net.Conn, res protocol.ClientResource, vip string, port int) {
	defer local.Close()
	host := res.Hostname
	if host == "" {
		host = res.Name
	}
	if res.Port > 0 && port == 0 {
		port = res.Port
	}
	upstream, err := t.c.DialResource(ctx, host, port)
	if err != nil {
		t.c.log.Debug("tun tcp dial", "vip", vip, "host", host, "port", port, "err", err)
		return
	}
	defer upstream.Close()
	t.c.log.Info("tun tcp", "vip", vip, "port", port, "resource", res.ID)
	errCh := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, upstream); errCh <- struct{}{} }()
	go func() { _, _ = io.Copy(upstream, local); errCh <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-errCh:
	}
}

func (t *unixTun) bridgeUDP(ctx context.Context, local net.Conn, res protocol.ClientResource, vip string, port int) {
	defer local.Close()
	host := res.Hostname
	if host == "" {
		host = res.Name
	}
	upstream, err := t.c.DialResource(ctx, host, port)
	if err != nil {
		return
	}
	defer upstream.Close()
	t.c.log.Info("tun udp", "vip", vip, "resource", res.ID)
	errCh := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, upstream); errCh <- struct{}{} }()
	go func() { _, _ = io.Copy(upstream, local); errCh <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-errCh:
	}
}

func (t *unixTun) tunToStack(ctx context.Context, offset int) {
	batch := t.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, offset+tunMTU)
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := t.dev.Read(bufs, sizes, offset)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			if len(pkt) == 0 {
				continue
			}
			data := make([]byte, len(pkt))
			copy(data, pkt)
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
			pb.DecRef()
		}
	}
}

func (t *unixTun) stackToTun(ctx context.Context, offset int) {
	for {
		pkt := t.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		data := v.AsSlice()
		buf := make([]byte, offset+len(data))
		if offset == 4 {
			// AF_INET family header for darwin utun
			buf[3] = 2
		}
		copy(buf[offset:], data)
		v.Release()
		_, _ = t.dev.Write([][]byte{buf}, offset)
		pkt.DecRef()
	}
}

func configureTUN(ifName, localIP, cidr string) error {
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("ifconfig", ifName, "inet", localIP, localIP, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		parts := strings.SplitN(cidr, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("bad cidr")
		}
		maskBits, _ := strconv.Atoi(parts[1])
		mask := net.CIDRMask(maskBits, 32)
		maskStr := net.IP(mask).String()
		if out, err := exec.Command("route", "-n", "add", "-net", parts[0], "-netmask", maskStr, "-interface", ifName).CombinedOutput(); err != nil {
			t := strings.ToLower(string(out))
			if !strings.Contains(t, "exists") && !strings.Contains(t, "file exists") {
				return fmt.Errorf("route add: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	case "linux":
		if out, err := exec.Command("ip", "addr", "add", localIP+"/32", "dev", ifName).CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip addr: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		if out, err := exec.Command("ip", "link", "set", ifName, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("ip link: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("ip", "route", "add", cidr, "dev", ifName).CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip route: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	case "windows":
		// Wintun interface; configure address + split route via netsh (needs admin).
		if out, err := exec.Command("netsh", "interface", "ip", "set", "address",
			"name="+ifName, "static", localIP, "255.192.0.0").CombinedOutput(); err != nil {
			t := strings.ToLower(string(out))
			if !strings.Contains(t, "exists") {
				return fmt.Errorf("netsh address: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		parts := strings.SplitN(cidr, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("bad cidr")
		}
		if out, err := exec.Command("route", "add", parts[0], "mask", "255.192.0.0", localIP).CombinedOutput(); err != nil {
			t := strings.ToLower(string(out))
			if !strings.Contains(t, "exists") {
				return fmt.Errorf("route add: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported os")
	}
}

func (t *unixTun) cleanupRoutes(ifName string) error {
	switch runtime.GOOS {
	case "darwin":
		parts := strings.SplitN(defaultVIPNet, "/", 2)
		mask := net.CIDRMask(10, 32)
		_ = exec.Command("route", "-n", "delete", "-net", parts[0], "-netmask", net.IP(mask).String(), "-interface", ifName).Run()
	case "linux":
		_ = exec.Command("ip", "route", "del", defaultVIPNet, "dev", ifName).Run()
	case "windows":
		parts := strings.SplitN(defaultVIPNet, "/", 2)
		_ = exec.Command("route", "delete", parts[0], "mask", "255.192.0.0").Run()
	}
	return nil
}
