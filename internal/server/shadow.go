package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/cluster"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/traffic"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

func shadowKey(tenantID, name string) string {
	return "shadow:" + store.RouteKey(tenantID, name)
}

// startShadowSyncLoop mirrors remote TCP/UDP listeners so any Edge can accept
// traffic and relay to the owning Edge over /internal/stream.
func (s *Server) startShadowSyncLoop(ctx context.Context) {
	go func() {
		s.syncShadowListeners(ctx)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.syncShadowListeners(ctx)
			}
		}
	}()
}

func (s *Server) syncShadowListeners(ctx context.Context) {
	desired := map[string]cluster.TunnelLocation{}
	for _, loc := range s.cluster.ListTunnels() {
		if loc.EdgeID == "" || loc.EdgeID == s.cfg.EdgeID {
			continue
		}
		if loc.RemotePort <= 0 {
			continue
		}
		typ := strings.ToLower(loc.Type)
		if typ != string(protocol.TunnelTCP) && typ != string(protocol.TunnelUDP) {
			continue
		}
		if _, ok := s.registry.Get(loc.TenantID, loc.TunnelName); ok {
			continue
		}
		desired[shadowKey(loc.TenantID, loc.TunnelName)] = loc
	}

	s.mu.Lock()
	for key, stop := range s.tcpStops {
		if !strings.HasPrefix(key, "shadow:") {
			continue
		}
		if _, ok := desired[key]; !ok {
			stop()
			delete(s.tcpStops, key)
			s.log.Info("shadow listener stopped", "key", key)
		}
	}
	s.mu.Unlock()

	for key, loc := range desired {
		s.mu.Lock()
		_, running := s.tcpStops[key]
		s.mu.Unlock()
		if running {
			continue
		}
		switch strings.ToLower(loc.Type) {
		case string(protocol.TunnelTCP):
			s.startShadowTCP(ctx, key, loc)
		case string(protocol.TunnelUDP):
			s.startShadowUDP(ctx, key, loc)
		}
	}
}

func (s *Server) stopShadowIfAny(tenantID, name string) {
	key := shadowKey(tenantID, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if stop, ok := s.tcpStops[key]; ok {
		stop()
		delete(s.tcpStops, key)
	}
}

func (s *Server) startShadowTCP(ctx context.Context, key string, loc cluster.TunnelLocation) {
	s.mu.Lock()
	if stop, ok := s.tcpStops[key]; ok {
		stop()
		delete(s.tcpStops, key)
	}
	listenCtx, cancel := context.WithCancel(ctx)
	s.tcpStops[key] = cancel
	s.mu.Unlock()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", loc.RemotePort))
	if err != nil {
		s.log.Debug("shadow tcp listen skipped", "port", loc.RemotePort, "err", err)
		cancel()
		s.mu.Lock()
		delete(s.tcpStops, key)
		s.mu.Unlock()
		return
	}
	s.trackListener(ln)
	s.log.Info("shadow tcp listening", "tunnel", loc.TunnelName, "port", loc.RemotePort, "owner", loc.EdgeID)

	go func() {
		<-listenCtx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-listenCtx.Done():
					return
				default:
					return
				}
			}
			go s.handleShadowTCPConn(listenCtx, loc, conn)
		}
	}()
}

func (s *Server) handleShadowTCPConn(ctx context.Context, loc cluster.TunnelLocation, client net.Conn) {
	defer client.Close()
	remote := client.RemoteAddr().String()
	if err := s.enforceTCPAccess(loc.TenantID, loc.TunnelName, remote); err != nil {
		return
	}
	release, bw, err := s.enforceTCPTraffic(loc.TenantID, loc.TunnelName, remote)
	if err != nil {
		return
	}
	defer release()

	peer := loc.AdvertiseHTTP
	if peer == "" {
		peer = s.peerURLFor(loc.EdgeID)
	}
	stream, err := s.dialPeerStream(ctx, peer, "tcp", loc.TenantID, loc.TunnelName)
	if err != nil {
		s.log.Warn("shadow tcp peer dial", "err", err, "peer", peer)
		return
	}
	s.metrics.IncTCP()
	tunnel.Proxy(traffic.WrapConn(client, bw), stream)
}

func (s *Server) startShadowUDP(ctx context.Context, key string, loc cluster.TunnelLocation) {
	s.mu.Lock()
	if stop, ok := s.tcpStops[key]; ok {
		stop()
		delete(s.tcpStops, key)
	}
	listenCtx, cancel := context.WithCancel(ctx)
	s.tcpStops[key] = cancel
	s.mu.Unlock()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: loc.RemotePort})
	if err != nil {
		s.log.Debug("shadow udp listen skipped", "port", loc.RemotePort, "err", err)
		cancel()
		s.mu.Lock()
		delete(s.tcpStops, key)
		s.mu.Unlock()
		return
	}
	s.log.Info("shadow udp listening", "tunnel", loc.TunnelName, "port", loc.RemotePort, "owner", loc.EdgeID)

	go func() {
		<-listenCtx.Done()
		_ = pc.Close()
	}()
	go s.serveShadowUDP(listenCtx, pc, loc)
}

func (s *Server) serveShadowUDP(ctx context.Context, pc *net.UDPConn, loc cluster.TunnelLocation) {
	type assoc struct {
		ch     chan []byte
		cancel context.CancelFunc
	}
	var mu sync.Mutex
	assocs := map[string]*assoc{}
	cleanup := func(k string) {
		mu.Lock()
		if a, ok := assocs[k]; ok {
			a.cancel()
			delete(assocs, k)
		}
		mu.Unlock()
	}

	buf := make([]byte, 64<<10)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, clientAddr, err := pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				mu.Lock()
				for k, a := range assocs {
					a.cancel()
					delete(assocs, k)
				}
				mu.Unlock()
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		key := clientAddr.String()
		payload := make([]byte, n)
		copy(payload, buf[:n])
		mu.Lock()
		a, exists := assocs[key]
		if !exists {
			ac, cancel := context.WithCancel(ctx)
			a = &assoc{ch: make(chan []byte, 32), cancel: cancel}
			assocs[key] = a
			mu.Unlock()
			go s.handleShadowUDPAssoc(ac, pc, loc, clientAddr, a.ch, func() { cleanup(key) })
		} else {
			mu.Unlock()
		}
		select {
		case a.ch <- payload:
		default:
		}
	}
}

func (s *Server) handleShadowUDPAssoc(ctx context.Context, pc *net.UDPConn, loc cluster.TunnelLocation, clientAddr *net.UDPAddr, ch <-chan []byte, done func()) {
	defer done()
	remote := clientAddr.String()
	peer := loc.AdvertiseHTTP
	if peer == "" {
		peer = s.peerURLFor(loc.EdgeID)
	}
	stream, err := s.dialPeerStream(ctx, peer, "udp", loc.TenantID, loc.TunnelName)
	if err != nil {
		s.log.Warn("shadow udp peer dial", "err", err)
		return
	}
	defer stream.Close()
	s.metrics.IncUDP()

	errCh := make(chan struct{}, 2)
	go func() {
		for {
			select {
			case <-ctx.Done():
				errCh <- struct{}{}
				return
			case payload, ok := <-ch:
				if !ok {
					errCh <- struct{}{}
					return
				}
				if err := tunnel.WriteUDPFrame(stream, payload); err != nil {
					errCh <- struct{}{}
					return
				}
			}
		}
	}()
	go func() {
		for {
			payload, err := tunnel.ReadUDPFrame(stream)
			if err != nil {
				errCh <- struct{}{}
				return
			}
			if _, err := pc.WriteToUDP(payload, clientAddr); err != nil {
				errCh <- struct{}{}
				return
			}
			_ = remote
		}
	}()
	select {
	case <-ctx.Done():
	case <-errCh:
	}
}
