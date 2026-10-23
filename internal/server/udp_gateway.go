package server

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/policy"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type udpAssoc struct {
	ch     chan []byte
	cancel context.CancelFunc
}

func (s *Server) startUDPListener(ctx context.Context, routeKey string, port int, tenantID, tunnelName string) {
	s.stopShadowIfAny(tenantID, tunnelName)
	s.mu.Lock()
	if stop, ok := s.tcpStops[routeKey]; ok {
		stop()
		delete(s.tcpStops, routeKey)
	}
	listenCtx, cancel := context.WithCancel(ctx)
	s.tcpStops[routeKey] = cancel
	s.mu.Unlock()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		s.log.Error("udp tunnel listen failed", "tunnel", routeKey, "port", port, "err", err)
		cancel()
		return
	}
	s.log.Info("udp tunnel listening", "tunnel", routeKey, "addr", pc.LocalAddr().String())

	go func() {
		<-listenCtx.Done()
		_ = pc.Close()
	}()
	go s.serveUDPTunnel(listenCtx, pc, tenantID, tunnelName)
}

func (s *Server) serveUDPTunnel(ctx context.Context, pc *net.UDPConn, tenantID, tunnelName string) {
	var mu sync.Mutex
	assocs := map[string]*udpAssoc{}

	cleanup := func(key string) {
		mu.Lock()
		if a, ok := assocs[key]; ok {
			a.cancel()
			delete(assocs, key)
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
				s.log.Warn("udp read", "tunnel", tunnelName, "err", err)
				return
			}
		}
		key := clientAddr.String()
		payload := make([]byte, n)
		copy(payload, buf[:n])

		mu.Lock()
		a, exists := assocs[key]
		if !exists {
			assocCtx, assocCancel := context.WithCancel(ctx)
			a = &udpAssoc{ch: make(chan []byte, 32), cancel: assocCancel}
			assocs[key] = a
			mu.Unlock()
			go s.handleUDPAssoc(assocCtx, pc, tenantID, tunnelName, clientAddr, a, func() { cleanup(key) })
		} else {
			mu.Unlock()
		}
		select {
		case a.ch <- payload:
		default:
			s.log.Debug("udp drop (backpressure)", "tunnel", tunnelName, "client", key)
		}
	}
}

func (s *Server) handleUDPAssoc(ctx context.Context, pc *net.UDPConn, tenantID, tunnelName string, clientAddr *net.UDPAddr, a *udpAssoc, done func()) {
	defer done()
	remote := clientAddr.String()

	if err := s.enforceUDPAccess(tenantID, tunnelName, remote); err != nil {
		s.log.Warn("udp access denied", "tunnel", tunnelName, "remote", remote)
		return
	}
	release, _, err := s.enforceTCPTraffic(tenantID, tunnelName, remote)
	if err != nil {
		s.log.Warn("udp traffic limited", "tunnel", tunnelName, "remote", remote)
		return
	}
	defer release()

	var stream net.Conn
	route, ok := s.registry.Get(tenantID, tunnelName)
	if ok && route.Session != nil && !route.Session.IsClosed() {
		var err error
		stream, err = route.Session.OpenUDPStream(tunnelName, remote)
		if err != nil {
			s.log.Warn("open udp stream", "tunnel", tunnelName, "err", err)
			return
		}
	} else {
		var err error
		stream, err = s.openAgentOrPeer(ctx, "udp", tenantID, tunnelName, remote)
		if err != nil {
			s.log.Warn("udp tunnel offline", "tunnel", tunnelName, "err", err)
			return
		}
	}
	defer stream.Close()

	s.metrics.IncUDP()
	s.auditEvent(tenantID, "public", "udp.access", tunnelName, remote)

	idle := 60 * time.Second
	errCh := make(chan struct{}, 2)

	go func() {
		for {
			select {
			case <-ctx.Done():
				errCh <- struct{}{}
				return
			case payload, ok := <-a.ch:
				if !ok {
					errCh <- struct{}{}
					return
				}
				_ = stream.SetWriteDeadline(time.Now().Add(idle))
				if err := tunnel.WriteUDPFrame(stream, payload); err != nil {
					errCh <- struct{}{}
					return
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				errCh <- struct{}{}
				return
			default:
			}
			_ = stream.SetReadDeadline(time.Now().Add(idle))
			payload, err := tunnel.ReadUDPFrame(stream)
			if err != nil {
				errCh <- struct{}{}
				return
			}
			if _, err := pc.WriteToUDP(payload, clientAddr); err != nil {
				errCh <- struct{}{}
				return
			}
		}
	}()

	<-errCh
}

func (s *Server) enforceUDPAccess(tenantID, tunnel, remoteAddr string) error {
	d := policy.Evaluate(
		s.listPolicies(tenantID),
		tenantID,
		tunnel,
		policy.ActionUDP,
		remoteAddr,
		policy.Identity{Anonymous: true},
		s.cfg.AccessDefaultDeny,
	)
	if d.Allowed {
		return nil
	}
	s.auditEvent(tenantID, "public", "access.deny", tunnel, d.Reason+" action=udp.access")
	return store.ErrUnauthorized
}
