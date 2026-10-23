package server

import (
	"context"
	"fmt"
	"net"

	"github.com/kelvins-io/Intranet-penetration/internal/traffic"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

func (s *Server) startTCPListener(ctx context.Context, routeKey string, port int, tenantID, tunnelName string) {
	s.mu.Lock()
	if stop, ok := s.tcpStops[routeKey]; ok {
		stop()
		delete(s.tcpStops, routeKey)
	}
	listenCtx, cancel := context.WithCancel(ctx)
	s.tcpStops[routeKey] = cancel
	s.mu.Unlock()

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.log.Error("tcp tunnel listen failed", "tunnel", routeKey, "addr", addr, "err", err)
		cancel()
		return
	}
	s.trackListener(ln)
	s.log.Info("tcp tunnel listening", "tunnel", routeKey, "addr", ln.Addr().String())

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
					s.log.Warn("tcp accept error", "tunnel", routeKey, "err", err)
					return
				}
			}
			go s.handleTCPConn(tenantID, tunnelName, conn)
		}
	}()
}

func (s *Server) handleTCPConn(tenantID, tunnelName string, client net.Conn) {
	defer client.Close()
	remote := client.RemoteAddr().String()
	if err := s.enforceTCPAccess(tenantID, tunnelName, remote); err != nil {
		s.log.Warn("tcp access denied", "tunnel", tunnelName, "remote", remote)
		return
	}
	release, bw, err := s.enforceTCPTraffic(tenantID, tunnelName, remote)
	if err != nil {
		s.log.Warn("tcp traffic limited", "tunnel", tunnelName, "remote", remote)
		return
	}
	defer release()

	stream, err := s.registry.OpenToAgent(tenantID, tunnelName, remote)
	if err != nil {
		s.log.Warn("open agent stream", "tunnel", tunnelName, "err", err)
		return
	}
	s.metrics.IncTCP()
	if route, ok := s.registry.Get(tenantID, tunnelName); ok && route.Session != nil && route.Session.E2E() {
		s.metrics.IncE2E()
	}
	s.auditEvent(tenantID, "public", "tcp.access", tunnelName, remote)
	tunnel.Proxy(traffic.WrapConn(client, bw), stream)
}
