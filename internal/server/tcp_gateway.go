package server

import (
	"context"
	"fmt"
	"net"

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
	stream, err := s.registry.OpenToAgent(tenantID, tunnelName, client.RemoteAddr().String())
	if err != nil {
		s.log.Warn("open agent stream", "tunnel", tunnelName, "err", err)
		return
	}
	s.store.Audit(tenantID, "public", "tcp.access", tunnelName, client.RemoteAddr().String())
	tunnel.Proxy(client, stream)
}
