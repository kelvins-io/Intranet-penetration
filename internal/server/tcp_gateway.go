package server

import (
	"context"
	"fmt"
	"net"

	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

func (s *Server) startTCPListener(ctx context.Context, tunnelName string, port int) {
	s.mu.Lock()
	if stop, ok := s.tcpStops[tunnelName]; ok {
		stop()
		delete(s.tcpStops, tunnelName)
	}
	listenCtx, cancel := context.WithCancel(ctx)
	s.tcpStops[tunnelName] = cancel
	s.mu.Unlock()

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.log.Error("tcp tunnel listen failed", "tunnel", tunnelName, "addr", addr, "err", err)
		cancel()
		return
	}
	s.trackListener(ln)
	s.log.Info("tcp tunnel listening", "tunnel", tunnelName, "addr", ln.Addr().String())

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
					s.log.Warn("tcp accept error", "tunnel", tunnelName, "err", err)
					return
				}
			}
			go s.handleTCPConn(tunnelName, conn)
		}
	}()
}

func (s *Server) handleTCPConn(tunnelName string, client net.Conn) {
	defer client.Close()
	stream, err := s.registry.OpenToAgent(tunnelName, client.RemoteAddr().String())
	if err != nil {
		s.log.Warn("open agent stream", "tunnel", tunnelName, "err", err)
		return
	}
	tunnel.Proxy(client, stream)
}
