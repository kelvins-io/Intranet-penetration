package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

// handleInternalStream upgrades a cluster-authenticated WebSocket and relays
// to the local Agent session (TCP byte pipe or UDP framed datagrams).
func (s *Server) handleInternalStream(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Cluster.Secret != "" && r.Header.Get("X-Cluster-Secret") != s.cfg.Cluster.Secret {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/internal/stream/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 3 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	mode, tenantID, name := parts[0], parts[1], parts[2]
	wc, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		s.log.Warn("peer stream accept", "err", err)
		return
	}
	conn := websocket.NetConn(r.Context(), wc, websocket.MessageBinary)
	defer conn.Close()

	switch strings.ToLower(mode) {
	case "tcp":
		stream, err := s.registry.OpenToAgent(tenantID, name, "peer:"+r.RemoteAddr)
		if err != nil {
			s.log.Warn("peer tcp open agent", "tunnel", name, "err", err)
			return
		}
		s.metrics.IncTCP()
		tunnel.Proxy(conn, stream)
	case "udp":
		route, ok := s.registry.Get(tenantID, name)
		if !ok || route.Session == nil || route.Session.IsClosed() {
			s.log.Warn("peer udp tunnel offline", "tunnel", name)
			return
		}
		stream, err := route.Session.OpenUDPStream(name, "peer:"+r.RemoteAddr)
		if err != nil {
			s.log.Warn("peer udp open agent", "err", err)
			return
		}
		defer stream.Close()
		s.metrics.IncUDP()
		relayFramed(conn, stream)
	default:
		s.log.Warn("peer stream bad mode", "mode", mode)
	}
}

func relayFramed(a, b net.Conn) {
	errCh := make(chan struct{}, 2)
	copyF := func(dst, src net.Conn) {
		for {
			payload, err := tunnel.ReadUDPFrame(src)
			if err != nil {
				errCh <- struct{}{}
				return
			}
			if err := tunnel.WriteUDPFrame(dst, payload); err != nil {
				errCh <- struct{}{}
				return
			}
		}
	}
	go copyF(a, b)
	go copyF(b, a)
	<-errCh
}

func (s *Server) dialPeerStream(ctx context.Context, peerHTTP, mode, tenantID, name string) (net.Conn, error) {
	base := strings.TrimRight(strings.TrimSpace(peerHTTP), "/")
	if base == "" {
		return nil, fmt.Errorf("empty peer url")
	}
	wsURL := httpToWS(base) + "/internal/stream/" + mode + "/" + tenantID + "/" + name
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hdr := http.Header{}
	if s.cfg.Cluster.Secret != "" {
		hdr.Set("X-Cluster-Secret", s.cfg.Cluster.Secret)
	}
	wc, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		return nil, fmt.Errorf("peer ws dial: %w", err)
	}
	return websocket.NetConn(ctx, wc, websocket.MessageBinary), nil
}

func httpToWS(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://")
	default:
		return "ws://" + u
	}
}

// openAgentOrPeer opens a local agent stream, or peers to the owning edge.
func (s *Server) openAgentOrPeer(ctx context.Context, mode, tenantID, name, remote string) (net.Conn, error) {
	if stream, err := s.registry.OpenToAgent(tenantID, name, remote); err == nil {
		return stream, nil
	}
	loc, ok := s.cluster.Get(tenantID, name)
	if !ok || loc.EdgeID == "" || loc.EdgeID == s.cfg.EdgeID {
		return nil, fmt.Errorf("tunnel %q offline", name)
	}
	peer := loc.AdvertiseHTTP
	if peer == "" {
		peer = s.peerURLFor(loc.EdgeID)
	}
	s.log.Info("cross-edge relay", "mode", mode, "tunnel", name, "peer_edge", loc.EdgeID, "peer", peer)
	return s.dialPeerStream(ctx, peer, mode, tenantID, name)
}
