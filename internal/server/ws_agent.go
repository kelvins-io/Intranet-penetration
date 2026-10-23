package server

import (
	"context"
	"net/http"

	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

// handleAgentWS accepts Agent WebSocket fallback sessions on the HTTP gateway.
func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	sess, err := tunnel.UpgradeAgentWS(w, r)
	if err != nil {
		s.log.Warn("agent ws upgrade failed", "err", err, "remote", r.RemoteAddr)
		return
	}
	s.log.Info("agent connected", "transport", "websocket", "remote", r.RemoteAddr)
	// Hijacked connection; serve until session ends.
	s.serveAgentSession(context.Background(), sess, r.RemoteAddr, "")
}
