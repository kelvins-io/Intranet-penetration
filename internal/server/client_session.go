package server

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/kelvins-io/Intranet-penetration/internal/policy"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
	"github.com/kelvins-io/Intranet-penetration/internal/tunnel"
)

type clientSessionState struct {
	user      *store.User
	tenant    *store.Tenant
	resources []protocol.ClientResource
	identity  policy.Identity
}

// serveMuxSession peeks the first control message and routes agent vs user client.
func (s *Server) serveMuxSession(ctx context.Context, sess *tunnel.Session, remote, peerCN string) {
	defer sess.Close()
	env, err := sess.ReadControlEnvelope()
	if err != nil {
		s.log.Debug("control peek failed", "remote", remote, "err", err)
		return
	}
	switch env.Type {
	case protocol.MsgClientHello:
		s.serveClientSession(ctx, sess, env, remote)
	case protocol.MsgHello:
		s.serveAgentSessionFromHello(ctx, sess, env, remote, peerCN)
	default:
		s.log.Warn("unknown handshake", "type", env.Type, "remote", remote)
		_ = protocol.WriteJSON(sess.Control(), protocol.MsgError, protocol.ErrorBody{
			Code: "bad_hello", Message: "expected hello or client_hello",
		})
	}
}

func (s *Server) serveClientSession(ctx context.Context, sess *tunnel.Session, env protocol.Envelope, remote string) {
	var st *clientSessionState
	_, ack, err := sess.HandshakeClientAsServer(env, func(h protocol.ClientHello) (*protocol.ClientHelloAck, error) {
		user, ten, err := s.resolveClientToken(h.Token)
		if err != nil {
			return nil, err
		}
		id := policy.Identity{Email: user.Email, Role: user.Role, UserID: user.ID}
		if err := s.enforceClientPosture(ten.ID, h); err != nil {
			return nil, err
		}
		resources := s.projectClientResources(ten, id)
		st = &clientSessionState{user: user, tenant: ten, resources: resources, identity: id}
		return &protocol.ClientHelloAck{
			Version:    protocol.Version,
			UserEmail:  user.Email,
			TenantID:   ten.ID,
			TenantSlug: ten.Slug,
			EdgeID:     s.cfg.EdgeID,
			Region:     s.cfg.Region,
			SessionTTL: 3600,
			Resources:  resources,
			SOCKSHint:  "127.0.0.1:1080",
		}, nil
	})
	if err != nil {
		s.log.Warn("client handshake failed", "remote", remote, "err", err)
		return
	}
	s.log.Info("client session ready", "user", ack.UserEmail, "tenant", ack.TenantSlug, "resources", len(ack.Resources), "remote", remote)
	s.auditEvent(st.tenant.ID, st.user.Email, "client.session", remote, fmt.Sprintf("resources=%d", len(st.resources)))

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go s.handleClientDialStream(ctx, stream, st, remote)
	}
}

func (s *Server) handleClientDialStream(ctx context.Context, stream net.Conn, st *clientSessionState, remote string) {
	defer stream.Close()
	env, err := protocol.ReadJSON(stream)
	if err != nil {
		return
	}
	if env.Type != protocol.MsgDial {
		_ = protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: false, Error: "expected dial"})
		return
	}
	var req protocol.DialRequest
	if err := protocol.DecodeBody(env, &req); err != nil {
		_ = protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: false, Error: "bad dial body"})
		return
	}
	res, err := s.resolveClientDial(st.resources, req)
	if err != nil {
		_ = protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: false, Error: err.Error()})
		return
	}
	action := policy.ActionTCP
	mode := protocol.TunnelTCP
	switch res.Type {
	case protocol.TunnelUDP:
		action = policy.ActionUDP
		mode = protocol.TunnelUDP
	case protocol.TunnelHTTP:
		action = policy.ActionHTTP
		mode = protocol.TunnelTCP // byte pipe to agent local HTTP
	}
	if req.Mode != "" {
		mode = req.Mode
	}
	d := policy.Evaluate(s.listPolicies(st.tenant.ID), st.tenant.ID, res.Name, action, remote, st.identity, s.cfg.AccessDefaultDeny)
	if !d.Allowed {
		s.auditEvent(st.tenant.ID, st.user.Email, "client.dial.deny", res.Name, d.Reason)
		_ = protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: false, Error: "forbidden: " + d.Reason})
		return
	}
	release, _, err := s.enforceTCPTraffic(st.tenant.ID, res.Name, remote)
	if err != nil {
		_ = protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: false, Error: "rate limited"})
		return
	}
	defer release()

	var upstream net.Conn
	if mode == protocol.TunnelUDP {
		route, ok := s.registry.Get(st.tenant.ID, res.Name)
		if !ok || route.Session == nil {
			upstream, err = s.openAgentOrPeer(ctx, "udp", st.tenant.ID, res.Name, "client:"+remote)
		} else {
			upstream, err = route.Session.OpenUDPStream(res.Name, "client:"+remote)
		}
	} else {
		upstream, err = s.openAgentOrPeer(ctx, "tcp", st.tenant.ID, res.Name, "client:"+remote)
	}
	if err != nil {
		_ = protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: false, Error: err.Error()})
		return
	}
	defer upstream.Close()

	if err := protocol.WriteJSON(stream, protocol.MsgDialAck, protocol.DialAck{OK: true, ResourceID: res.ID}); err != nil {
		return
	}
	s.auditEvent(st.tenant.ID, st.user.Email, "client.dial", res.Name, remote)
	if mode == protocol.TunnelUDP {
		relayFramed(stream, upstream)
		return
	}
	tunnel.Proxy(stream, upstream)
}

func (s *Server) resolveClientToken(token string) (*store.User, *store.Tenant, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("token required")
	}
	if s.store != nil {
		return s.store.ResolveUserAPIKey(token)
	}
	if s.ctrl != nil {
		id, err := s.ctrl.ResolveIdentity(token)
		if err != nil {
			return nil, nil, err
		}
		if id.TenantID == "" {
			return nil, nil, fmt.Errorf("identity missing tenant")
		}
		ten := &store.Tenant{ID: id.TenantID, Slug: id.TenantSlug}
		user := &store.User{ID: id.UserID, Email: id.Email, Role: id.Role, TenantID: id.TenantID, APIKey: token}
		return user, ten, nil
	}
	return nil, nil, fmt.Errorf("unauthorized")
}

func (s *Server) enforceClientPosture(tenantID string, h protocol.ClientHello) error {
	posture := h.Posture
	if posture.DeviceID == "" {
		posture.DeviceID = h.DeviceID
	}
	if posture.AgentVersion == "" {
		posture.AgentVersion = h.ClientVer
	}
	device := h.DeviceID
	if device == "" {
		device = "client"
	}
	return s.enforcePosture(tenantID, device, posture)
}
