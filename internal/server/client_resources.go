package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/kelvins-io/Intranet-penetration/internal/policy"
	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/kelvins-io/Intranet-penetration/internal/store"
)

// projectClientResources lists tunnels the identity may access under AccessPolicy.
func (s *Server) projectClientResources(tenant *store.Tenant, id policy.Identity) []protocol.ClientResource {
	if tenant == nil {
		return nil
	}
	var out []protocol.ClientResource
	seen := map[string]bool{}

	addOnline := func(tenantID, slug, name string, typ protocol.TunnelType, publicAddr string, port int, domain string) {
		key := tenantID + "/" + name
		if seen[key] {
			return
		}
		action := policy.ActionHTTP
		switch typ {
		case protocol.TunnelTCP:
			action = policy.ActionTCP
		case protocol.TunnelUDP:
			action = policy.ActionUDP
		}
		d := policy.Evaluate(s.listPolicies(tenantID), tenantID, name, action, "", id, s.cfg.AccessDefaultDeny)
		if !d.Allowed {
			return
		}
		seen[key] = true
		host := name + "." + slug + "." + s.cfg.BaseDomain
		if domain != "" {
			host = domain
		}
		res := protocol.ClientResource{
			ID:         key,
			Name:       name,
			Type:       typ,
			Hostname:   host,
			Port:       port,
			TenantSlug: slug,
			TenantID:   tenantID,
		}
		if typ == protocol.TunnelHTTP {
			base := strings.TrimRight(s.cfg.Cluster.AdvertiseHTTP, "/")
			if base == "" {
				base = "http://" + s.cfg.PublicHost + normalizeListenAddr(s.cfg.HTTPGateway)
			}
			res.BrowserURL = fmt.Sprintf("%s/%s/%s/", base, slug, name)
		}
		if publicAddr != "" && port == 0 {
			if h, p, err := net.SplitHostPort(strings.TrimSuffix(publicAddr, "/tcp")); err == nil {
				res.Port, _ = strconv.Atoi(p)
				_ = h
			}
		}
		out = append(out, res)
	}

	for _, route := range s.registry.List() {
		if route.TenantID != tenant.ID {
			continue
		}
		addOnline(route.TenantID, route.TenantSlug, route.TunnelName, route.Type, route.PublicAddr, route.RemotePort, route.Domain)
	}
	for _, loc := range s.cluster.ListTunnels() {
		if loc.TenantID != tenant.ID {
			continue
		}
		addOnline(loc.TenantID, loc.TenantSlug, loc.TunnelName, protocol.TunnelType(loc.Type), loc.PublicAddr, loc.RemotePort, loc.Domain)
	}
	if s.store != nil {
		for _, rec := range s.store.ListTunnels(tenant.ID) {
			if !rec.Online {
				continue
			}
			addOnline(rec.TenantID, tenant.Slug, rec.Name, protocol.TunnelType(rec.Type), rec.PublicAddr, rec.RemotePort, rec.Domain)
		}
	}
	return out
}

func (s *Server) resolveClientDial(resources []protocol.ClientResource, req protocol.DialRequest) (*protocol.ClientResource, error) {
	if req.ResourceID != "" {
		for i := range resources {
			if resources[i].ID == req.ResourceID {
				return &resources[i], nil
			}
		}
		return nil, fmt.Errorf("unknown resource_id")
	}
	host := strings.TrimSpace(req.Host)
	host = strings.ToLower(host)
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if req.Port == 0 {
			req.Port, _ = strconv.Atoi(p)
		}
	}
	for i := range resources {
		r := &resources[i]
		if strings.EqualFold(r.Hostname, host) || strings.EqualFold(r.Name, host) {
			return r, nil
		}
		if r.VIP != "" && r.VIP == host {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no resource for host %q", host)
}
