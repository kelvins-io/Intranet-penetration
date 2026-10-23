package server

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

type regionRecommendation struct {
	Region        string  `json:"region"`
	EdgeID        string  `json:"edge_id"`
	AdvertiseHTTP string  `json:"advertise_http"`
	AgentListen   string  `json:"agent_listen,omitempty"`
	QUICListen    string  `json:"quic_listen,omitempty"`
	WSURL         string  `json:"ws_url,omitempty"`
	Score         float64 `json:"score"`
	Reason        string  `json:"reason"`
	Fresh         bool    `json:"fresh"`
	TunnelLoad    int     `json:"tunnel_load"`
}

// handleRegionDiscover is unauthenticated for Agents (region auto-schedule).
func (s *Server) handleRegionDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	prefer := r.URL.Query().Get("prefer")
	if prefer == "" {
		prefer = r.URL.Query().Get("region")
	}
	rec := s.recommendRegion(prefer)
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleRegionRecommend(w http.ResponseWriter, r *http.Request, au *apiUser) {
	prefer := r.URL.Query().Get("prefer")
	if prefer == "" {
		prefer = au.Tenant.Slug
	}
	_ = au
	writeJSON(w, http.StatusOK, s.recommendRegion(prefer))
}

func (s *Server) recommendRegion(prefer string) regionRecommendation {
	prefer = strings.TrimSpace(prefer)
	edges := s.cluster.ListEdges()
	tunnels := s.cluster.ListTunnels()
	loadByEdge := map[string]int{}
	for _, t := range tunnels {
		loadByEdge[t.EdgeID]++
	}

	type cand struct {
		rec   regionRecommendation
		score float64
	}
	var cands []cand
	now := time.Now().UTC()

	add := func(edgeID, region, advertise string, local bool) {
		if edgeID == "" {
			return
		}
		fresh := true
		for _, e := range edges {
			if e.ID == edgeID {
				if now.Sub(e.LastSeen) > 2*time.Minute {
					fresh = false
				}
				if region == "" {
					region = e.Region
				}
				if advertise == "" {
					advertise = e.AdvertiseHTTP
				}
				break
			}
		}
		if advertise == "" {
			advertise = s.cfg.Cluster.AdvertiseHTTP
		}
		score := 50.0
		reason := "baseline"
		if prefer != "" && strings.EqualFold(region, prefer) {
			score += 40
			reason = "region match"
		}
		if local || edgeID == s.cfg.EdgeID {
			score += 10
			if reason == "baseline" {
				reason = "local edge"
			}
		}
		if fresh {
			score += 15
		} else {
			score -= 30
			reason = "stale heartbeat"
		}
		load := loadByEdge[edgeID]
		score -= float64(load) * 2 // prefer less loaded
		ws := wsURLFromAdvertise(advertise)
		cands = append(cands, cand{
			score: score,
			rec: regionRecommendation{
				Region:        region,
				EdgeID:        edgeID,
				AdvertiseHTTP: advertise,
				AgentListen:   s.cfg.Listen,
				QUICListen:    s.cfg.QUICListen,
				WSURL:         ws,
				Score:         score,
				Reason:        reason,
				Fresh:         fresh,
				TunnelLoad:    load,
			},
		})
	}

	// Always include self.
	add(s.cfg.EdgeID, s.cfg.Region, s.cfg.Cluster.AdvertiseHTTP, true)
	for _, e := range edges {
		if e.ID == s.cfg.EdgeID {
			continue
		}
		add(e.ID, e.Region, e.AdvertiseHTTP, false)
	}
	for _, rp := range s.cfg.Regions {
		// Static region peers without live edge heartbeat.
		found := false
		for _, c := range cands {
			if strings.EqualFold(c.rec.Region, rp.Name) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		add("peer-"+rp.Name, rp.Name, rp.AdvertiseHTTP, false)
	}

	if len(cands) == 0 {
		return regionRecommendation{
			Region:        s.cfg.Region,
			EdgeID:        s.cfg.EdgeID,
			AdvertiseHTTP: s.cfg.Cluster.AdvertiseHTTP,
			AgentListen:   s.cfg.Listen,
			QUICListen:    s.cfg.QUICListen,
			WSURL:         wsURLFromAdvertise(s.cfg.Cluster.AdvertiseHTTP),
			Score:         1,
			Reason:        "fallback local",
			Fresh:         true,
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	best := cands[0].rec
	best.Score = cands[0].score
	return best
}

func wsURLFromAdvertise(advertise string) string {
	advertise = strings.TrimSpace(advertise)
	if advertise == "" {
		return ""
	}
	u := strings.TrimRight(advertise, "/")
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://") + "/agent/ws"
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://") + "/agent/ws"
	default:
		return "ws://" + u + "/agent/ws"
	}
}
