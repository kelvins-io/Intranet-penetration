package server

import (
	"context"
	"net/http"
	"time"
)

// startProbeLoop runs synthetic health probes against the local gateway for SLA.
func (s *Server) startProbeLoop(ctx context.Context) {
	interval := s.cfg.ProbeInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	base := s.cfg.Cluster.AdvertiseHTTP
	if base == "" {
		if s.cfg.IsEdge() && s.cfg.HTTPGateway != "" {
			base = "http://127.0.0.1" + normalizeListenAddr(s.cfg.HTTPGateway)
		} else if s.cfg.APIListen != "" {
			base = "http://127.0.0.1" + normalizeListenAddr(s.cfg.APIListen)
		} else {
			base = "http://127.0.0.1" + normalizeListenAddr(s.cfg.HTTPGateway)
		}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		// Immediate first sample so SLA is probe-backed quickly.
		s.runProbe(client, base)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runProbe(client, base)
			}
		}
	}()
}

func (s *Server) runProbe(client *http.Client, base string) {
	url := stringsTrimRightSlash(base) + "/healthz"
	start := time.Now()
	resp, err := client.Get(url)
	lat := time.Since(start)
	ok := err == nil && resp != nil && resp.StatusCode == http.StatusOK
	if resp != nil {
		_ = resp.Body.Close()
	}
	s.metrics.RecordProbe(ok, lat)
	if !ok {
		s.log.Debug("sla probe failed", "url", url, "err", err, "latency", lat)
	}
}

func normalizeListenAddr(addr string) string {
	if addr == "" {
		return ":8088"
	}
	if addr[0] == ':' {
		return addr
	}
	return ":" + addr
}

func stringsTrimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
