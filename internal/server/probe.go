package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/trace"
)

// startProbeLoop runs synthetic health + optional path probes for SLA.
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
	client := &http.Client{Timeout: 8 * time.Second}
	go func() {
		s.runProbes(client, base)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runProbes(client, base)
			}
		}
	}()
}

func (s *Server) runProbes(client *http.Client, base string) {
	s.runHealthProbe(client, base)
	if path := strings.TrimSpace(s.cfg.ProbePath); path != "" {
		s.runPathProbe(client, base, path)
	}
}

func (s *Server) runHealthProbe(client *http.Client, base string) {
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
		s.log.Debug("sla probe failed", "kind", "healthz", "url", url, "err", err, "latency", lat)
	}
}

func (s *Server) runPathProbe(client *http.Client, base, path string) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := stringsTrimRightSlash(base) + path
	sp, _ := trace.Start(context.Background(), "probe.path")
	sp.Attrs["url"] = url
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		s.metrics.RecordPathProbe(false, 0)
		sp.End(s.log, err)
		return
	}
	req.Header.Set("X-Request-ID", sp.TraceID)
	req.Header.Set("User-Agent", "ip-sla-probe/1")
	resp, err := client.Do(req)
	lat := time.Since(start)
	ok := false
	if err == nil && resp != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		// Path may 401 under access policy; treat 2xx/3xx/401/403 as "reachable".
		ok = resp.StatusCode < 500
	}
	s.metrics.RecordPathProbe(ok, lat)
	sp.Attrs["ok"] = formatBool(ok)
	sp.End(s.log, err)
	if !ok {
		s.log.Debug("sla path probe failed", "url", url, "err", err, "latency", lat)
	}
}

func formatBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
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
