package metrics

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const probeWindow = 64

type Snapshot struct {
	StartedAt         time.Time `json:"started_at"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
	HTTPRequests      uint64    `json:"http_requests"`
	TCPConnections    uint64    `json:"tcp_connections"`
	UDPAssociations   uint64    `json:"udp_associations"`
	BytesIn           uint64    `json:"bytes_in"`
	BytesOut          uint64    `json:"bytes_out"`
	E2EStreams        uint64    `json:"e2e_streams"`
	AgentConnects     uint64    `json:"agent_connects"`
	ProbeTotal        uint64    `json:"probe_total"`
	ProbeSuccess      uint64    `json:"probe_success"`
	ProbeFail         uint64    `json:"probe_fail"`
	ProbeLatencyMsP50 float64   `json:"probe_latency_ms_p50"`
	Availability      float64   `json:"availability_pct"`
	AvailabilitySource string   `json:"availability_source"`
}

type Collector struct {
	started time.Time
	httpReq atomic.Uint64
	tcpConn atomic.Uint64
	udpAssoc atomic.Uint64
	bytesIn atomic.Uint64
	bytesOut atomic.Uint64
	e2e     atomic.Uint64
	agents  atomic.Uint64
	probeOK atomic.Uint64
	probeFail atomic.Uint64

	mu           sync.Mutex
	probeLatMs   []float64 // ring of recent latencies
	probeRing    []bool    // ring of recent success
	probeIdx     int
	probeFilled  bool
}

func New() *Collector {
	return &Collector{
		started:    time.Now().UTC(),
		probeLatMs: make([]float64, probeWindow),
		probeRing:  make([]bool, probeWindow),
	}
}

func (c *Collector) IncHTTP()   { c.httpReq.Add(1) }
func (c *Collector) IncTCP()    { c.tcpConn.Add(1) }
func (c *Collector) IncUDP()    { c.udpAssoc.Add(1) }
func (c *Collector) IncE2E()    { c.e2e.Add(1) }
func (c *Collector) IncAgent()  { c.agents.Add(1) }

func (c *Collector) AddBytes(in, out int64) {
	if in > 0 {
		c.bytesIn.Add(uint64(in))
	}
	if out > 0 {
		c.bytesOut.Add(uint64(out))
	}
}

// RecordProbe records a synthetic health probe result for SLA calculation.
func (c *Collector) RecordProbe(ok bool, latency time.Duration) {
	if ok {
		c.probeOK.Add(1)
	} else {
		c.probeFail.Add(1)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probeRing[c.probeIdx] = ok
	c.probeLatMs[c.probeIdx] = float64(latency.Milliseconds())
	c.probeIdx = (c.probeIdx + 1) % probeWindow
	if c.probeIdx == 0 {
		c.probeFilled = true
	}
}

func (c *Collector) Snapshot() Snapshot {
	up := time.Since(c.started)
	ok := c.probeOK.Load()
	fail := c.probeFail.Load()
	total := ok + fail

	c.mu.Lock()
	n := probeWindow
	if !c.probeFilled {
		n = c.probeIdx
	}
	windowOK := 0
	var latSum float64
	latN := 0
	for i := 0; i < n; i++ {
		if c.probeRing[i] {
			windowOK++
		}
		if c.probeLatMs[i] > 0 {
			latSum += c.probeLatMs[i]
			latN++
		}
	}
	c.mu.Unlock()

	avail := 100.0
	source := "uptime_fallback"
	if n > 0 {
		avail = 100 * float64(windowOK) / float64(n)
		source = "synthetic_probe_window"
	} else if total > 0 {
		avail = 100 * float64(ok) / float64(total)
		source = "synthetic_probe_lifetime"
	}
	p50 := 0.0
	if latN > 0 {
		p50 = latSum / float64(latN) // mean as cheap p50 proxy for small window
	}

	return Snapshot{
		StartedAt:          c.started,
		UptimeSeconds:      int64(up.Seconds()),
		HTTPRequests:       c.httpReq.Load(),
		TCPConnections:     c.tcpConn.Load(),
		UDPAssociations:    c.udpAssoc.Load(),
		BytesIn:            c.bytesIn.Load(),
		BytesOut:           c.bytesOut.Load(),
		E2EStreams:         c.e2e.Load(),
		AgentConnects:      c.agents.Load(),
		ProbeTotal:         total,
		ProbeSuccess:       ok,
		ProbeFail:          fail,
		ProbeLatencyMsP50:  p50,
		Availability:       avail,
		AvailabilitySource: source,
	}
}

// WritePrometheus writes a minimal Prometheus text exposition.
func (c *Collector) WritePrometheus(w io.Writer) {
	s := c.Snapshot()
	_, _ = fmt.Fprintf(w, "# HELP ip_http_requests_total Public HTTP proxy requests\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_http_requests_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_http_requests_total %d\n", s.HTTPRequests)
	_, _ = fmt.Fprintf(w, "# HELP ip_tcp_connections_total Public TCP connections\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_tcp_connections_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_tcp_connections_total %d\n", s.TCPConnections)
	_, _ = fmt.Fprintf(w, "# HELP ip_udp_associations_total Public UDP associations\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_udp_associations_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_udp_associations_total %d\n", s.UDPAssociations)
	_, _ = fmt.Fprintf(w, "# HELP ip_bytes_in_total Bytes received from public clients\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_bytes_in_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_bytes_in_total %d\n", s.BytesIn)
	_, _ = fmt.Fprintf(w, "# HELP ip_bytes_out_total Bytes sent to public clients\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_bytes_out_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_bytes_out_total %d\n", s.BytesOut)
	_, _ = fmt.Fprintf(w, "# HELP ip_agent_connects_total Agent sessions established\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_agent_connects_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_agent_connects_total %d\n", s.AgentConnects)
	_, _ = fmt.Fprintf(w, "# HELP ip_e2e_streams_total E2E sealed streams\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_e2e_streams_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_e2e_streams_total %d\n", s.E2EStreams)
	_, _ = fmt.Fprintf(w, "# HELP ip_probe_success_total Synthetic probe successes\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_probe_success_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_probe_success_total %d\n", s.ProbeSuccess)
	_, _ = fmt.Fprintf(w, "# HELP ip_probe_fail_total Synthetic probe failures\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_probe_fail_total counter\n")
	_, _ = fmt.Fprintf(w, "ip_probe_fail_total %d\n", s.ProbeFail)
	_, _ = fmt.Fprintf(w, "# HELP ip_availability_pct Rolling probe availability percent\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_availability_pct gauge\n")
	_, _ = fmt.Fprintf(w, "ip_availability_pct %g\n", s.Availability)
	_, _ = fmt.Fprintf(w, "# HELP ip_uptime_seconds Process uptime seconds\n")
	_, _ = fmt.Fprintf(w, "# TYPE ip_uptime_seconds gauge\n")
	_, _ = fmt.Fprintf(w, "ip_uptime_seconds %d\n", s.UptimeSeconds)
}
