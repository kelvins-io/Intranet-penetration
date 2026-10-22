package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	StartedAt      time.Time `json:"started_at"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	HTTPRequests   uint64    `json:"http_requests"`
	TCPConnections uint64    `json:"tcp_connections"`
	BytesIn        uint64    `json:"bytes_in"`
	BytesOut       uint64    `json:"bytes_out"`
	E2EStreams     uint64    `json:"e2e_streams"`
	AgentConnects  uint64    `json:"agent_connects"`
	Availability   float64   `json:"availability_pct"`
}

type Collector struct {
	started time.Time
	httpReq atomic.Uint64
	tcpConn atomic.Uint64
	bytesIn atomic.Uint64
	bytesOut atomic.Uint64
	e2e     atomic.Uint64
	agents  atomic.Uint64
	mu      sync.Mutex
	downFor time.Duration
}

func New() *Collector {
	return &Collector{started: time.Now().UTC()}
}

func (c *Collector) IncHTTP()            { c.httpReq.Add(1) }
func (c *Collector) IncTCP()             { c.tcpConn.Add(1) }
func (c *Collector) AddBytes(in, out int64) {
	if in > 0 {
		c.bytesIn.Add(uint64(in))
	}
	if out > 0 {
		c.bytesOut.Add(uint64(out))
	}
}
func (c *Collector) IncE2E()    { c.e2e.Add(1) }
func (c *Collector) IncAgent()  { c.agents.Add(1) }

func (c *Collector) Snapshot() Snapshot {
	up := time.Since(c.started)
	avail := 100.0
	c.mu.Lock()
	down := c.downFor
	c.mu.Unlock()
	if up > 0 && down > 0 {
		avail = 100 * (1 - float64(down)/float64(up))
		if avail < 0 {
			avail = 0
		}
	}
	return Snapshot{
		StartedAt:      c.started,
		UptimeSeconds:  int64(up.Seconds()),
		HTTPRequests:   c.httpReq.Load(),
		TCPConnections: c.tcpConn.Load(),
		BytesIn:        c.bytesIn.Load(),
		BytesOut:       c.bytesOut.Load(),
		E2EStreams:     c.e2e.Load(),
		AgentConnects:  c.agents.Load(),
		Availability:   avail,
	}
}
