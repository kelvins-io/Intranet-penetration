package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProbeAvailability(t *testing.T) {
	c := New()
	for i := 0; i < 10; i++ {
		c.RecordProbe(true, 5*time.Millisecond)
	}
	c.RecordProbe(false, 20*time.Millisecond)
	s := c.Snapshot()
	if s.AvailabilitySource != "synthetic_probe_window" {
		t.Fatalf("source %s", s.AvailabilitySource)
	}
	if s.Availability < 80 || s.Availability > 95 {
		t.Fatalf("availability %v", s.Availability)
	}
	var buf bytes.Buffer
	c.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), "ip_availability_pct") {
		t.Fatal("missing prometheus metric")
	}
}
