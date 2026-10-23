package server

import (
	"testing"

	"github.com/kelvins-io/Intranet-penetration/internal/cluster"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
)

func TestWSURLFromAdvertise(t *testing.T) {
	if got := wsURLFromAdvertise("http://edge.example:8088"); got != "ws://edge.example:8088/agent/ws" {
		t.Fatalf("got %s", got)
	}
	if got := wsURLFromAdvertise("https://edge.example"); got != "wss://edge.example/agent/ws" {
		t.Fatalf("got %s", got)
	}
}

func TestRecommendPrefersMatchingRegion(t *testing.T) {
	s := &Server{
		cfg: &config.ServerConfig{
			EdgeID: "edge-local",
			Region: "local",
			Listen: ":7700",
			QUICListen: ":7700",
			Cluster: config.ClusterConfig{AdvertiseHTTP: "http://127.0.0.1:8088"},
		},
		cluster: cluster.NewMemory(),
	}
	_ = s.cluster.Heartbeat("edge-east", "http://east:8088", "cn-east")
	_ = s.cluster.Heartbeat("edge-local", "http://127.0.0.1:8088", "local")

	rec := s.recommendRegion("cn-east")
	if rec.Region != "cn-east" || rec.EdgeID != "edge-east" {
		t.Fatalf("expected cn-east/edge-east, got %#v", rec)
	}
}
