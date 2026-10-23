package cluster

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisTunnelPrefix = "ip:tunnel:"
	redisDomainPrefix = "ip:domain:"
	redisEdgePrefix   = "ip:edge:"
	redisTTL          = 90 * time.Second
)

type RedisRegistry struct {
	rdb *redis.Client
}

func NewRedis(redisURL string) (*RedisRegistry, error) {
	rdb, err := DialRedis(redisURL)
	if err != nil {
		return nil, err
	}
	return NewRedisWithClient(rdb), nil
}

func (r *RedisRegistry) Put(loc TunnelLocation) error {
	ctx := context.Background()
	loc.UpdatedAt = time.Now().UTC()
	b, err := json.Marshal(loc)
	if err != nil {
		return err
	}
	k := redisTunnelPrefix + key(loc.TenantID, loc.TunnelName)
	pipe := r.rdb.Pipeline()
	pipe.Set(ctx, k, b, redisTTL)
	if loc.Domain != "" {
		pipe.Set(ctx, redisDomainPrefix+strings.ToLower(loc.Domain), k, redisTTL)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisRegistry) Get(tenantID, name string) (*TunnelLocation, bool) {
	ctx := context.Background()
	b, err := r.rdb.Get(ctx, redisTunnelPrefix+key(tenantID, name)).Bytes()
	if err != nil {
		return nil, false
	}
	var loc TunnelLocation
	if err := json.Unmarshal(b, &loc); err != nil {
		return nil, false
	}
	return &loc, true
}

func (r *RedisRegistry) GetByDomain(domain string) (*TunnelLocation, bool) {
	ctx := context.Background()
	k, err := r.rdb.Get(ctx, redisDomainPrefix+strings.ToLower(domain)).Result()
	if err != nil {
		return nil, false
	}
	b, err := r.rdb.Get(ctx, k).Bytes()
	if err != nil {
		return nil, false
	}
	var loc TunnelLocation
	if err := json.Unmarshal(b, &loc); err != nil {
		return nil, false
	}
	return &loc, true
}

func (r *RedisRegistry) DeleteAgent(tenantID, agentID string) error {
	ctx := context.Background()
	var cursor uint64
	for {
		keys, next, err := r.rdb.Scan(ctx, cursor, redisTunnelPrefix+tenantID+"/*", 100).Result()
		if err != nil {
			return err
		}
		for _, k := range keys {
			b, err := r.rdb.Get(ctx, k).Bytes()
			if err != nil {
				continue
			}
			var loc TunnelLocation
			if json.Unmarshal(b, &loc) != nil {
				continue
			}
			if loc.AgentID != agentID {
				continue
			}
			_ = r.rdb.Del(ctx, k).Err()
			if loc.Domain != "" {
				_ = r.rdb.Del(ctx, redisDomainPrefix+strings.ToLower(loc.Domain)).Err()
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (r *RedisRegistry) Heartbeat(edgeID, advertiseHTTP, region string) error {
	ctx := context.Background()
	info := EdgeInfo{ID: edgeID, AdvertiseHTTP: advertiseHTTP, Region: region, LastSeen: time.Now().UTC()}
	b, _ := json.Marshal(info)
	return r.rdb.Set(ctx, redisEdgePrefix+edgeID, b, redisTTL).Err()
}

func (r *RedisRegistry) ListEdges() []EdgeInfo {
	ctx := context.Background()
	keys, _ := r.rdb.Keys(ctx, redisEdgePrefix+"*").Result()
	out := []EdgeInfo{}
	for _, k := range keys {
		b, err := r.rdb.Get(ctx, k).Bytes()
		if err != nil {
			continue
		}
		var e EdgeInfo
		if json.Unmarshal(b, &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func (r *RedisRegistry) ListTunnels() []TunnelLocation {
	ctx := context.Background()
	keys, _ := r.rdb.Keys(ctx, redisTunnelPrefix+"*").Result()
	out := []TunnelLocation{}
	for _, k := range keys {
		b, err := r.rdb.Get(ctx, k).Bytes()
		if err != nil {
			continue
		}
		var loc TunnelLocation
		if json.Unmarshal(b, &loc) == nil {
			out = append(out, loc)
		}
	}
	return out
}

func (r *RedisRegistry) Close() error {
	return r.rdb.Close()
}

// RefreshTTL re-puts all tunnels for an edge (called periodically by owning edge).
func (r *RedisRegistry) Touch(loc TunnelLocation) error {
	return r.Put(loc)
}
