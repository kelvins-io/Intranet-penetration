package resume

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kelvins-io/Intranet-penetration/internal/protocol"
	"github.com/redis/go-redis/v9"
)

const (
	redisTokPrefix   = "ip:resume:tok:"
	redisAgentPrefix = "ip:resume:agent:"
)

// RedisStore shares resume tokens across Edge processes via Redis.
type RedisStore struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewRedis(rdb *redis.Client, ttl time.Duration) *RedisStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &RedisStore{rdb: rdb, ttl: ttl}
}

var _ Backend = (*RedisStore)(nil)

func (s *RedisStore) Issue(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string {
	ctx := context.Background()
	ak := redisAgentPrefix + agentKey(tenantID, agentID)
	if old, err := s.rdb.Get(ctx, ak).Result(); err == nil && old != "" {
		_ = s.rdb.Del(ctx, redisTokPrefix+old).Err()
	}
	tok := newToken()
	st := State{
		Token:     tok,
		TenantID:  tenantID,
		AgentID:   agentID,
		Tunnels:   append([]protocol.AssignedTunnel(nil), tunnels...),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}
	b, _ := json.Marshal(st)
	pipe := s.rdb.Pipeline()
	pipe.Set(ctx, redisTokPrefix+tok, b, s.ttl)
	pipe.Set(ctx, ak, tok, s.ttl)
	_, _ = pipe.Exec(ctx)
	return tok
}

func (s *RedisStore) KeepAlive(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string {
	ctx := context.Background()
	ak := redisAgentPrefix + agentKey(tenantID, agentID)
	tok, err := s.rdb.Get(ctx, ak).Result()
	if err == nil && tok != "" {
		if st, ok := s.Lookup(tok); ok {
			st.Tunnels = append([]protocol.AssignedTunnel(nil), tunnels...)
			st.ExpiresAt = time.Now().UTC().Add(s.ttl)
			b, _ := json.Marshal(st)
			pipe := s.rdb.Pipeline()
			pipe.Set(ctx, redisTokPrefix+tok, b, s.ttl)
			pipe.Expire(ctx, ak, s.ttl)
			_, _ = pipe.Exec(ctx)
			return tok
		}
	}
	return s.Issue(tenantID, agentID, tunnels)
}

func (s *RedisStore) Lookup(token string) (*State, bool) {
	ctx := context.Background()
	b, err := s.rdb.Get(ctx, redisTokPrefix+token).Bytes()
	if err != nil {
		return nil, false
	}
	var st State
	if json.Unmarshal(b, &st) != nil {
		return nil, false
	}
	if time.Now().After(st.ExpiresAt) {
		return nil, false
	}
	st.Tunnels = append([]protocol.AssignedTunnel(nil), st.Tunnels...)
	return &st, true
}

func (s *RedisStore) Consume(token string) (*State, bool) {
	ctx := context.Background()
	st, ok := s.Lookup(token)
	if !ok {
		return nil, false
	}
	pipe := s.rdb.Pipeline()
	pipe.Del(ctx, redisTokPrefix+token)
	pipe.Del(ctx, redisAgentPrefix+agentKey(st.TenantID, st.AgentID))
	_, _ = pipe.Exec(ctx)
	return st, true
}

func (s *RedisStore) SoftHold(tenantID, agentID string, tunnels []protocol.AssignedTunnel) string {
	return s.KeepAlive(tenantID, agentID, tunnels)
}
