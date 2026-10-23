package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisSnapshotKey = "ip:store:snapshot"

type redisEnvelope struct {
	UpdatedAt time.Time `json:"updated_at"`
	Snapshot  Snapshot  `json:"snapshot"`
}

// AttachRedis enables control-plane HA: every persist dual-writes to Redis,
// and Open can hydrate from Redis when the key is newer than the local file.
func (s *Store) AttachRedis(rdb *redis.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rdb = rdb
}

// HydrateFromRedis loads snapshot from Redis if present (shared control state).
func (s *Store) HydrateFromRedis() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rdb == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := s.rdb.Get(ctx, redisSnapshotKey).Bytes()
	if err == redis.Nil {
		return nil
	}
	if err != nil {
		return err
	}
	var env redisEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("decode redis store: %w", err)
	}
	s.data = env.Snapshot
	s.redisUpdated = env.UpdatedAt
	return s.persistLocked() // refresh local cache file
}

func (s *Store) persistRedisLocked() error {
	if s.rdb == nil {
		return nil
	}
	env := redisEnvelope{UpdatedAt: time.Now().UTC(), Snapshot: s.data}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.rdb.Set(ctx, redisSnapshotKey, b, 0).Err(); err != nil {
		return err
	}
	s.redisUpdated = env.UpdatedAt
	return nil
}
