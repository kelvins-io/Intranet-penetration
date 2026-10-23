package cluster

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DialRedis parses redisURL and pings. Caller owns Close.
func DialRedis(redisURL string) (*redis.Client, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return rdb, nil
}

// Redis returns the underlying client (nil for memory registry).
func (r *RedisRegistry) Redis() *redis.Client {
	return r.rdb
}

// NewRedisWithClient wraps an existing client (shared with resume/store HA).
func NewRedisWithClient(rdb *redis.Client) *RedisRegistry {
	return &RedisRegistry{rdb: rdb}
}
