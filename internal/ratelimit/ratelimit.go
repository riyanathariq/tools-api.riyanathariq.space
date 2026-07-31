package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Limiter struct {
	rdb *redis.Client
}

func New(rdb *redis.Client) *Limiter {
	return &Limiter{rdb: rdb}
}

func ConnectValkey(ctx context.Context, url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse VALKEY_URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping valkey: %w", err)
	}
	return rdb, nil
}

// Allow implements a fixed-window counter in Valkey.
// On Valkey errors it denies (fail-closed) so abuse paths stay protected.
func (l *Limiter) Allow(key string, limit int, window time.Duration) (ok bool, retryAfter time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rk := "rl:" + key
	n, err := l.rdb.Incr(ctx, rk).Result()
	if err != nil {
		return false, time.Second
	}
	if n == 1 {
		_ = l.rdb.Expire(ctx, rk, window).Err()
	}
	if n > int64(limit) {
		ttl, err := l.rdb.TTL(ctx, rk).Result()
		if err != nil || ttl < 0 {
			return false, window
		}
		return false, ttl
	}
	return true, 0
}
