package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	count   int
	resetAt time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
}

func New() *Limiter {
	return &Limiter{buckets: map[string]bucket{}}
}

func (l *Limiter) Allow(key string, limit int, window time.Duration) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, exists := l.buckets[key]
	if !exists || !b.resetAt.After(now) {
		l.buckets[key] = bucket{count: 1, resetAt: now.Add(window)}
		return true, 0
	}
	if b.count >= limit {
		return false, time.Until(b.resetAt)
	}
	b.count++
	l.buckets[key] = b
	return true, 0
}
