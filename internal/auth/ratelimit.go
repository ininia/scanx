package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a keyed token-bucket rate limiter (per IP, per token...).
type Limiter struct {
	mu      sync.Mutex
	every   rate.Limit
	burst   int
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewLimiter allows n events per period with the given burst.
func NewLimiter(n int, per time.Duration, burst int) *Limiter {
	return &Limiter{every: rate.Limit(float64(n) / per.Seconds()), burst: burst, buckets: map[string]*bucket{}}
}

// Allow reports whether an event for key may happen now.
func (l *Limiter) Allow(key string) bool {
	return l.AllowAt(key, time.Now())
}

// AllowAt is Allow with an explicit clock (tests).
func (l *Limiter) AllowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.seen) > 30*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(l.every, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}
