package hub

import (
	"math"
	"net"
	"sync"
	"time"
)

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

// IPRateLimiter enforces per-source-IP token-bucket rate limiting on public tunnel
// handshake and device enrollment endpoints to prevent reconnect storms and CPU DoS.
type IPRateLimiter struct {
	ratePerSec float64
	burst      float64

	mu      sync.Mutex
	buckets map[string]*ipBucket
	ops     uint64
}

// NewIPRateLimiter creates a per-IP limiter. ratePerMin <= 0 disables limiting.
func NewIPRateLimiter(ratePerMin float64, burst int) *IPRateLimiter {
	if ratePerMin <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = int(math.Ceil(ratePerMin / 6.0))
		if burst < 5 {
			burst = 5
		}
	}
	return &IPRateLimiter{
		ratePerSec: ratePerMin / 60.0,
		burst:      float64(burst),
		buckets:    make(map[string]*ipBucket),
	}
}

// Allow consumes one token for remoteAddr (host:port or bare IP) and reports whether allowed.
func (l *IPRateLimiter) Allow(remoteAddr string) bool {
	if l == nil || l.ratePerSec <= 0 {
		return true
	}
	ip := extractIP(remoteAddr)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.ops++
	if l.ops%1024 == 0 && len(l.buckets) > 1024 {
		cutoff := now.Add(-10 * time.Minute)
		for k, b := range l.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{
			tokens:   l.burst,
			lastSeen: now,
		}
		l.buckets[ip] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.ratePerSec
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
		}
		b.lastSeen = now
	}

	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}
