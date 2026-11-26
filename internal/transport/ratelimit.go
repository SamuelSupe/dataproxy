package transport

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BandwidthLimiter implements a thread-safe token bucket rate limiter in bytes/sec.
// A nil limiter or rate <= 0 imposes no limit.
type BandwidthLimiter struct {
	mu          sync.Mutex
	rate        float64 // bytes per second
	burst       float64 // max token accumulation
	tokens      float64
	lastUpdated time.Time
}

// NewBandwidthLimiter constructs a token bucket limiter for bytesPerSec.
// Returns nil if bytesPerSec <= 0 (unlimited).
func NewBandwidthLimiter(bytesPerSec int64) *BandwidthLimiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := float64(bytesPerSec) / 4.0 // 250ms burst window for smooth pacing
	if burst < 16*1024 {
		burst = 16 * 1024
	}
	if burst > float64(bytesPerSec) {
		burst = float64(bytesPerSec)
	}
	return &BandwidthLimiter{
		rate:        float64(bytesPerSec),
		burst:       burst,
		tokens:      burst,
		lastUpdated: time.Now(),
	}
}

// RateBytesPerSec returns the configured byte/s limit.
func (l *BandwidthLimiter) RateBytesPerSec() int64 {
	if l == nil {
		return 0
	}
	return int64(l.rate)
}

// Wait blocks until n bytes of quota are available.
func (l *BandwidthLimiter) Wait(n int) {
	_ = l.WaitCancel(n, nil)
}

// WaitCancel blocks until n bytes of quota are available or cancelCh is closed.
// Returns false if aborted early via cancelCh so closing a throttled connection
// never leaves blocked goroutines hanging in sleep.
func (l *BandwidthLimiter) WaitCancel(n int, cancelCh <-chan struct{}) bool {
	if l == nil || n <= 0 {
		return true
	}
	remaining := float64(n)
	for remaining > 0 {
		chunk := remaining
		if chunk > l.burst {
			chunk = l.burst
		}
		if !l.waitChunk(chunk, cancelCh) {
			return false
		}
		remaining -= chunk
	}
	return true
}

func (l *BandwidthLimiter) waitChunk(want float64, cancelCh <-chan struct{}) bool {
	l.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(l.lastUpdated).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.lastUpdated = now
	}

	l.tokens -= want
	var sleepDur time.Duration
	if l.tokens < 0 {
		sleepSec := (-l.tokens) / l.rate
		sleepDur = time.Duration(sleepSec * float64(time.Second))
	}
	l.mu.Unlock()

	if sleepDur <= 0 {
		return true
	}
	if cancelCh == nil {
		time.Sleep(sleepDur)
		return true
	}
	timer := time.NewTimer(sleepDur)
	select {
	case <-timer.C:
		return true
	case <-cancelCh:
		timer.Stop()
		return false
	}
}

// ParseBandwidth parses human-readable bandwidth expressions into bytes per second.
// Examples: "20MB/s", "512KB/s", "10MiB/s", "100Mbps", "1048576", "" (unlimited).
func ParseBandwidth(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" || raw == "0" || strings.EqualFold(raw, "unlimited") {
		return 0, nil
	}

	lower := strings.ToLower(raw)
	type unit struct {
		suffix string
		mult   float64
	}
	units := []unit{
		{"gib/s", 1024 * 1024 * 1024},
		{"mib/s", 1024 * 1024},
		{"kib/s", 1024},
		{"gb/s", 1000 * 1000 * 1000},
		{"mb/s", 1000 * 1000},
		{"kb/s", 1000},
		{"gbps", 1000 * 1000 * 1000 / 8.0},
		{"mbps", 1000 * 1000 / 8.0},
		{"kbps", 1000 / 8.0},
		{"b/s", 1},
		{"gb", 1000 * 1000 * 1000},
		{"mb", 1000 * 1000},
		{"kb", 1000},
	}

	for _, u := range units {
		if strings.HasSuffix(lower, u.suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(lower, u.suffix))
			val, err := strconv.ParseFloat(numStr, 64)
			if err != nil || val < 0 {
				return 0, fmt.Errorf("invalid bandwidth %q", s)
			}
			return int64(val * u.mult), nil
		}
	}

	val, err := strconv.ParseInt(lower, 10, 64)
	if err != nil || val < 0 {
		return 0, fmt.Errorf("invalid bandwidth %q (examples: 20MB/s, 512KB/s, 100Mbps)", s)
	}
	return val, nil
}

// RateLimitedConn wraps a net.Conn and enforces one or more BandwidthLimiters on Read and Write,
// supporting immediate abort of any in-flight rate wait when Close() is called.
type RateLimitedConn struct {
	net.Conn
	readLimiters  []*BandwidthLimiter
	writeLimiters []*BandwidthLimiter
	closedCh      chan struct{}
	closeOnce     sync.Once
}

// WrapConnWithLimiters returns conn wrapped with optional read and write limiters.
// If all limiters are nil, conn is returned unwrapped.
func WrapConnWithLimiters(conn net.Conn, readLimiters, writeLimiters []*BandwidthLimiter) net.Conn {
	var rl, wl []*BandwidthLimiter
	for _, l := range readLimiters {
		if l != nil {
			rl = append(rl, l)
		}
	}
	for _, l := range writeLimiters {
		if l != nil {
			wl = append(wl, l)
		}
	}
	if len(rl) == 0 && len(wl) == 0 {
		return conn
	}
	return &RateLimitedConn{
		Conn:          conn,
		readLimiters:  rl,
		writeLimiters: wl,
		closedCh:      make(chan struct{}),
	}
}

func (c *RateLimitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		for _, l := range c.readLimiters {
			if !l.WaitCancel(n, c.closedCh) {
				return n, net.ErrClosed
			}
		}
	}
	return n, err
}

func (c *RateLimitedConn) Write(p []byte) (int, error) {
	if len(c.writeLimiters) == 0 {
		return c.Conn.Write(p)
	}
	const chunkSize = 32 * 1024
	total := 0
	for total < len(p) {
		end := total + chunkSize
		if end > len(p) {
			end = len(p)
		}
		n, err := c.Conn.Write(p[total:end])
		if n > 0 {
			total += n
			for _, l := range c.writeLimiters {
				if !l.WaitCancel(n, c.closedCh) {
					return total, net.ErrClosed
				}
			}
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (c *RateLimitedConn) Close() error {
	c.closeOnce.Do(func() { close(c.closedCh) })
	return c.Conn.Close()
}

func (c *RateLimitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// IdleTimeoutConn wraps a net.Conn and lazily refreshes read/write deadlines
// (at most once per refreshInterval = min(timeout/4, 1s)) so high-throughput
// database streams avoid per-packet netpoll timer lock contention while still
// reclaiming orphaned idle sessions promptly.
type IdleTimeoutConn struct {
	net.Conn
	timeout           time.Duration
	refreshIntervalNs int64
	lastReadSetNs     atomic.Int64
	lastWriteSetNs    atomic.Int64
}

// WrapConnWithIdleTimeout wraps conn if timeout > 0; otherwise returns conn as-is.
func WrapConnWithIdleTimeout(conn net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return conn
	}
	refresh := timeout / 4
	if refresh > time.Second {
		refresh = time.Second
	}
	return &IdleTimeoutConn{
		Conn:              conn,
		timeout:           timeout,
		refreshIntervalNs: refresh.Nanoseconds(),
	}
}

func (c *IdleTimeoutConn) maybeRefreshReadDeadline() {
	now := time.Now()
	nowNs := now.UnixNano()
	prev := c.lastReadSetNs.Load()
	if prev == 0 || nowNs-prev >= c.refreshIntervalNs {
		if c.lastReadSetNs.CompareAndSwap(prev, nowNs) {
			_ = c.Conn.SetReadDeadline(now.Add(c.timeout))
		}
	}
}

func (c *IdleTimeoutConn) maybeRefreshWriteDeadline() {
	now := time.Now()
	nowNs := now.UnixNano()
	prev := c.lastWriteSetNs.Load()
	if prev == 0 || nowNs-prev >= c.refreshIntervalNs {
		if c.lastWriteSetNs.CompareAndSwap(prev, nowNs) {
			_ = c.Conn.SetWriteDeadline(now.Add(c.timeout))
		}
	}
}

func (c *IdleTimeoutConn) Read(p []byte) (int, error) {
	c.maybeRefreshReadDeadline()
	return c.Conn.Read(p)
}

func (c *IdleTimeoutConn) Write(p []byte) (int, error) {
	c.maybeRefreshWriteDeadline()
	return c.Conn.Write(p)
}

func (c *IdleTimeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
