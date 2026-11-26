package hub

import (
	"fmt"
	"io"
	"math"
	"sync/atomic"
)

// DefaultLatencyBuckets covers 1ms through 10s for stream open and tunnel RTT histograms.
var DefaultLatencyBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

// Histogram is a zero-dependency, lock-free Prometheus-compatible latency histogram.
type Histogram struct {
	bounds    []float64
	buckets   []atomic.Uint64
	total     atomic.Uint64
	sumMicros atomic.Int64
}

// NewHistogram creates a lock-free histogram with the provided upper bounds in seconds.
func NewHistogram(bounds []float64) *Histogram {
	if len(bounds) == 0 {
		bounds = DefaultLatencyBuckets
	}
	cp := append([]float64(nil), bounds...)
	return &Histogram{
		bounds:  cp,
		buckets: make([]atomic.Uint64, len(cp)),
	}
}

// Observe records a latency sample in seconds.
func (h *Histogram) Observe(seconds float64) {
	if h == nil || math.IsNaN(seconds) || seconds < 0 {
		return
	}
	for i, b := range h.bounds {
		if seconds <= b {
			h.buckets[i].Add(1)
		}
	}
	h.total.Add(1)
	h.sumMicros.Add(int64(seconds * 1e6))
}

// Count returns total observations recorded.
func (h *Histogram) Count() uint64 {
	if h == nil {
		return 0
	}
	return h.total.Load()
}

// WritePrometheus writes the histogram in standard Prometheus text exposition format.
func (h *Histogram) WritePrometheus(w io.Writer, name, help string) {
	if h == nil {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	for i, b := range h.bounds {
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, b, h.buckets[i].Load())
	}
	total := h.total.Load()
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, total)
	fmt.Fprintf(w, "%s_sum %.6f\n", name, float64(h.sumMicros.Load())/1e6)
	fmt.Fprintf(w, "%s_count %d\n", name, total)
}

// Metrics aggregates hub-wide latency histograms and operational counters.
type Metrics struct {
	StreamOpenDuration    *Histogram
	TunnelRTT             *Histogram
	MeshForwardedStreams  atomic.Int64
	QuotaRejectedStreams  atomic.Int64
	RateLimitedHandshakes atomic.Int64
}

// NewMetrics constructs a hub Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		StreamOpenDuration: NewHistogram(DefaultLatencyBuckets),
		TunnelRTT:          NewHistogram(DefaultLatencyBuckets),
	}
}
