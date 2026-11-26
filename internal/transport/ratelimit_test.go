package transport

import (
	"testing"
	"time"
)

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"unlimited", 0},
		{"20MB/s", 20_000_000},
		{"512KB/s", 512_000},
		{"1MiB/s", 1024 * 1024},
		{"80Mbps", 10_000_000},
		{"65536", 65536},
	}
	for _, tc := range cases {
		got, err := ParseBandwidth(tc.in)
		if err != nil {
			t.Fatalf("ParseBandwidth(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseBandwidth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if _, err := ParseBandwidth("not-a-rate"); err == nil {
		t.Fatalf("expected error for invalid bandwidth string")
	}
}

func TestBandwidthLimiterPacing(t *testing.T) {
	// 200 KB/s limit with ~50KB initial burst; transferring 150KB should take ~0.4s-0.6s.
	lim := NewBandwidthLimiter(200_000)
	start := time.Now()
	for i := 0; i < 15; i++ {
		lim.Wait(10_000)
	}
	elapsed := time.Since(start)
	if elapsed < 350*time.Millisecond {
		t.Fatalf("expected rate limiting delay >= 350ms, got %v", elapsed)
	}
}
