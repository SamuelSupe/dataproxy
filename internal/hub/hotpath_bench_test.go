package hub

import (
	"context"
	"net"
	"testing"
	"time"

	"dataproxy/pkg/protocol"
)

type fakeHealthyStreamMux struct{}

func (*fakeHealthyStreamMux) OpenStream() (net.Conn, error)                       { return nil, nil }
func (*fakeHealthyStreamMux) OpenStreamContext(context.Context) (net.Conn, error) { return nil, nil }
func (*fakeHealthyStreamMux) AcceptStream() (net.Conn, error) { return nil, nil }
func (*fakeHealthyStreamMux) Ping() (time.Duration, error)    { return 0, nil }
func (*fakeHealthyStreamMux) IsClosed() bool                  { return false }
func (*fakeHealthyStreamMux) Close() error                    { return nil }

func BenchmarkParseVirtualTarget_Lowercase(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		t, s, err := ParseVirtualTarget("mysql-orders.tenant-acme.dataproxy.internal:3306", "dataproxy.internal")
		if err != nil || t != "tenant-acme" || s != "mysql-orders" {
			b.Fatalf("unexpected parse: t=%q s=%q err=%v", t, s, err)
		}
	}
}

func BenchmarkNewTraceID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if id := newTraceID(); len(id) != 16 {
			b.Fatalf("bad id %q", id)
		}
	}
}

func BenchmarkRegistry_SelectCandidates_4Lanes(b *testing.B) {
	r := NewRegistry(5 * time.Second)
	svcs := map[string]protocol.ServiceAnnouncement{
		"pg": {Name: "pg", Protocol: protocol.ProtocolTCP},
	}
	// Populate 1 control lane + 3 data lanes via stub closed-false mux.
	stub := &fakeHealthyStreamMux{}
	for lane := 0; lane < 4; lane++ {
		role := "data"
		if lane == 0 {
			role = "control"
		}
		_ = r.Register(&AgentSession{
			SessionID: "sess_" + string(rune('a'+lane)),
			TenantID:  "tenant-bench",
			AgentID:   "agent-1",
			PoolLane:  lane,
			Role:      role,
			Services:  svcs,
			mux:       stub,
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cands, ok := r.selectCandidates("tenant-bench", "pg", protocol.ProtocolTCP, false)
		if !ok || len(cands) != 3 {
			b.Fatalf("unexpected cands: ok=%v len=%d", ok, len(cands))
		}
	}
}

func BenchmarkEnsureTraceparent_Valid(b *testing.B) {
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got := ensureTraceparent(tp); got != tp {
			b.Fatalf("unexpected traceparent %q", got)
		}
	}
}

func BenchmarkEnsureTraceparent_Generate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got := ensureTraceparent(""); len(got) != 55 {
			b.Fatalf("unexpected generated traceparent %q", got)
		}
	}
}

func TestIPRateLimiter_BoundedMemoryUnderIPFlood(t *testing.T) {
	lim := NewIPRateLimiter(60, 5)
	for i := 0; i < maxRateLimitEntries+2000; i++ {
		addr := string([]byte{
			byte('a' + (i/10000)%26),
			byte('a' + (i/1000)%26),
			byte('a' + (i/100)%26),
			byte('a' + (i/10)%26),
			byte('a' + i%26),
		})
		lim.Allow(addr)
	}
	lim.mu.Lock()
	n := len(lim.buckets)
	lim.mu.Unlock()
	if n > maxRateLimitEntries {
		t.Fatalf("expected rate limiter buckets <= %d, got %d", maxRateLimitEntries, n)
	}
}
