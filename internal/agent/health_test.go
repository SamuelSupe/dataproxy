package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeServicesSanitized_ParallelAndDeterministicOrder verifies that multiple slow services
// are probed concurrently (total time ~1x single service delay instead of Nx) while keeping exact
// config order in the returned slice.
func TestProbeServicesSanitized_ParallelAndDeterministicOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(120 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	svcs := make([]ServiceConfig, 6)
	for i := range svcs {
		svcs[i] = ServiceConfig{
			Name:       fmt.Sprintf("svc-%02d", i),
			Protocol:   "http",
			TargetAddr: addr,
		}
	}

	start := time.Now()
	statuses := ProbeServicesSanitized(svcs)
	elapsed := time.Since(start)

	if len(statuses) != len(svcs) {
		t.Fatalf("expected %d statuses, got %d", len(svcs), len(statuses))
	}
	for i, st := range statuses {
		wantName := fmt.Sprintf("svc-%02d", i)
		if st.Name != wantName || !st.Healthy {
			t.Fatalf("idx %d: expected healthy %s, got %+v", i, wantName, st)
		}
	}
	// Serial execution of 6 × 120ms would take >= 720ms; parallel execution completes well under 450ms!
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("expected parallel health probe < 500ms for 6×120ms services, got %v", elapsed)
	}
}
