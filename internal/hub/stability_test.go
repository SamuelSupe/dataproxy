package hub

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/pkg/protocol"
)

type blockingAcceptMux struct {
	closeOnce sync.Once
	closedCh  chan struct{}
}

func newBlockingAcceptMux() *blockingAcceptMux {
	return &blockingAcceptMux{closedCh: make(chan struct{})}
}

func (m *blockingAcceptMux) OpenStream() (net.Conn, error)                       { return nil, errors.New("unused") }
func (m *blockingAcceptMux) OpenStreamContext(context.Context) (net.Conn, error) { return nil, errors.New("unused") }
func (m *blockingAcceptMux) AcceptStream() (net.Conn, error) {
	<-m.closedCh
	return nil, net.ErrClosed
}
func (m *blockingAcceptMux) Ping() (time.Duration, error) { return 0, nil }
func (m *blockingAcceptMux) IsClosed() bool {
	select {
	case <-m.closedCh:
		return true
	default:
		return false
	}
}
func (m *blockingAcceptMux) Close() error {
	m.closeOnce.Do(func() { close(m.closedCh) })
	return nil
}

func TestTunnelServer_IdleControlStreamAcceptTimeout(t *testing.T) {
	origTimeout := ctrlStreamAcceptTimeout
	ctrlStreamAcceptTimeout = 80 * time.Millisecond
	defer func() { ctrlStreamAcceptTimeout = origTimeout }()

	tenantAuth, err := auth.NewTenantAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(5 * time.Second)
	ts := NewTunnelServer(tenantAuth, nil, reg, 15*time.Second, nil)

	mux := newBlockingAcceptMux()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ts.serveTunnelMux(mux, "198.51.100.10:5555", "quic", nil)
	}()

	select {
	case <-done:
		if !mux.IsClosed() {
			t.Fatal("expected mux to be closed after idle control stream accept timeout")
		}
	case <-time.After(1 * time.Second):
		_ = mux.Close()
		t.Fatal("serveTunnelMux hung indefinitely when peer never opened control stream #1")
	}
}

func TestHubPreAuthLimits_OversizedEnrollAndMongoRejected(t *testing.T) {
	// 1. Public /tunnel/v1/enroll must reject bodies > 64 KiB.
	dm, err := auth.NewDeviceManager("", "", time.Hour, 15*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenantAuth, err := auth.NewTenantAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := NewTunnelServer(tenantAuth, dm, NewRegistry(5*time.Second), 15*time.Second, nil)

	oversized := `{"code":"enroll_abc","csr_pem":"` + strings.Repeat("A", maxPublicControlBodyBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/tunnel/v1/enroll", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	ts.HandleDeviceEnroll(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized /tunnel/v1/enroll body, got %d", rec.Code)
	}

	// 2. Pre-auth MongoDB smart router must reject frames > 256 KiB before allocating.
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], maxHubPreAuthMongoMsgBytes+1)
	binary.LittleEndian.PutUint32(hdr[12:16], hubMongoOpMsg)
	if _, _, _, _, err := readHubMongoMsg(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("expected readHubMongoMsg to reject oversized pre-auth frame > 256KiB")
	}

	// 3. Malformed BSON with zero-length embedded document must terminate safely without looping.
	badBSON := []byte{
		16, 0, 0, 0, // docLen = 16
		0x03, 'a', 0x00, // embedded doc key "a"
		0, 0, 0, 0, // malformed subLen = 0
		0x00, 0x00, 0x00, 0x00, 0x00,
	}
	cmdName, _ := parseHubMongoBSON(badBSON)
	if cmdName != "a" {
		t.Fatalf("expected cmdName 'a', got %q", cmdName)
	}
}

func TestRegistry_DeprioritizesDegradedReplicaAndBoundsQuotaMap(t *testing.T) {
	reg := NewRegistry(5 * time.Second)
	reg.SetQuotas(10, 0)

	svcs := map[string]protocol.ServiceAnnouncement{
		"pg": {Name: "pg", Protocol: protocol.ProtocolTCP},
	}
	degraded := &AgentSession{
		SessionID: "sess-degraded",
		TenantID:  "tenant-ha",
		AgentID:   "node-a",
		PoolLane:  1,
		Role:      "data",
		Services:  svcs,
		mux:       &fakeHealthyStreamMux{},
	}
	healthy := &AgentSession{
		SessionID: "sess-healthy",
		TenantID:  "tenant-ha",
		AgentID:   "node-b",
		PoolLane:  1,
		Role:      "data",
		Services:  svcs,
		mux:       &fakeHealthyStreamMux{},
	}
	// Healthy replica is busy (5 active streams), while degraded replica has 0 active streams
	// because it recently suffered a transport open failure (blackholed).
	healthy.activeStreams.Store(5)
	degraded.recordOpenTransportFailure()

	if err := reg.Register(degraded); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(healthy); err != nil {
		t.Fatal(err)
	}

	// Across multiple round-robin rotations, healthy MUST always be tried ahead of degraded.
	for i := 0; i < 6; i++ {
		cands, ok := reg.selectCandidates("tenant-ha", "pg", protocol.ProtocolTCP, false)
		if !ok || len(cands) != 2 {
			t.Fatalf("expected 2 candidates, got %d (ok=%v)", len(cands), ok)
		}
		if cands[0].SessionID != "sess-healthy" {
			t.Fatalf("iter %d: expected healthy session first, got %s", i, cands[0].SessionID)
		}
	}

	// Querying unknown offline tenants must NOT allocate entries in tenantActiveStreams.
	for i := 0; i < 500; i++ {
		_, _ = reg.OpenTenantStream(context.Background(), "nonexistent-tenant-"+string(rune('a'+i%26))+string(rune('0'+i%10)), "pg", protocol.ProtocolTCP, "caller")
	}
	reg.mu.RLock()
	quotaMapLen := len(reg.tenantActiveStreams)
	reg.mu.RUnlock()
	if quotaMapLen != 0 {
		t.Fatalf("expected 0 tenantActiveStreams entries for offline tenants, got %d", quotaMapLen)
	}
}
