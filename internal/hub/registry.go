package hub

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

var (
	ErrTenantOffline       = errors.New("hub: tenant has no online agent sessions")
	ErrServiceNotFound     = errors.New("hub: service not exposed by any healthy agent for tenant")
	ErrStreamRejected      = errors.New("hub: agent rejected stream open request")
	ErrTenantQuotaExceeded = errors.New("hub: tenant concurrent quota exceeded")
)

// StreamRejectError carries the structured rejection code returned by the tenant agent.
type StreamRejectError struct {
	Code    string
	Message string
}

func (e *StreamRejectError) Error() string {
	return fmt.Sprintf("agent rejected stream [%s]: %s", e.Code, e.Message)
}

func (e *StreamRejectError) Unwrap() error {
	return ErrStreamRejected
}

// StreamMeta carries caller identity, short-lived job ticket ID, W3C traceparent,
// and structured business purpose propagated straight into tenant-local audit logs.
type StreamMeta struct {
	CallerID    string
	TicketID    string
	Purpose     map[string]string
	Traceparent string
}

// AgentSession represents one authenticated tenant agent tunnel connection.
type AgentSession struct {
	SessionID   string
	TenantID    string
	AgentID     string
	DeviceID    string
	PoolLane    int
	Role        string // "all", "control", or "data"
	RemoteAddr  string
	Transport   string // "wss", "quic", "tls", or "tcp"
	ConnectedAt time.Time
	Labels      map[string]string

	svcMu         sync.RWMutex
	Services      map[string]protocol.ServiceAnnouncement
	ServiceHealth []protocol.ServiceHealthStatus

	mux transport.StreamMux

	draining       atomic.Bool
	activeStreams  atomic.Int64
	totalStreams   atomic.Int64
	bytesIn        atomic.Int64 // bytes from central caller -> tenant
	bytesOut       atomic.Int64 // bytes from tenant -> central caller
	lastSeenUnix   atomic.Int64
	lastRTTMicros  atomic.Int64
	openFailCount  atomic.Int32
	openFailAtUnix atomic.Int64
}

func (s *AgentSession) isRecentlyDegraded(nowUnix int64) bool {
	return s.openFailCount.Load() > 0 && nowUnix-s.openFailAtUnix.Load() < 15
}

func (s *AgentSession) recordOpenSuccess() {
	if s.openFailCount.Load() != 0 {
		s.openFailCount.Store(0)
	}
}

func (s *AgentSession) recordOpenTransportFailure() {
	n := s.openFailCount.Add(1)
	s.openFailAtUnix.Store(time.Now().Unix())
	// After 3 consecutive transport-level stream open failures, asynchronously verify
	// session liveness and close a blackholed mux instead of waiting for full heartbeat expiry.
	if n == 3 {
		go func(sess *AgentSession) {
			if _, err := sess.mux.Ping(); err != nil {
				_ = sess.Close()
			}
		}(s)
	}
}

// MarkDraining prevents new streams from being scheduled onto this session.
func (s *AgentSession) MarkDraining() {
	s.draining.Store(true)
}

// IsHealthy reports whether the yamux session is open and not draining.
func (s *AgentSession) IsHealthy() bool {
	return !s.draining.Load() && !s.mux.IsClosed()
}

// UpdateServices atomically refreshes the session's exposed service list (on agent hot-reload).
func (s *AgentSession) UpdateServices(svcs []protocol.ServiceAnnouncement) {
	m := make(map[string]protocol.ServiceAnnouncement, len(svcs))
	for _, svc := range svcs {
		m[svc.Name] = svc
	}
	s.svcMu.Lock()
	s.Services = m
	s.svcMu.Unlock()
}

// UpdateHealth stores the latest sanitized local target health snapshot reported by the agent.
func (s *AgentSession) UpdateHealth(statuses []protocol.ServiceHealthStatus) {
	cp := append([]protocol.ServiceHealthStatus(nil), statuses...)
	s.svcMu.Lock()
	s.ServiceHealth = cp
	s.svcMu.Unlock()
}

// HasService reports whether this agent announced serviceName with a compatible protocol.
func (s *AgentSession) HasService(serviceName, reqProto string) bool {
	s.svcMu.RLock()
	svc, ok := s.Services[serviceName]
	s.svcMu.RUnlock()
	if !ok {
		return false
	}
	if svc.Protocol == protocol.ProtocolTCP && reqProto != protocol.ProtocolTCP {
		return false
	}
	return true
}

// RecordHeartbeat updates last-seen timestamp and optional RTT sample.
func (s *AgentSession) RecordHeartbeat(rtt time.Duration) {
	s.lastSeenUnix.Store(time.Now().Unix())
	s.recordOpenSuccess()
	if rtt > 0 {
		s.lastRTTMicros.Store(rtt.Microseconds())
	}
}

// Close closes the underlying yamux session.
func (s *AgentSession) Close() error {
	return s.mux.Close()
}

// SessionSnapshot is a JSON-serializable view of an AgentSession for Admin API & metrics.
type SessionSnapshot struct {
	SessionID     string                         `json:"session_id"`
	AgentID       string                         `json:"agent_id"`
	DeviceID      string                         `json:"device_id,omitempty"`
	PoolLane      int                            `json:"pool_lane"`
	Role          string                         `json:"role,omitempty"`
	RemoteAddr    string                         `json:"remote_addr"`
	Transport     string                         `json:"transport"`
	Draining      bool                           `json:"draining"`
	ConnectedAt   time.Time                      `json:"connected_at"`
	ActiveStreams int64                          `json:"active_streams"`
	TotalStreams  int64                          `json:"total_streams"`
	BytesIn       int64                          `json:"bytes_in"`
	BytesOut      int64                          `json:"bytes_out"`
	Services      []protocol.ServiceAnnouncement `json:"services"`
	ServiceHealth []protocol.ServiceHealthStatus `json:"service_health,omitempty"`
}

// TenantSnapshot aggregates all online agent replicas for a tenant.
type TenantSnapshot struct {
	TenantID string            `json:"tenant_id"`
	Sessions []SessionSnapshot `json:"sessions"`
}

// Registry tracks all active multi-tenant agent sessions and schedules outbound streams
// across healthy replicas using least-active-streams load balancing with failover,
// per-tenant concurrency quotas, and optional cross-node Hub Mesh forwarding.
type Registry struct {
	mu                   sync.RWMutex
	sessionsByTenant     map[string][]*AgentSession
	tenantActiveStreams  map[string]*atomic.Int64
	rrCounter            atomic.Uint64
	streamOpenTimeout    time.Duration
	rejectedStreams      atomic.Int64
	maxStreamsPerTenant  int
	maxSessionsPerTenant int
	metrics              *Metrics
	mesh                 *MeshPeer
}

// NewRegistry creates a new multi-tenant session registry.
func NewRegistry(streamOpenTimeout time.Duration) *Registry {
	if streamOpenTimeout <= 0 {
		streamOpenTimeout = 10 * time.Second
	}
	return &Registry{
		sessionsByTenant:    make(map[string][]*AgentSession),
		tenantActiveStreams: make(map[string]*atomic.Int64),
		streamOpenTimeout:   streamOpenTimeout,
	}
}

// SetQuotas configures Hub-side noisy-neighbor concurrency caps per tenant (0 = unlimited).
func (r *Registry) SetQuotas(maxStreamsPerTenant, maxSessionsPerTenant int) {
	r.mu.Lock()
	r.maxStreamsPerTenant = maxStreamsPerTenant
	r.maxSessionsPerTenant = maxSessionsPerTenant
	r.mu.Unlock()
}

// SetMetrics attaches Prometheus latency histograms and counters to the registry.
func (r *Registry) SetMetrics(m *Metrics) {
	r.mu.Lock()
	r.metrics = m
	r.mu.Unlock()
}

// SetMesh attaches a Hub-to-Hub cluster mesh forwarder for cross-node routing.
func (r *Registry) SetMesh(m *MeshPeer) {
	r.mu.Lock()
	r.mesh = m
	r.mu.Unlock()
}

// Register adds an authenticated AgentSession to its tenant pool and automatically
// evicts any stale half-open session with the same (DeviceID/AgentID, PoolLane)
// to prevent zombie-session blackholing while allowing multi-lane tunnel pools.
func (r *Registry) Register(sess *AgentSession) error {
	var evicted []*AgentSession
	r.mu.Lock()
	existing := r.sessionsByTenant[sess.TenantID]
	kept := make([]*AgentSession, 0, len(existing)+1)
	for _, s := range existing {
		sameInstance := (sess.DeviceID != "" && s.DeviceID == sess.DeviceID) ||
			(sess.DeviceID == "" && sess.AgentID != "" && s.AgentID == sess.AgentID)
		if sameInstance && s.PoolLane == sess.PoolLane && s.SessionID != sess.SessionID {
			evicted = append(evicted, s)
			continue
		}
		kept = append(kept, s)
	}
	if r.maxSessionsPerTenant > 0 && len(kept) >= r.maxSessionsPerTenant {
		r.mu.Unlock()
		return fmt.Errorf("%w: tenant %s reached max_sessions_per_tenant (%d)",
			ErrTenantQuotaExceeded, sess.TenantID, r.maxSessionsPerTenant)
	}
	kept = append(kept, sess)
	r.sessionsByTenant[sess.TenantID] = kept
	r.mu.Unlock()

	for _, old := range evicted {
		old.MarkDraining()
		go func(s *AgentSession) { _ = s.Close() }(old)
	}
	return nil
}

// CloseAll terminates all active agent sessions across all tenants (used during hub shutdown).
func (r *Registry) CloseAll() {
	r.mu.Lock()
	var all []*AgentSession
	for _, list := range r.sessionsByTenant {
		all = append(all, list...)
	}
	r.sessionsByTenant = make(map[string][]*AgentSession)
	r.mu.Unlock()

	for _, s := range all {
		_ = s.Close()
	}
}

// Unregister removes a session from its tenant pool.
func (r *Registry) Unregister(sess *AgentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.sessionsByTenant[sess.TenantID]
	for i, s := range list {
		if s.SessionID == sess.SessionID {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(r.sessionsByTenant, sess.TenantID)
	} else {
		r.sessionsByTenant[sess.TenantID] = list
	}
}

// CloseTenantSessions terminates all active sessions for a tenant (e.g. on token revocation).
func (r *Registry) CloseTenantSessions(tenantID string) int {
	r.mu.Lock()
	list := append([]*AgentSession(nil), r.sessionsByTenant[tenantID]...)
	delete(r.sessionsByTenant, tenantID)
	r.mu.Unlock()

	for _, s := range list {
		_ = s.Close()
	}
	return len(list)
}

// CloseDeviceSessions terminates ONLY active sessions belonging to deviceID, leaving
// all other HA agent replicas of the same tenant completely untouched.
func (r *Registry) CloseDeviceSessions(deviceID string) int {
	var toClose []*AgentSession
	r.mu.Lock()
	for tid, list := range r.sessionsByTenant {
		kept := list[:0]
		for _, s := range list {
			if s.DeviceID == deviceID {
				toClose = append(toClose, s)
			} else {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(r.sessionsByTenant, tid)
		} else {
			r.sessionsByTenant[tid] = kept
		}
	}
	r.mu.Unlock()

	for _, s := range toClose {
		_ = s.Close()
	}
	return len(toClose)
}

// OpenTenantStream locates a healthy agent session for tenantID exposing serviceName,
// opens a yamux stream, completes the exact-framed StreamOpen handshake, and returns
// a tracked net.Conn ready for immediate raw protocol passthrough.
func (r *Registry) OpenTenantStream(
	ctx context.Context,
	tenantID, serviceName, proto, callerID string,
) (net.Conn, error) {
	return r.OpenTenantStreamWithMeta(ctx, tenantID, serviceName, proto, StreamMeta{CallerID: callerID})
}

// OpenTenantStreamWithMeta opens a tenant stream propagating TicketID, W3C traceparent,
// and structured Purpose metadata. If the tenant is not locally connected and Hub Mesh
// peers are configured, it transparently forwards the stream to the peer holding the agent.
func (r *Registry) OpenTenantStreamWithMeta(
	ctx context.Context,
	tenantID, serviceName, proto string,
	meta StreamMeta,
) (net.Conn, error) {
	return r.openTenantStreamInternal(ctx, tenantID, serviceName, proto, meta, true)
}

// OpenLocalTenantStreamWithMeta opens a stream strictly against local agent sessions
// without mesh forwarding (used by MeshPeer when receiving a forwarded request).
func (r *Registry) OpenLocalTenantStreamWithMeta(
	ctx context.Context,
	tenantID, serviceName, proto string,
	meta StreamMeta,
) (net.Conn, error) {
	return r.openTenantStreamInternal(ctx, tenantID, serviceName, proto, meta, false)
}

func (r *Registry) openTenantStreamInternal(
	ctx context.Context,
	tenantID, serviceName, proto string,
	meta StreamMeta,
	allowMesh bool,
) (net.Conn, error) {
	start := time.Now()
	r.mu.RLock()
	metrics := r.metrics
	mesh := r.mesh
	r.mu.RUnlock()

	defer func() {
		if metrics != nil {
			metrics.StreamOpenDuration.Observe(time.Since(start).Seconds())
		}
	}()

	candidates, hasAnySession := r.selectCandidates(tenantID, serviceName, proto, false)
	canMesh := allowMesh && mesh != nil && mesh.HasPeers()
	if (!hasAnySession || len(candidates) == 0) && !canMesh {
		if !hasAnySession {
			return nil, fmt.Errorf("%w: %s", ErrTenantOffline, tenantID)
		}
		return nil, fmt.Errorf("%w: tenant=%s service=%s proto=%s", ErrServiceNotFound, tenantID, serviceName, proto)
	}

	slot, err := r.acquireTenantStreamSlot(tenantID, metrics)
	if err != nil {
		return nil, err
	}

	if !hasAnySession || len(candidates) == 0 {
		conn, meshErr := mesh.ForwardStream(ctx, tenantID, serviceName, proto, meta)
		if meshErr == nil {
			if slot != nil {
				return &quotaTrackedConn{Conn: conn, slot: slot}, nil
			}
			return conn, nil
		}
		if slot != nil {
			slot.Add(-1)
		}
		return nil, meshErr
	}

	conn, err := r.dialCandidates(ctx, candidates, serviceName, proto, meta)
	if err != nil {
		if slot != nil {
			slot.Add(-1)
		}
		return nil, err
	}
	if slot != nil {
		return &quotaTrackedConn{Conn: conn, slot: slot}, nil
	}
	return conn, nil
}

func (r *Registry) acquireTenantStreamSlot(tenantID string, metrics *Metrics) (*atomic.Int64, error) {
	r.mu.RLock()
	limit := r.maxStreamsPerTenant
	if limit <= 0 {
		r.mu.RUnlock()
		return nil, nil
	}
	counter := r.tenantActiveStreams[tenantID]
	r.mu.RUnlock()

	if counter == nil {
		r.mu.Lock()
		counter = r.tenantActiveStreams[tenantID]
		if counter == nil {
			// Prune idle zero-count tenant entries when map grows large to bound memory under churn.
			if len(r.tenantActiveStreams) >= 4096 {
				for tid, c := range r.tenantActiveStreams {
					if c.Load() == 0 {
						delete(r.tenantActiveStreams, tid)
					}
				}
			}
			counter = &atomic.Int64{}
			r.tenantActiveStreams[tenantID] = counter
		}
		r.mu.Unlock()
	}

	for {
		cur := counter.Load()
		if cur >= int64(limit) {
			if metrics != nil {
				metrics.QuotaRejectedStreams.Add(1)
			}
			return nil, fmt.Errorf("%w: tenant %s reached max_streams_per_tenant (%d)",
				ErrTenantQuotaExceeded, tenantID, limit)
		}
		if counter.CompareAndSwap(cur, cur+1) {
			return counter, nil
		}
	}
}

type quotaTrackedConn struct {
	net.Conn
	slot      *atomic.Int64
	closeOnce sync.Once
}

func (q *quotaTrackedConn) CloseWrite() error {
	if cw, ok := q.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return q.Close()
}

func (q *quotaTrackedConn) Close() error {
	var err error
	q.closeOnce.Do(func() {
		q.slot.Add(-1)
		err = q.Conn.Close()
	})
	return err
}

// OpenTenantStreamUnchecked bypasses Hub-side service announcement filtering and sends
// StreamOpenRequest directly to a healthy session for tenantID.
// Useful for testing defense-in-depth agent local whitelist enforcement.
func (r *Registry) OpenTenantStreamUnchecked(
	ctx context.Context,
	tenantID, serviceName, proto, callerID string,
) (net.Conn, error) {
	candidates, hasAnySession := r.selectCandidates(tenantID, serviceName, proto, true)
	if !hasAnySession || len(candidates) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrTenantOffline, tenantID)
	}
	return r.dialCandidates(ctx, candidates, serviceName, proto, StreamMeta{CallerID: callerID})
}

func (r *Registry) selectCandidates(tenantID, serviceName, proto string, ignoreServiceCheck bool) ([]*AgentSession, bool) {
	r.mu.RLock()
	list := r.sessionsByTenant[tenantID]
	if len(list) == 0 {
		r.mu.RUnlock()
		return nil, false
	}
	candidates := make([]*AgentSession, 0, len(list))
	for _, s := range list {
		if !s.IsHealthy() {
			continue
		}
		if ignoreServiceCheck || s.HasService(serviceName, proto) {
			candidates = append(candidates, s)
		}
	}
	r.mu.RUnlock()

	// Control/Data plane separation: filter in-place to keep dedicated "data"/"all" lanes
	// preferred over "control"-only lanes without allocating a second slice.
	if len(candidates) > 1 {
		nData := 0
		for _, s := range candidates {
			if s.Role != "control" {
				nData++
			}
		}
		if nData > 0 && nData < len(candidates) {
			w := 0
			for _, s := range candidates {
				if s.Role != "control" {
					candidates[w] = s
					w++
				}
			}
			candidates = candidates[:w]
		}
	}

	if len(candidates) > 1 {
		// In-place round-robin rotation + stable insertion sort placing healthy sessions
		// strictly ahead of recently failed (potentially blackholed) sessions, then by least active streams.
		n := len(candidates)
		offset := int(r.rrCounter.Add(1)) % n
		if offset > 0 {
			reverseSessions(candidates[:offset])
			reverseSessions(candidates[offset:])
			reverseSessions(candidates)
		}
		nowUnix := time.Now().Unix()
		for i := 1; i < n; i++ {
			cur := candidates[i]
			curDeg := cur.isRecentlyDegraded(nowUnix)
			curLoad := cur.activeStreams.Load()
			j := i - 1
			for j >= 0 {
				jDeg := candidates[j].isRecentlyDegraded(nowUnix)
				if jDeg == curDeg {
					if candidates[j].activeStreams.Load() <= curLoad {
						break
					}
				} else if !jDeg && curDeg {
					break
				}
				candidates[j+1] = candidates[j]
				j--
			}
			candidates[j+1] = cur
		}
	}
	return candidates, true
}

func reverseSessions(s []*AgentSession) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func (r *Registry) dialCandidates(
	ctx context.Context,
	candidates []*AgentSession,
	serviceName, proto string,
	meta StreamMeta,
) (net.Conn, error) {
	var lastErr error
	for _, sess := range candidates {
		conn, err := r.openStreamOnSession(ctx, sess, serviceName, proto, meta)
		if err == nil {
			sess.recordOpenSuccess()
			return conn, nil
		}
		lastErr = err
		if errors.Is(err, ErrStreamRejected) {
			sess.recordOpenSuccess()
			r.rejectedStreams.Add(1)
			return nil, err
		}
		sess.recordOpenTransportFailure()
	}
	return nil, lastErr
}

func (r *Registry) openStreamOnSession(
	ctx context.Context,
	sess *AgentSession,
	serviceName, proto string,
	meta StreamMeta,
) (net.Conn, error) {
	deadline := time.Now().Add(r.streamOpenTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	openCtx, cancelOpen := context.WithDeadline(ctx, deadline)
	defer cancelOpen()

	stream, err := sess.mux.OpenStreamContext(openCtx)
	if err != nil {
		return nil, fmt.Errorf("open stream on session %s: %w", sess.SessionID, err)
	}
	_ = stream.SetDeadline(deadline)

	req := protocol.StreamOpenRequest{
		TraceID:        newTraceID(),
		Traceparent:    meta.Traceparent,
		ServiceName:    serviceName,
		Protocol:       proto,
		CallerIdentity: meta.CallerID,
		TicketID:       meta.TicketID,
		Purpose:        meta.Purpose,
	}
	if err := protocol.WriteFrame(stream, protocol.FrameStreamOpenReq, req); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("write stream open req: %w", err)
	}

	var resp protocol.StreamOpenResponse
	if err := protocol.ReadTypedFrame(stream, protocol.FrameStreamOpenResp, &resp); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("read stream open resp: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})

	if !resp.OK {
		_ = stream.Close()
		return nil, &StreamRejectError{Code: resp.Code, Message: resp.Message}
	}

	sess.activeStreams.Add(1)
	sess.totalStreams.Add(1)
	return &trackedStreamConn{
		Conn: stream,
		sess: sess,
	}, nil
}

type trackedStreamConn struct {
	net.Conn
	sess      *AgentSession
	closeOnce sync.Once
}

func (t *trackedStreamConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.sess.bytesOut.Add(int64(n))
	}
	return n, err
}

func (t *trackedStreamConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.sess.bytesIn.Add(int64(n))
	}
	return n, err
}

func (t *trackedStreamConn) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return t.Close()
}

func (t *trackedStreamConn) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.sess.activeStreams.Add(-1)
		err = t.Conn.Close()
	})
	return err
}

// Snapshot returns a sorted point-in-time view of all connected tenants and their sessions.
func (r *Registry) Snapshot() []TenantSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tids := make([]string, 0, len(r.sessionsByTenant))
	for tid := range r.sessionsByTenant {
		tids = append(tids, tid)
	}
	sort.Strings(tids)

	out := make([]TenantSnapshot, 0, len(tids))
	for _, tid := range tids {
		sessions := r.sessionsByTenant[tid]
		snaps := make([]SessionSnapshot, 0, len(sessions))
		for _, s := range sessions {
			s.svcMu.RLock()
			svcs := make([]protocol.ServiceAnnouncement, 0, len(s.Services))
			for _, svc := range s.Services {
				svcs = append(svcs, svc)
			}
			healthSnap := append([]protocol.ServiceHealthStatus(nil), s.ServiceHealth...)
			s.svcMu.RUnlock()
			sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
			snaps = append(snaps, SessionSnapshot{
				SessionID:     s.SessionID,
				AgentID:       s.AgentID,
				DeviceID:      s.DeviceID,
				PoolLane:      s.PoolLane,
				Role:          s.Role,
				RemoteAddr:    s.RemoteAddr,
				Transport:     s.Transport,
				Draining:      s.draining.Load(),
				ConnectedAt:   s.ConnectedAt,
				ActiveStreams: s.activeStreams.Load(),
				TotalStreams:  s.totalStreams.Load(),
				BytesIn:       s.bytesIn.Load(),
				BytesOut:      s.bytesOut.Load(),
				Services:      svcs,
				ServiceHealth: healthSnap,
			})
		}
		out = append(out, TenantSnapshot{TenantID: tid, Sessions: snaps})
	}
	return out
}

// RejectedStreams returns total streams rejected by agents.
func (r *Registry) RejectedStreams() int64 {
	return r.rejectedStreams.Load()
}

var (
	tracePrefix = initTracePrefix()
	traceSeq    atomic.Uint32
)

func initTracePrefix() [4]byte {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return b
}

// newTraceID generates a fast, unique 16-hex-char trace ID without per-stream OS CSPRNG syscalls.
func newTraceID() string {
	var raw [8]byte
	copy(raw[0:4], tracePrefix[:])
	binary.BigEndian.PutUint32(raw[4:8], traceSeq.Add(1))
	var dst [16]byte
	hex.Encode(dst[:], raw[:])
	return string(dst[:])
}

func newShortID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
