package hub

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"dataproxy/internal/transport"
)

const (
	maxMeshControlFrame = 64 * 1024
	meshRouteCacheTTL   = 30 * time.Second
	maxMeshRouteEntries = 4096
)

type cachedPeerRoute struct {
	peerAddr  string
	expiresAt time.Time
}

// PeerForwardRequest is sent from one Hub node to a peer Hub node when the target
// tenant agent is connected to a different Hub instance in the cluster.
type PeerForwardRequest struct {
	MeshSecret  string            `json:"mesh_secret"`
	SourceNode  string            `json:"source_node,omitempty"`
	TenantID    string            `json:"tenant_id"`
	ServiceName string            `json:"service_name"`
	Protocol    string            `json:"protocol"`
	CallerID    string            `json:"caller_id,omitempty"`
	TicketID    string            `json:"ticket_id,omitempty"`
	Purpose     map[string]string `json:"purpose,omitempty"`
	Traceparent string            `json:"traceparent,omitempty"`
	Hop         int               `json:"hop"`
}

// PeerForwardResponse reports whether the peer Hub located the tenant locally and opened a stream.
type PeerForwardResponse struct {
	OK         bool   `json:"ok"`
	ErrorCode  string `json:"error_code,omitempty"` // "offline", "not_found", "rejected", "quota", "auth", "loop", "other"
	RejectCode string `json:"reject_code,omitempty"`
	Message    string `json:"message,omitempty"`
}

// MeshPeer implements transparent Hub-to-Hub stream forwarding for multi-node HA Hub clusters.
// Central callers can hit ANY Hub node; if the tenant's agent is attached to a peer node,
// the stream is seamlessly bridged over the internal cluster mesh.
type MeshPeer struct {
	nodeID   string
	secret   string
	peers    []string
	registry *Registry
	metrics  *Metrics
	logger   *slog.Logger

	routeMu    sync.RWMutex
	routeCache map[string]cachedPeerRoute
}

// NewMeshPeer creates a Hub-to-Hub mesh forwarder.
func NewMeshPeer(nodeID, secret string, peers []string, registry *Registry, metrics *Metrics, logger *slog.Logger) *MeshPeer {
	if logger == nil {
		logger = slog.Default()
	}
	clean := make([]string, 0, len(peers))
	for _, p := range peers {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			clean = append(clean, trimmed)
		}
	}
	return &MeshPeer{
		nodeID:     nodeID,
		secret:     secret,
		peers:      clean,
		registry:   registry,
		metrics:    metrics,
		logger:     logger.With("component", "hub_mesh", "node_id", nodeID),
		routeCache: make(map[string]cachedPeerRoute),
	}
}

func (m *MeshPeer) orderedPeersFor(tenantID string) []string {
	if len(m.peers) <= 1 {
		return m.peers
	}
	now := time.Now()
	m.routeMu.RLock()
	entry, ok := m.routeCache[tenantID]
	m.routeMu.RUnlock()
	if !ok || now.After(entry.expiresAt) || entry.peerAddr == m.peers[0] {
		return m.peers
	}
	ordered := make([]string, 0, len(m.peers))
	ordered = append(ordered, entry.peerAddr)
	for _, p := range m.peers {
		if p != entry.peerAddr {
			ordered = append(ordered, p)
		}
	}
	return ordered
}

func (m *MeshPeer) cacheRoute(tenantID, peerAddr string) {
	now := time.Now()
	m.routeMu.Lock()
	if len(m.routeCache) >= maxMeshRouteEntries {
		for k, v := range m.routeCache {
			if now.After(v.expiresAt) {
				delete(m.routeCache, k)
			}
		}
		if len(m.routeCache) >= maxMeshRouteEntries {
			evict := maxMeshRouteEntries / 8
			for k := range m.routeCache {
				delete(m.routeCache, k)
				evict--
				if evict <= 0 {
					break
				}
			}
		}
	}
	m.routeCache[tenantID] = cachedPeerRoute{
		peerAddr:  peerAddr,
		expiresAt: now.Add(meshRouteCacheTTL),
	}
	m.routeMu.Unlock()
}

func (m *MeshPeer) evictRoute(tenantID, peerAddr string) {
	m.routeMu.Lock()
	if cur, ok := m.routeCache[tenantID]; ok && cur.peerAddr == peerAddr {
		delete(m.routeCache, tenantID)
	}
	m.routeMu.Unlock()
}

// HasPeers reports whether this Hub has configured peer nodes to forward to.
func (m *MeshPeer) HasPeers() bool {
	return m != nil && len(m.peers) > 0
}

// Serve accepts incoming Hub-to-Hub peer forwarding connections on ln.
func (m *MeshPeer) Serve(ln net.Listener) error {
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			m.logger.Warn("hub mesh accept error, backing off", "error", err)
			sleepAcceptBackoff(&tempDelay)
			continue
		}
		tempDelay = 0
		go m.handlePeerConn(conn)
	}
}

func (m *MeshPeer) handlePeerConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			m.logger.Error("recovered panic in hub mesh handler", "panic", r)
		}
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var req PeerForwardRequest
	if err := readMeshJSON(conn, &req); err != nil {
		return
	}

	if m.secret != "" && subtle.ConstantTimeCompare([]byte(req.MeshSecret), []byte(m.secret)) != 1 {
		_ = writeMeshJSON(conn, PeerForwardResponse{
			OK:        false,
			ErrorCode: "auth",
			Message:   "invalid mesh secret",
		})
		return
	}
	if req.Hop > 1 {
		_ = writeMeshJSON(conn, PeerForwardResponse{
			OK:        false,
			ErrorCode: "loop",
			Message:   "mesh hop limit exceeded",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Always open LOCALLY on the receiving peer to prevent forwarding loops.
	stream, err := m.registry.OpenLocalTenantStreamWithMeta(ctx, req.TenantID, req.ServiceName, req.Protocol, StreamMeta{
		CallerID:    req.CallerID,
		TicketID:    req.TicketID,
		Purpose:     req.Purpose,
		Traceparent: req.Traceparent,
	})
	if err != nil {
		resp := PeerForwardResponse{
			OK:        false,
			ErrorCode: "other",
			Message:   err.Error(),
		}
		var rej *StreamRejectError
		switch {
		case errors.Is(err, ErrTenantOffline):
			resp.ErrorCode = "offline"
		case errors.Is(err, ErrServiceNotFound):
			resp.ErrorCode = "not_found"
		case errors.Is(err, ErrTenantQuotaExceeded):
			resp.ErrorCode = "quota"
		case errors.As(err, &rej):
			resp.ErrorCode = "rejected"
			resp.RejectCode = rej.Code
			resp.Message = rej.Message
		}
		_ = writeMeshJSON(conn, resp)
		return
	}
	defer func() { _ = stream.Close() }()

	if err := writeMeshJSON(conn, PeerForwardResponse{OK: true}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	m.logger.Info("mesh forwarded stream accepted",
		"source_node", req.SourceNode,
		"tenant_id", req.TenantID,
		"service", req.ServiceName,
		"traceparent", req.Traceparent,
	)
	transport.BidirectionalPipe(conn, stream)
}

// ForwardStream attempts to locate the target tenant on any configured peer Hub node
// and returns a live bridged net.Conn ready for immediate raw protocol traffic.
func (m *MeshPeer) ForwardStream(
	ctx context.Context,
	tenantID, serviceName, proto string,
	meta StreamMeta,
) (net.Conn, error) {
	if !m.HasPeers() {
		return nil, fmt.Errorf("%w: %s", ErrTenantOffline, tenantID)
	}

	req := PeerForwardRequest{
		MeshSecret:  m.secret,
		SourceNode:  m.nodeID,
		TenantID:    tenantID,
		ServiceName: serviceName,
		Protocol:    proto,
		CallerID:    meta.CallerID,
		TicketID:    meta.TicketID,
		Purpose:     meta.Purpose,
		Traceparent: meta.Traceparent,
		Hop:         1,
	}

	var sawNotFound bool
	var lastErr error
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

	for _, peerAddr := range m.orderedPeersFor(tenantID) {
		conn, err := dialer.DialContext(ctx, "tcp", peerAddr)
		if err != nil {
			m.evictRoute(tenantID, peerAddr)
			lastErr = err
			continue
		}

		deadline := time.Now().Add(10 * time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetDeadline(deadline)

		if err := writeMeshJSON(conn, req); err != nil {
			_ = conn.Close()
			m.evictRoute(tenantID, peerAddr)
			lastErr = err
			continue
		}

		var resp PeerForwardResponse
		if err := readMeshJSON(conn, &resp); err != nil {
			_ = conn.Close()
			m.evictRoute(tenantID, peerAddr)
			lastErr = err
			continue
		}

		if resp.OK {
			_ = conn.SetDeadline(time.Time{})
			m.cacheRoute(tenantID, peerAddr)
			if m.metrics != nil {
				m.metrics.MeshForwardedStreams.Add(1)
			}
			m.logger.Info("mesh forwarded stream to peer hub",
				"peer", peerAddr,
				"tenant_id", tenantID,
				"service", serviceName,
			)
			return conn, nil
		}

		_ = conn.Close()
		switch resp.ErrorCode {
		case "rejected":
			m.cacheRoute(tenantID, peerAddr)
			return nil, &StreamRejectError{Code: resp.RejectCode, Message: resp.Message}
		case "quota":
			m.cacheRoute(tenantID, peerAddr)
			return nil, fmt.Errorf("%w: %s", ErrTenantQuotaExceeded, resp.Message)
		case "not_found":
			sawNotFound = true
		case "auth":
			lastErr = errors.New("hub mesh authentication failed: " + resp.Message)
		default:
			m.evictRoute(tenantID, peerAddr)
			lastErr = errors.New(resp.Message)
		}
	}

	if sawNotFound {
		return nil, fmt.Errorf("%w: tenant=%s service=%s proto=%s", ErrServiceNotFound, tenantID, serviceName, proto)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %s (mesh: %v)", ErrTenantOffline, tenantID, lastErr)
	}
	return nil, fmt.Errorf("%w: %s", ErrTenantOffline, tenantID)
}

func writeMeshJSON(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > maxMeshControlFrame {
		return errors.New("mesh control frame too large")
	}
	// Single contiguous Write call to avoid split TCP packets on mesh handshakes.
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(payload)))
	copy(buf[4:], payload)
	_, err = w.Write(buf)
	return err
}

func readMeshJSON(r io.Reader, out any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxMeshControlFrame {
		return fmt.Errorf("invalid mesh control frame size: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}
