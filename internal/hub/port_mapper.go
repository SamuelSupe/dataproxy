package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/store"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

// TCPBindingInfo is the JSON view of an active TCP port mapping on the hub.
type TCPBindingInfo struct {
	ID           string    `json:"id"`
	ListenAddr   string    `json:"listen_addr"`
	TenantID     string    `json:"tenant_id"`
	ServiceName  string    `json:"service_name"`
	AllowedCIDRs []string  `json:"allowed_cidrs,omitempty"`
	ActiveConns  int64     `json:"active_conns"`
	TotalConns   int64     `json:"total_conns"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

type tcpBinding struct {
	id           string
	listenAddr   string
	tenantID     string
	serviceName  string
	allowedCIDRs []string
	allowedNets  []*net.IPNet
	ln           net.Listener
	createdAt    time.Time
	expiresAt    time.Time
	activeConns  atomic.Int64
	totalConns   atomic.Int64
	closed       atomic.Bool
}

// PortMapper manages dedicated/ephemeral TCP listeners on the central hub.
// Each listener transparently forwards raw TCP bytes (including Server-First protocols
// like MySQL/PostgreSQL) directly to a specific (tenant_id, service_name).
type PortMapper struct {
	registry *Registry
	st       store.Store
	logger   *slog.Logger

	mu       sync.RWMutex
	bindings map[string]*tcpBinding
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewPortMapper creates a TCP port mapping manager.
func NewPortMapper(registry *Registry, logger *slog.Logger) *PortMapper {
	return NewPortMapperWithStore(registry, nil, logger)
}

// NewPortMapperWithStore creates a TCP port mapping manager backed by optional persistent Store.
func NewPortMapperWithStore(registry *Registry, st store.Store, logger *slog.Logger) *PortMapper {
	if logger == nil {
		logger = slog.Default()
	}
	pm := &PortMapper{
		registry: registry,
		st:       st,
		logger:   logger.With("component", "port_mapper"),
		bindings: make(map[string]*tcpBinding),
		stopCh:   make(chan struct{}),
	}
	go pm.reapExpiredLoop()
	return pm
}

// RestorePersisted reloads persisted non-TTL TCP bindings from Store on hub startup.
func (pm *PortMapper) RestorePersisted() {
	if pm.st == nil {
		return
	}
	snap, err := pm.st.Load()
	if err != nil || snap == nil {
		return
	}
	for _, pb := range snap.Bindings {
		if _, err := pm.addInternal(TCPBindingSpec{
			ID:           pb.ID,
			ListenAddr:   pb.ListenAddr,
			TenantID:     pb.TenantID,
			ServiceName:  pb.ServiceName,
			AllowedCIDRs: pb.AllowedCIDRs,
		}, false); err != nil {
			pm.logger.Warn("failed restoring persisted tcp binding", "id", pb.ID, "listen_addr", pb.ListenAddr, "error", err)
		}
	}
}

// Add starts a TCP listener according to spec, persists it if non-TTL and Store is configured,
// and returns its active binding info (including kernel-assigned port if ListenAddr ended in ":0").
func (pm *PortMapper) Add(spec TCPBindingSpec) (*TCPBindingInfo, error) {
	return pm.addInternal(spec, true)
}

// AddStatic starts a config-declared static TCP listener without overwriting dynamic Store state.
func (pm *PortMapper) AddStatic(spec TCPBindingSpec) (*TCPBindingInfo, error) {
	return pm.addInternal(spec, false)
}

func (pm *PortMapper) addInternal(spec TCPBindingSpec, persist bool) (*TCPBindingInfo, error) {
	if spec.TenantID == "" || spec.ServiceName == "" {
		return nil, errors.New("tenant_id and service_name are required")
	}
	if spec.ListenAddr == "" {
		spec.ListenAddr = "127.0.0.1:0"
	}

	var allowedNets []*net.IPNet
	for _, cidr := range spec.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		allowedNets = append(allowedNets, ipNet)
	}

	ln, err := net.Listen("tcp", spec.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", spec.ListenAddr, err)
	}

	id := spec.ID
	if id == "" {
		id = "tcp_" + newShortID()
	}

	now := time.Now().UTC()
	var exp time.Time
	if spec.TTL > 0 {
		exp = now.Add(spec.TTL)
	}

	b := &tcpBinding{
		id:           id,
		listenAddr:   ln.Addr().String(),
		tenantID:     spec.TenantID,
		serviceName:  spec.ServiceName,
		allowedCIDRs: append([]string(nil), spec.AllowedCIDRs...),
		allowedNets:  allowedNets,
		ln:           ln,
		createdAt:    now,
		expiresAt:    exp,
	}

	pm.mu.Lock()
	if _, exists := pm.bindings[id]; exists {
		pm.mu.Unlock()
		_ = ln.Close()
		return nil, fmt.Errorf("binding id %q already exists", id)
	}
	pm.bindings[id] = b
	pm.mu.Unlock()

	if persist && pm.st != nil && spec.TTL <= 0 {
		_ = pm.st.SaveBinding(store.PersistedBinding{
			ID:           b.id,
			ListenAddr:   b.listenAddr,
			TenantID:     b.tenantID,
			ServiceName:  b.serviceName,
			AllowedCIDRs: b.allowedCIDRs,
		})
	}

	pm.logger.Info("tcp port binding started",
		"id", b.id,
		"listen_addr", b.listenAddr,
		"tenant_id", b.tenantID,
		"service", b.serviceName,
	)

	go pm.serveBinding(b)
	info := b.info()
	return &info, nil
}

// Remove stops and deletes a TCP binding by ID.
func (pm *PortMapper) Remove(id string) bool {
	pm.mu.Lock()
	b, ok := pm.bindings[id]
	if ok {
		delete(pm.bindings, id)
	}
	pm.mu.Unlock()
	if !ok {
		return false
	}
	b.closed.Store(true)
	_ = b.ln.Close()
	if pm.st != nil {
		_ = pm.st.DeleteBinding(id)
	}
	pm.logger.Info("tcp port binding removed", "id", id, "listen_addr", b.listenAddr)
	return true
}

// List returns all active TCP bindings sorted by ID.
func (pm *PortMapper) List() []TCPBindingInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]TCPBindingInfo, 0, len(pm.bindings))
	for _, b := range pm.bindings {
		out = append(out, b.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Close shuts down all TCP port bindings.
func (pm *PortMapper) Close() {
	pm.stopOnce.Do(func() { close(pm.stopCh) })
	pm.mu.Lock()
	all := make([]*tcpBinding, 0, len(pm.bindings))
	for _, b := range pm.bindings {
		all = append(all, b)
	}
	pm.bindings = make(map[string]*tcpBinding)
	pm.mu.Unlock()

	for _, b := range all {
		b.closed.Store(true)
		_ = b.ln.Close()
	}
}

func (pm *PortMapper) serveBinding(b *tcpBinding) {
	for {
		clientConn, err := b.ln.Accept()
		if err != nil {
			if b.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			pm.logger.Warn("tcp binding accept error", "id", b.id, "error", err)
			continue
		}

		if !b.isAllowedRemote(clientConn.RemoteAddr()) {
			pm.logger.Warn("AUDIT: rejected tcp connection outside allowed_cidrs",
				"binding_id", b.id,
				"remote_addr", clientConn.RemoteAddr().String(),
			)
			_ = clientConn.Close()
			continue
		}

		b.activeConns.Add(1)
		b.totalConns.Add(1)
		go func(cc net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					pm.logger.Error("recovered panic in tcp binding handler", "binding_id", b.id, "panic", r)
				}
				b.activeConns.Add(-1)
				_ = cc.Close()
			}()

			callerID := "tcp-binding:" + b.id + "@" + cc.RemoteAddr().String()
			stream, err := pm.registry.OpenTenantStream(context.Background(), b.tenantID, b.serviceName, protocol.ProtocolTCP, callerID)
			if err != nil {
				pm.logger.Warn("failed opening tenant tcp stream",
					"binding_id", b.id,
					"tenant_id", b.tenantID,
					"service", b.serviceName,
					"error", err,
				)
				return
			}
			defer func() { _ = stream.Close() }()

			transport.BidirectionalPipe(cc, stream)
		}(clientConn)
	}
}

func (pm *PortMapper) reapExpiredLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			now := time.Now().UTC()
			var expired []string
			pm.mu.RLock()
			for id, b := range pm.bindings {
				if !b.expiresAt.IsZero() && now.After(b.expiresAt) && b.activeConns.Load() == 0 {
					expired = append(expired, id)
				}
			}
			pm.mu.RUnlock()
			for _, id := range expired {
				pm.Remove(id)
			}
		}
	}
}

func (b *tcpBinding) isAllowedRemote(addr net.Addr) bool {
	if len(b.allowedNets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range b.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (b *tcpBinding) info() TCPBindingInfo {
	return TCPBindingInfo{
		ID:           b.id,
		ListenAddr:   b.listenAddr,
		TenantID:     b.tenantID,
		ServiceName:  b.serviceName,
		AllowedCIDRs: b.allowedCIDRs,
		ActiveConns:  b.activeConns.Load(),
		TotalConns:   b.totalConns.Load(),
		CreatedAt:    b.createdAt,
		ExpiresAt:    b.expiresAt,
	}
}
