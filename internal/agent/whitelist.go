package agent

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/agent/guard"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

var (
	ErrForbiddenService = errors.New("service is not in agent local allowlist")
	ErrProtocolMismatch = errors.New("requested protocol is not permitted for service")
	ErrRateLimited      = errors.New("service max concurrent connections reached")
	ErrOutsideWindow    = errors.New("access denied outside configured time window")
)

// WhitelistEntry represents a single locally allowed backend target with its
// concurrency semaphore, bandwidth shaping limiter, access window, and unified ProtocolGuard plugin.
type WhitelistEntry struct {
	Name         string
	Protocol     string
	TargetAddr   string
	TargetTLS    *tls.Config // Non-nil when target_tls.enabled=true
	UsesStartTLS bool        // True for MySQL/PostgreSQL where STARTTLS happens inside ProtocolGuard
	DialTimeout  time.Duration
	IdleTimeout  time.Duration

	TxLimiter *transport.BandwidthLimiter
	RxLimiter *transport.BandwidthLimiter
	Windows   *TimeWindowChecker
	Guard     guard.ProtocolGuard // Unified pluggable L7 interceptor (mysql|postgres|mongodb|redis|http)

	sem         chan struct{}
	activeConns atomic.Int64
}

// Release frees one concurrency slot for this target.
func (e *WhitelistEntry) Release() {
	<-e.sem
	e.activeConns.Add(-1)
}

// Whitelist enforces the tenant's zero-trust intranet exposure boundary and supports
// atomic hot-reload without interrupting active in-flight streams.
type Whitelist struct {
	mu            sync.RWMutex
	entries       map[string]*WhitelistEntry
	globalWindows *TimeWindowChecker
	deniedCount   atomic.Int64
	acceptedCount atomic.Int64
}

// NewWhitelist builds a local allowlist from configured services and optional global time windows.
func NewWhitelist(services []ServiceConfig, globalWindows *TimeWindowChecker) *Whitelist {
	w := &Whitelist{}
	w.Reload(services, globalWindows)
	return w
}

// Reload atomically replaces the live service allowlist and time windows.
// Existing in-flight streams hold direct references to their previous *WhitelistEntry
// and complete cleanly without interruption.
func (w *Whitelist) Reload(services []ServiceConfig, globalWindows *TimeWindowChecker) {
	entries := make(map[string]*WhitelistEntry, len(services))
	for i := range services {
		svc := &services[i]
		maxConns := svc.MaxConns
		if maxConns <= 0 {
			maxConns = 128
		}

		tlsCfg := svc.targetTLSConfig
		if tlsCfg == nil && svc.TargetTLS != nil && svc.TargetTLS.Enabled {
			tlsCfg, _ = svc.TargetTLS.BuildTLSConfig(svc.TargetAddr)
		}

		var protoGuard guard.ProtocolGuard
		usesStartTLS := false
		if g := svc.EffectiveGuard(); g != nil {
			spec := guard.GuardSpec{
				Type:      g.Type,
				ReadOnly:  g.ReadOnly,
				TargetTLS: tlsCfg,
			}
			if g.Type == "mysql" || g.Type == "postgres" {
				usesStartTLS = tlsCfg != nil
			}
			if g.CredentialInjection != nil && g.CredentialInjection.Enabled {
				spec.InjectCreds = true
				spec.UsernameSpec = g.CredentialInjection.Username
				spec.PasswordSpec = g.CredentialInjection.Password
				spec.AuthSource = g.CredentialInjection.AuthSource
			}
			protoGuard, _ = guard.BuildGuard(spec)
		} else if svc.Protocol == protocol.ProtocolHTTP {
			protoGuard, _ = guard.BuildGuard(guard.GuardSpec{
				Type:               "http",
				AllowedHTTPMethods: svc.AllowedHTTPMethods,
				InjectHeaders:      svc.InjectHeaders,
			})
		}

		entries[svc.Name] = &WhitelistEntry{
			Name:         svc.Name,
			Protocol:     svc.Protocol,
			TargetAddr:   svc.TargetAddr,
			TargetTLS:    tlsCfg,
			UsesStartTLS: usesStartTLS,
			DialTimeout:  svc.DialTimeout,
			IdleTimeout:  svc.IdleTimeout,
			TxLimiter:    transport.NewBandwidthLimiter(svc.maxBandwidthBytes),
			RxLimiter:    transport.NewBandwidthLimiter(svc.maxBandwidthBytes),
			Windows:      svc.windows,
			Guard:        protoGuard,
			sem:          make(chan struct{}, maxConns),
		}
	}

	w.mu.Lock()
	w.entries = entries
	w.globalWindows = globalWindows
	w.mu.Unlock()
}

// Acquire validates serviceName, reqProto, and access time windows, then reserves a concurrency slot.
func (w *Whitelist) Acquire(serviceName, reqProto string) (*WhitelistEntry, string, error) {
	w.mu.RLock()
	entry, ok := w.entries[serviceName]
	gWin := w.globalWindows
	w.mu.RUnlock()

	if !ok {
		w.deniedCount.Add(1)
		return nil, protocol.CodeForbiddenService, fmt.Errorf("%w: %q", ErrForbiddenService, serviceName)
	}

	if entry.Protocol == protocol.ProtocolTCP && reqProto != protocol.ProtocolTCP {
		w.deniedCount.Add(1)
		return nil, protocol.CodeProtocolMismatch, fmt.Errorf("%w: service %q only allows tcp, got %q", ErrProtocolMismatch, serviceName, reqProto)
	}
	if reqProto != protocol.ProtocolTCP && reqProto != protocol.ProtocolHTTP {
		w.deniedCount.Add(1)
		return nil, protocol.CodeProtocolMismatch, fmt.Errorf("%w: unsupported protocol %q", ErrProtocolMismatch, reqProto)
	}

	if ok, reason := gWin.Allowed(); !ok {
		w.deniedCount.Add(1)
		return nil, protocol.CodeOutsideWindow, fmt.Errorf("%w: %s", ErrOutsideWindow, reason)
	}
	if ok, reason := entry.Windows.Allowed(); !ok {
		w.deniedCount.Add(1)
		return nil, protocol.CodeOutsideWindow, fmt.Errorf("%w: service %q: %s", ErrOutsideWindow, serviceName, reason)
	}

	select {
	case entry.sem <- struct{}{}:
		entry.activeConns.Add(1)
		w.acceptedCount.Add(1)
		return entry, "", nil
	default:
		w.deniedCount.Add(1)
		return nil, protocol.CodeRateLimited, fmt.Errorf("%w: service %q", ErrRateLimited, serviceName)
	}
}

// DeniedCount returns total rejected stream open attempts (for audit & testing).
func (w *Whitelist) DeniedCount() int64 {
	return w.deniedCount.Load()
}

// BlockedProtocolOps returns total DB write queries/commands and HTTP methods blocked by local guards.
func (w *Whitelist) BlockedProtocolOps() (dbBlocked int64, httpBlocked int64) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, e := range w.entries {
		if e.Guard == nil {
			continue
		}
		if e.Guard.Type() == "http" {
			httpBlocked += e.Guard.BlockedCount()
		} else {
			dbBlocked += e.Guard.BlockedCount()
		}
	}
	return dbBlocked, httpBlocked
}
