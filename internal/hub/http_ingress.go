package hub

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/pkg/protocol"
)

const (
	HeaderTenant      = "X-Dataproxy-Tenant"
	HeaderService     = "X-Dataproxy-Service"
	HeaderAuth        = "X-Dataproxy-Auth"
	HeaderTicket      = "X-Dataproxy-Ticket"
	HeaderTraceparent = "traceparent"
)

type routeCtxKey struct{}

type httpRouteTarget struct {
	tenantID    string
	serviceName string
	callerID    string
	ticketID    string
	purpose     map[string]string
	traceparent string
}

// HTTPIngress exposes tenant internal HTTP/WebSocket platforms as standard HTTP
// endpoints on the central hub, routing by Host virtual domain, X-Dataproxy-* headers,
// or a self-contained short-lived X-Dataproxy-Ticket JWT.
type HTTPIngress struct {
	registry     *Registry
	acl          *auth.CallerACL
	tickets      *auth.TicketManager
	domainSuffix string
	logger       *slog.Logger
	transport    *http.Transport
	proxy        *httputil.ReverseProxy
}

// CloseIdleConnections releases idle reverse-proxy connections during hub shutdown.
func (h *HTTPIngress) CloseIdleConnections() {
	if h != nil && h.transport != nil {
		h.transport.CloseIdleConnections()
	}
}

// NewHTTPIngress constructs a multi-tenant HTTP reverse proxy handler.
func NewHTTPIngress(registry *Registry, acl *auth.CallerACL, tickets *auth.TicketManager, domainSuffix string, logger *slog.Logger) *HTTPIngress {
	if logger == nil {
		logger = slog.Default()
	}
	h := &HTTPIngress{
		registry:     registry,
		acl:          acl,
		tickets:      tickets,
		domainSuffix: domainSuffix,
		logger:       logger.With("component", "http_ingress"),
	}

	transport := &http.Transport{
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       256,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		ReadBufferSize:        64 * 1024,
		WriteBufferSize:       64 * 1024,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			target, ok := ctx.Value(routeCtxKey{}).(httpRouteTarget)
			if !ok {
				return nil, errors.New("missing route target in context")
			}
			return h.registry.OpenTenantStreamWithMeta(ctx, target.tenantID, target.serviceName, protocol.ProtocolHTTP, StreamMeta{
				CallerID:    target.callerID,
				TicketID:    target.ticketID,
				Purpose:     target.purpose,
				Traceparent: target.traceparent,
			})
		},
	}

	h.transport = transport
	h.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			target := pr.In.Context().Value(routeCtxKey{}).(httpRouteTarget)
			poolID := target.callerID
			if target.ticketID != "" {
				poolID = target.ticketID
			}
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = target.serviceName + "." + target.tenantID + "." + poolID + ".pool"
			pr.Out.Host = pr.In.Host

			// Propagate W3C traceparent end-to-end into tenant backend services.
			if target.traceparent != "" {
				pr.Out.Header.Set(HeaderTraceparent, target.traceparent)
			}

			// Strip central dataproxy routing, ticket, and auth headers so hub secrets never leak to tenant apps.
			pr.Out.Header.Del(HeaderTenant)
			pr.Out.Header.Del(HeaderService)
			pr.Out.Header.Del(HeaderAuth)
			pr.Out.Header.Del(HeaderTicket)
			pr.Out.Header.Del("Proxy-Authorization")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logger.Warn("http reverse proxy error", "host", r.Host, "path", r.URL.Path, "error", err)
			switch {
			case errors.Is(err, ErrTenantQuotaExceeded):
				http.Error(w, "tenant concurrent stream quota exceeded", http.StatusTooManyRequests)
			case errors.Is(err, ErrTenantOffline):
				http.Error(w, "tenant tunnel offline", http.StatusServiceUnavailable)
			case errors.Is(err, ErrServiceNotFound):
				http.Error(w, "tenant service not found", http.StatusNotFound)
			case errors.Is(err, ErrStreamRejected):
				http.Error(w, "tenant rejected request: "+err.Error(), http.StatusForbidden)
			default:
				http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
			}
		},
	}

	return h
}

// ServeHTTP authenticates, authorizes, resolves the target tenant service, and proxies the request.
func (h *HTTPIngress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tp := ensureTraceparent(r.Header.Get(HeaderTraceparent))

	// Fast path: short-lived single-tenant Job Ticket via X-Dataproxy-Ticket header.
	if rawTicket := strings.TrimSpace(r.Header.Get(HeaderTicket)); rawTicket != "" && h.tickets != nil {
		claims, err := h.tickets.VerifyJWT(rawTicket)
		if err != nil {
			h.logger.Warn("AUDIT: http ingress invalid job ticket", "remote", r.RemoteAddr, "error", err)
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), routeCtxKey{}, httpRouteTarget{
			tenantID:    claims.TenantID,
			serviceName: claims.ServiceName,
			callerID:    "http-ticket:" + claims.TicketID,
			ticketID:    claims.TicketID,
			purpose:     claims.Purpose,
			traceparent: tp,
		})
		h.proxy.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	callerID, err := h.authenticateRequest(r)
	if err != nil {
		h.logger.Warn("AUDIT: http ingress auth failed", "remote", r.RemoteAddr, "host", r.Host)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	tenantID, serviceName, err := h.resolveTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.acl.Authorize(callerID, tenantID, serviceName); err != nil {
		h.logger.Warn("AUDIT: http ingress ACL denied",
			"caller", callerID,
			"tenant_id", tenantID,
			"service", serviceName,
			"reason", err.Error(),
		)
		http.Error(w, "forbidden: caller not authorized for target tenant/service", http.StatusForbidden)
		return
	}

	ctx := context.WithValue(r.Context(), routeCtxKey{}, httpRouteTarget{
		tenantID:    tenantID,
		serviceName: serviceName,
		callerID:    callerID,
		traceparent: tp,
	})
	h.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// ensureTraceparent preserves a valid W3C traceparent header (zero allocs)
// or generates a new 55-byte W3C traceparent without OS CSPRNG syscalls.
func ensureTraceparent(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if isValidW3CTraceparent(trimmed) {
		return trimmed
	}
	var rawIDs [24]byte
	binary.BigEndian.PutUint64(rawIDs[0:8], rand.Uint64())
	binary.BigEndian.PutUint64(rawIDs[8:16], rand.Uint64())
	binary.BigEndian.PutUint64(rawIDs[16:24], rand.Uint64())

	// Format: "00-" + 32 hex + "-" + 16 hex + "-01" (exact length 55)
	var out [55]byte
	out[0], out[1], out[2] = '0', '0', '-'
	hex.Encode(out[3:35], rawIDs[0:16])
	out[35] = '-'
	hex.Encode(out[36:52], rawIDs[16:24])
	out[52], out[53], out[54] = '-', '0', '1'
	return string(out[:])
}

func isValidW3CTraceparent(s string) bool {
	if len(s) != 55 || s[2] != '-' || s[35] != '-' || s[52] != '-' {
		return false
	}
	for i := 0; i < 55; i++ {
		if i == 2 || i == 35 || i == 52 {
			continue
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (h *HTTPIngress) resolveTarget(r *http.Request) (tenantID, serviceName string, err error) {
	hdrTenant := strings.TrimSpace(r.Header.Get(HeaderTenant))
	hdrService := strings.TrimSpace(r.Header.Get(HeaderService))
	if hdrTenant != "" || hdrService != "" {
		if hdrTenant == "" || hdrService == "" {
			return "", "", errors.New("both X-Dataproxy-Tenant and X-Dataproxy-Service headers are required")
		}
		return hdrTenant, hdrService, nil
	}
	return ParseVirtualTarget(r.Host, h.domainSuffix)
}

func (h *HTTPIngress) authenticateRequest(r *http.Request) (string, error) {
	raw := strings.TrimSpace(r.Header.Get(HeaderAuth))
	if raw == "" {
		raw = strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	}
	if raw == "" {
		if h.acl.AllowNoAuth() {
			return "anonymous-dev", nil
		}
		return "", auth.ErrCallerUnauthorized
	}

	if strings.HasPrefix(raw, "Bearer ") {
		return h.acl.AuthenticateBearer(strings.TrimPrefix(raw, "Bearer "))
	}
	if strings.HasPrefix(raw, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "Basic "))
		if err != nil {
			return "", auth.ErrCallerUnauthorized
		}
		user, pass, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return "", auth.ErrCallerUnauthorized
		}
		return h.acl.AuthenticateBasic(user, pass)
	}
	return h.acl.AuthenticateBearer(raw)
}
