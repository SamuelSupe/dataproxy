package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

const (
	maxPublicControlBodyBytes = 64 * 1024
	ctrlStreamWriteTimeout    = 10 * time.Second
)

var ctrlStreamAcceptTimeout = 15 * time.Second

// sleepAcceptBackoff backs off exponentially (5ms -> 1s) on transient listener Accept errors
// (such as temporary EMFILE/ENFILE bursts) instead of killing the listener or spinning at 100% CPU.
func sleepAcceptBackoff(delay *time.Duration) {
	if *delay == 0 {
		*delay = 5 * time.Millisecond
	} else {
		*delay *= 2
		if *delay > time.Second {
			*delay = time.Second
		}
	}
	time.Sleep(*delay)
}

// TunnelServer accepts outbound agent tunnel connections over WSS and/or raw TLS/TCP,
// and serves one-time device enrollment & automatic certificate renewal endpoints on the same HTTPS port.
type TunnelServer struct {
	auth              *auth.TenantAuthenticator
	devices           *auth.DeviceManager
	registry          *Registry
	limiter           *IPRateLimiter
	metrics           *Metrics
	heartbeatInterval time.Duration
	logger            *slog.Logger
}

// NewTunnelServer creates a new tunnel acceptor.
func NewTunnelServer(
	tenantAuth *auth.TenantAuthenticator,
	devices *auth.DeviceManager,
	registry *Registry,
	heartbeatInterval time.Duration,
	logger *slog.Logger,
) *TunnelServer {
	if heartbeatInterval <= 0 {
		heartbeatInterval = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TunnelServer{
		auth:              tenantAuth,
		devices:           devices,
		registry:          registry,
		heartbeatInterval: heartbeatInterval,
		logger:            logger.With("component", "tunnel_server"),
	}
}

// SetRateLimiter configures per-IP handshake rate limiting on public tunnel endpoints.
func (ts *TunnelServer) SetRateLimiter(l *IPRateLimiter) {
	ts.limiter = l
}

// SetMetrics attaches Prometheus histograms and counters to the tunnel server.
func (ts *TunnelServer) SetMetrics(m *Metrics) {
	ts.metrics = m
}

func (ts *TunnelServer) checkRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if ts.limiter == nil || ts.limiter.Allow(r.RemoteAddr) {
		return true
	}
	if ts.metrics != nil {
		ts.metrics.RateLimitedHandshakes.Add(1)
	}
	ts.logger.Warn("AUDIT: tunnel endpoint rate limited", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
	return false
}

// HandleDeviceEnroll exchanges a 15-minute single-use enrollment code + CSR for a signed device certificate.
func (ts *TunnelServer) HandleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
	if !ts.checkRateLimit(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if ts.devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device PKI not enabled"})
		return
	}
	var req struct {
		Code   string `json:"code"`
		CSRPEM string `json:"csr_pem"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicControlBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized json body"})
		return
	}
	bundle, err := ts.devices.CompleteEnrollment(req.Code, req.CSRPEM)
	if err != nil {
		ts.logger.Warn("AUDIT: device enrollment rejected", "remote_addr", r.RemoteAddr, "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	ts.logger.Info("AUDIT: device enrolled successfully",
		"tenant_id", bundle.TenantID,
		"device_id", bundle.DeviceID,
		"cert_serial", bundle.CertSerial,
		"remote_addr", r.RemoteAddr,
	)
	writeJSON(w, http.StatusCreated, bundle)
}

// HandleDeviceRenew rotates an active (non-revoked) device's short-lived certificate and token.
func (ts *TunnelServer) HandleDeviceRenew(w http.ResponseWriter, r *http.Request) {
	if !ts.checkRateLimit(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if ts.devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device PKI not enabled"})
		return
	}
	var req struct {
		DeviceID    string `json:"device_id"`
		DeviceToken string `json:"device_token"`
		CSRPEM      string `json:"csr_pem"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicControlBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized json body"})
		return
	}
	var peerCerts []*x509.Certificate
	if r.TLS != nil {
		peerCerts = r.TLS.PeerCertificates
	}
	bundle, err := ts.devices.RenewDevice(req.DeviceID, req.DeviceToken, req.CSRPEM, peerCerts)
	if err != nil {
		ts.logger.Warn("AUDIT: device cert renewal rejected", "device_id", req.DeviceID, "error", err)
		status := http.StatusUnauthorized
		if errors.Is(err, auth.ErrDeviceRevoked) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	ts.logger.Info("AUDIT: device certificate rotated",
		"tenant_id", bundle.TenantID,
		"device_id", bundle.DeviceID,
		"new_serial", bundle.CertSerial,
	)
	writeJSON(w, http.StatusOK, bundle)
}

// HandleWebSocket upgrades an incoming HTTP/HTTPS request from an agent into a
// yamux-multiplexed tunnel connection.
func (ts *TunnelServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !ts.checkRateLimit(w, r) {
		return
	}
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{"dataproxy-v1"},
		InsecureSkipVerify: true, // Non-browser agent clients do not send Origin headers
	})
	if err != nil {
		ts.logger.Warn("websocket accept failed", "remote_addr", r.RemoteAddr, "error", err)
		return
	}

	var peerCerts []*x509.Certificate
	if r.TLS != nil {
		peerCerts = r.TLS.PeerCertificates
	}

	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netConn := websocket.NetConn(connCtx, wsConn, websocket.MessageBinary)
	ts.serveTunnelConn(netConn, r.RemoteAddr, "wss", peerCerts)
}

// ServeRawListener accepts raw TLS or TCP agent tunnel connections on ln.
func (ts *TunnelServer) ServeRawListener(ln net.Listener, transportName string) error {
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			ts.logger.Warn("raw tunnel accept error, backing off", "transport", transportName, "error", err)
			sleepAcceptBackoff(&tempDelay)
			continue
		}
		tempDelay = 0
		remoteAddr := conn.RemoteAddr().String()
		if ts.limiter != nil && !ts.limiter.Allow(remoteAddr) {
			if ts.metrics != nil {
				ts.metrics.RateLimitedHandshakes.Add(1)
			}
			ts.logger.Warn("AUDIT: raw tunnel handshake rate limited", "transport", transportName, "remote_addr", remoteAddr)
			_ = conn.Close()
			continue
		}
		go func(c net.Conn, remote string) {
			defer func() {
				if r := recover(); r != nil {
					ts.logger.Error("recovered panic in raw tunnel handshake", "remote_addr", remote, "panic", r)
					_ = c.Close()
				}
			}()
			var peerCerts []*x509.Certificate
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
				if err := tc.Handshake(); err != nil {
					ts.logger.Warn("tls handshake failed", "remote_addr", remote, "error", err)
					_ = c.Close()
					return
				}
				_ = tc.SetDeadline(time.Time{})
				peerCerts = tc.ConnectionState().PeerCertificates
			}
			ts.serveTunnelConn(c, remote, transportName, peerCerts)
		}(conn, remoteAddr)
	}
}

// ServeQUIC accepts native QUIC (UDP + TLS 1.3) agent tunnel connections on ln.
// Native QUIC streams replace Yamux completely, eliminating transport Head-of-Line blocking.
func (ts *TunnelServer) ServeQUIC(ln *transport.QUICListener) error {
	var tempDelay time.Duration
	for {
		qconn, err := ln.Accept(context.Background())
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			ts.logger.Warn("quic tunnel accept error, backing off", "error", err)
			sleepAcceptBackoff(&tempDelay)
			continue
		}
		tempDelay = 0
		remoteAddr := qconn.RemoteAddr().String()
		if ts.limiter != nil && !ts.limiter.Allow(remoteAddr) {
			if ts.metrics != nil {
				ts.metrics.RateLimitedHandshakes.Add(1)
			}
			ts.logger.Warn("AUDIT: quic tunnel handshake rate limited", "remote_addr", remoteAddr)
			_ = qconn.CloseWithError(429, "rate limit exceeded")
			continue
		}
		go func(qc *quic.Conn, remote string) {
			peerCerts := qc.ConnectionState().TLS.PeerCertificates
			ts.serveTunnelMux(transport.NewQUICMux(qc), remote, "quic", peerCerts)
		}(qconn, remoteAddr)
	}
}

func (ts *TunnelServer) serveTunnelConn(conn net.Conn, remoteAddr, transportName string, peerCerts []*x509.Certificate) {
	muxSession, err := yamux.Server(conn, transport.DefaultYamuxConfig())
	if err != nil {
		ts.logger.Warn("init yamux server failed", "remote_addr", remoteAddr, "error", err)
		_ = conn.Close()
		return
	}
	ts.serveTunnelMux(transport.NewYamuxMux(muxSession, conn), remoteAddr, transportName, peerCerts)
}

func (ts *TunnelServer) serveTunnelMux(muxSession transport.StreamMux, remoteAddr, transportName string, peerCerts []*x509.Certificate) {
	defer func() {
		if r := recover(); r != nil {
			ts.logger.Error("recovered panic in tunnel session handler", "remote_addr", remoteAddr, "panic", r)
		}
		_ = muxSession.Close()
	}()

	// Accept Control Stream #1 from agent with a strict pre-auth timeout so an idle
	// client that completes WSS/QUIC/TLS handshake without opening Stream #1 cannot
	// hold goroutines or sockets indefinitely (Slowloris defense).
	acceptTimer := time.AfterFunc(ctrlStreamAcceptTimeout, func() {
		_ = muxSession.Close()
	})
	ctrlStream, err := muxSession.AcceptStream()
	acceptTimer.Stop()
	if err != nil {
		ts.logger.Warn("failed accepting agent control stream", "remote_addr", remoteAddr, "error", err)
		return
	}
	defer func() { _ = ctrlStream.Close() }()

	_ = ctrlStream.SetDeadline(time.Now().Add(15 * time.Second))
	var req protocol.RegisterRequest
	if err := protocol.ReadTypedFrame(ctrlStream, protocol.FrameRegisterReq, &req); err != nil {
		ts.logger.Warn("failed reading register request", "remote_addr", remoteAddr, "error", err)
		return
	}

	var authErr error
	if req.DeviceID != "" && ts.devices != nil {
		authErr = ts.devices.AuthenticateDevice(req.TenantID, req.DeviceID, req.Token, peerCerts)
	} else {
		authErr = ts.auth.Authenticate(req.TenantID, req.Token, peerCerts)
	}
	if authErr != nil {
		code := protocol.CodeAuthFailed
		if errors.Is(authErr, auth.ErrDeviceRevoked) {
			code = protocol.CodeDeviceRevoked
		}
		ts.logger.Warn("AUDIT: rejected agent tunnel auth",
			"tenant_id", req.TenantID,
			"agent_id", req.AgentID,
			"device_id", req.DeviceID,
			"remote_addr", remoteAddr,
			"reason", authErr.Error(),
		)
		_ = protocol.WriteFrame(ctrlStream, protocol.FrameRegisterResp, protocol.RegisterResponse{
			OK:      false,
			Code:    code,
			Message: authErr.Error(),
		})
		return
	}

	svcMap := make(map[string]protocol.ServiceAnnouncement, len(req.Services))
	for _, s := range req.Services {
		svcMap[s.Name] = s
	}

	role := req.Role
	if role == "" {
		role = "all"
	}
	sess := &AgentSession{
		SessionID:   "sess_" + newShortID(),
		TenantID:    req.TenantID,
		AgentID:     req.AgentID,
		DeviceID:    req.DeviceID,
		PoolLane:    req.PoolLane,
		Role:        role,
		RemoteAddr:  remoteAddr,
		Transport:   transportName,
		ConnectedAt: time.Now().UTC(),
		Labels:      req.Labels,
		Services:    svcMap,
		mux:         muxSession,
	}
	sess.RecordHeartbeat(0)

	if err := ts.registry.Register(sess); err != nil {
		ts.logger.Warn("AUDIT: rejected agent session due to tenant quota",
			"tenant_id", sess.TenantID,
			"agent_id", sess.AgentID,
			"pool_lane", sess.PoolLane,
			"error", err,
		)
		_ = protocol.WriteFrame(ctrlStream, protocol.FrameRegisterResp, protocol.RegisterResponse{
			OK:      false,
			Code:    "ERR_QUOTA_EXCEEDED",
			Message: err.Error(),
		})
		return
	}
	defer ts.registry.Unregister(sess)

	if err := protocol.WriteFrame(ctrlStream, protocol.FrameRegisterResp, protocol.RegisterResponse{
		OK:                   true,
		SessionID:            sess.SessionID,
		HeartbeatIntervalSec: int(ts.heartbeatInterval.Seconds()),
	}); err != nil {
		ts.logger.Warn("failed writing register response", "session_id", sess.SessionID, "error", err)
		return
	}
	_ = ctrlStream.SetDeadline(time.Time{})

	ts.logger.Info("agent tunnel connected",
		"tenant_id", sess.TenantID,
		"agent_id", sess.AgentID,
		"session_id", sess.SessionID,
		"pool_lane", sess.PoolLane,
		"role", sess.Role,
		"transport", transportName,
		"services", len(sess.Services),
		"remote_addr", remoteAddr,
	)

	// Control stream loop: respond to Ping and handle graceful Drain notices.
	readTimeout := ts.heartbeatInterval*3 + 5*time.Second
	for {
		_ = ctrlStream.SetReadDeadline(time.Now().Add(readTimeout))
		frame, err := protocol.ReadFrame(ctrlStream, protocol.DefaultMaxFrameSize)
		if err != nil {
			if !errors.Is(err, io.EOF) && !muxSession.IsClosed() {
				ts.logger.Info("agent control stream closed",
					"tenant_id", sess.TenantID,
					"session_id", sess.SessionID,
					"error", err,
				)
			}
			return
		}

		switch frame.Type {
		case protocol.FramePing:
			var ping protocol.PingMessage
			_ = json.Unmarshal(frame.Payload, &ping)
			_ = ctrlStream.SetWriteDeadline(time.Now().Add(ctrlStreamWriteTimeout))
			werr := protocol.WriteFrame(ctrlStream, protocol.FramePong, protocol.PongMessage{
				SentAtUnixNano: ping.SentAtUnixNano,
			})
			_ = ctrlStream.SetWriteDeadline(time.Time{})
			if werr != nil {
				return
			}
			var rtt time.Duration
			if measured, err := muxSession.Ping(); err == nil && measured > 0 {
				rtt = measured
				if ts.metrics != nil {
					ts.metrics.TunnelRTT.Observe(rtt.Seconds())
				}
			}
			sess.RecordHeartbeat(rtt)

		case protocol.FrameDrain:
			var drain protocol.DrainMessage
			_ = json.Unmarshal(frame.Payload, &drain)
			sess.MarkDraining()
			ts.logger.Info("agent session entered draining state",
				"tenant_id", sess.TenantID,
				"session_id", sess.SessionID,
				"reason", drain.Reason,
			)

		case protocol.FrameServiceUpdate:
			var upd protocol.ServiceUpdateMessage
			if err := json.Unmarshal(frame.Payload, &upd); err == nil {
				sess.UpdateServices(upd.Services)
				ts.logger.Info("agent hot-reloaded exposed services",
					"tenant_id", sess.TenantID,
					"session_id", sess.SessionID,
					"service_count", len(upd.Services),
				)
			}

		case protocol.FrameHealthReport:
			var hr protocol.HealthReportMessage
			if err := json.Unmarshal(frame.Payload, &hr); err == nil {
				sess.UpdateHealth(hr.Services)
			}
		}
	}
}
