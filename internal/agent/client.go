package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

// Client is the tenant-side dataproxy-agent runtime supporting multi-lane tunnel pools
// (control/data plane separation), hot-reload, health telemetry, and pluggable L7 guards.
type Client struct {
	mu              sync.RWMutex
	cfg             *Config
	configPath      string
	globalTxLimiter *transport.BandwidthLimiter
	globalRxLimiter *transport.BandwidthLimiter
	audit           *AuditLogger
	activeCtrlMap   map[int]func(frameType uint8, msg any) error

	whitelist     *Whitelist
	logger        *slog.Logger
	activeStreams atomic.Int64
	streamZeroCh  chan struct{}

	readyOnce sync.Once
	readyCh   chan struct{}
}

// NewClient creates a new tenant agent client.
func NewClient(cfg *Config, logger *slog.Logger) (*Client, error) {
	if err := cfg.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	baseLogger := logger.With("component", "agent", "tenant_id", cfg.TenantID, "agent_id", cfg.AgentID)
	auditLogger, err := NewAuditLogger(cfg.TenantID, cfg.AgentID, cfg.Audit, baseLogger)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:             cfg,
		whitelist:       NewWhitelist(cfg.Services, cfg.globalWindows),
		globalTxLimiter: transport.NewBandwidthLimiter(cfg.maxBandwidthBytes),
		globalRxLimiter: transport.NewBandwidthLimiter(cfg.maxBandwidthBytes),
		audit:           auditLogger,
		activeCtrlMap:   make(map[int]func(uint8, any) error),
		logger:          baseLogger,
		streamZeroCh:    make(chan struct{}, 1),
		readyCh:         make(chan struct{}),
	}, nil
}

// SetConfigPath enables automatic polling hot-reload on the given agent.yaml file path.
func (c *Client) SetConfigPath(path string) {
	c.mu.Lock()
	c.configPath = path
	c.mu.Unlock()
}

// Ready returns a channel closed once the agent successfully registers with the hub for the first time.
func (c *Client) Ready() <-chan struct{} {
	return c.readyCh
}

// Whitelist returns the agent's local whitelist guard (useful for inspection/tests).
func (c *Client) Whitelist() *Whitelist {
	return c.whitelist
}

// ReloadConfig validates and atomically applies newCfg without disconnecting any tunnel lane
// or interrupting any active database/HTTP streams, then pushes FrameServiceUpdate + HealthReport to the hub.
func (c *Client) ReloadConfig(newCfg *Config) error {
	if err := newCfg.NormalizeAndValidate(); err != nil {
		return fmt.Errorf("validate reloaded config: %w", err)
	}

	newAudit, err := NewAuditLogger(newCfg.TenantID, newCfg.AgentID, newCfg.Audit, c.logger)
	if err != nil {
		return fmt.Errorf("init reloaded audit logger: %w", err)
	}

	c.whitelist.Reload(newCfg.Services, newCfg.globalWindows)

	c.mu.Lock()
	oldAudit := c.audit
	c.cfg = newCfg
	c.globalTxLimiter = transport.NewBandwidthLimiter(newCfg.maxBandwidthBytes)
	c.globalRxLimiter = transport.NewBandwidthLimiter(newCfg.maxBandwidthBytes)
	c.audit = newAudit
	writers := make([]func(uint8, any) error, 0, len(c.activeCtrlMap))
	for _, fn := range c.activeCtrlMap {
		writers = append(writers, fn)
	}
	announcements := newCfg.Announcements()
	svcsCopy := append([]ServiceConfig(nil), newCfg.Services...)
	c.mu.Unlock()

	if oldAudit != nil {
		oldAudit.Close()
	}

	if len(writers) > 0 {
		statuses := ProbeServicesSanitized(svcsCopy)
		for _, writeCtrl := range writers {
			_ = writeCtrl(protocol.FrameServiceUpdate, protocol.ServiceUpdateMessage{Services: announcements})
			_ = writeCtrl(protocol.FrameHealthReport, protocol.HealthReportMessage{Services: statuses})
		}
	}

	newAudit.Record(AuditEvent{
		Event:  "config_reloaded",
		Reason: fmt.Sprintf("hot-reloaded %d whitelisted services without dropping active streams", len(announcements)),
	})
	return nil
}

// ReloadFromFile loads and applies config from path (or the configured configPath).
func (c *Client) ReloadFromFile(path string) error {
	if path == "" {
		c.mu.RLock()
		path = c.configPath
		c.mu.RUnlock()
	}
	if path == "" {
		return errors.New("no config file path configured for reload")
	}
	newCfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	return c.ReloadConfig(newCfg)
}

// Run maintains pool_size outbound tunnel lane(s) to the hub with exponential backoff reconnects
// until ctx is canceled. When pool_size > 1, lane 0 acts as the dedicated control/health lane
// and lanes 1..N-1 serve parallel data streams, eliminating single-TCP Head-of-Line blocking.
func (c *Client) Run(ctx context.Context) error {
	defer func() {
		c.mu.RLock()
		a := c.audit
		c.mu.RUnlock()
		if a != nil {
			a.Close()
		}
	}()

	go c.watchConfigLoop(ctx)
	go c.watchCertRenewalLoop(ctx)

	c.mu.RLock()
	poolSize := c.cfg.PoolSize
	c.mu.RUnlock()
	if poolSize <= 1 {
		return c.runLaneLoop(ctx, 0, "all")
	}

	var wg sync.WaitGroup
	for lane := 0; lane < poolSize; lane++ {
		role := "data"
		if lane == 0 {
			role = "control"
		}
		wg.Add(1)
		go func(l int, r string) {
			defer wg.Done()
			_ = c.runLaneLoop(ctx, l, r)
		}(lane, role)
	}
	wg.Wait()
	return nil
}

func (c *Client) runLaneLoop(ctx context.Context, lane int, role string) error {
	c.mu.RLock()
	backoff := c.cfg.ReconnectMinWait
	maxBackoff := c.cfg.ReconnectMaxWait
	c.mu.RUnlock()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		start := time.Now()
		err := c.runSession(ctx, lane, role)
		if ctx.Err() != nil {
			if lane == 0 {
				c.logger.Info("agent stopped gracefully")
			}
			return nil
		}

		if time.Since(start) > 30*time.Second {
			c.mu.RLock()
			backoff = c.cfg.ReconnectMinWait
			c.mu.RUnlock()
		}

		jitter := time.Duration(rand.Int64N(int64(backoff/4 + 1)))
		sleepDur := backoff + jitter
		c.logger.Warn("tunnel lane ended, scheduling reconnect",
			"lane", lane,
			"role", role,
			"error", err,
			"retry_in", sleepDur.String(),
		)

		timer := time.NewTimer(sleepDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) watchConfigLoop(ctx context.Context) {
	c.mu.RLock()
	path := c.configPath
	interval := c.cfg.ConfigWatchInterval
	c.mu.RUnlock()
	if path == "" || interval <= 0 {
		return
	}

	var lastHash [32]byte
	var lastMod time.Time
	var lastSize int64
	if fi, err := os.Stat(path); err == nil {
		lastMod = fi.ModTime()
		lastSize = fi.Size()
	}
	if data, err := os.ReadFile(path); err == nil {
		lastHash = sha256.Sum256(data)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fi, err := os.Stat(path)
			if err != nil {
				continue
			}
			// Fast path: skip opening & hashing unchanged config files in steady state
			// (while still hashing files modified within the last 2s to catch rapid sub-second edits).
			if fi.ModTime().Equal(lastMod) && fi.Size() == lastSize && time.Since(fi.ModTime()) > 2*time.Second {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			lastMod = fi.ModTime()
			lastSize = fi.Size()
			curHash := sha256.Sum256(data)
			if curHash == lastHash {
				continue
			}
			lastHash = curHash
			if err := c.ReloadFromFile(path); err != nil {
				c.logger.Error("hot-reload rejected invalid config file; keeping previous config", "path", path, "error", err)
			}
		}
	}
}

func (c *Client) runSession(parentCtx context.Context, lane int, role string) error {
	sessionCtx, cancelSession := context.WithCancel(context.Background())
	defer cancelSession()

	c.mu.RLock()
	cfgSnap := c.cfg
	c.mu.RUnlock()

	c.logger.Info("dialing hub tunnel", "mode", cfgSnap.Server.Mode, "url", cfgSnap.Server.URL, "quic_url", cfgSnap.Server.QUICURL, "lane", lane, "role", role)
	// Abort an in-flight Hub dial OR registration handshake immediately if parentCtx is canceled,
	// while keeping sessionCtx alive after registration so websocket.NetConn / QUIC stay open during graceful drain.
	initDone := make(chan struct{})
	var closeInitOnce sync.Once
	stopInitWatcher := func() { closeInitOnce.Do(func() { close(initDone) }) }
	defer stopInitWatcher()

	var muxMu sync.Mutex
	var activeMux transport.StreamMux
	go func() {
		select {
		case <-parentCtx.Done():
			cancelSession()
			muxMu.Lock()
			m := activeMux
			muxMu.Unlock()
			if m != nil {
				_ = m.Close()
			}
		case <-initDone:
		}
	}()
	muxSession, activeTransport, err := transport.DialTunnelMux(sessionCtx, transport.DialConfig{
		Mode:        cfgSnap.Server.Mode,
		URL:         cfgSnap.Server.URL,
		QUICURL:     cfgSnap.Server.QUICURL,
		ProxyURL:    cfgSnap.Server.ProxyURL,
		DialTimeout: cfgSnap.Server.DialTimeout,
		TLS:         cfgSnap.Server.TLS,
	})
	if err != nil {
		return err
	}
	muxMu.Lock()
	activeMux = muxSession
	muxMu.Unlock()
	if parentCtx.Err() != nil {
		_ = muxSession.Close()
		return parentCtx.Err()
	}
	defer func() { _ = muxSession.Close() }()

	ctrlStream, err := muxSession.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer func() { _ = ctrlStream.Close() }()

	c.mu.RLock()
	regReq := protocol.RegisterRequest{
		Version:  protocol.CurrentVersion,
		TenantID: c.cfg.TenantID,
		AgentID:  c.cfg.AgentID,
		DeviceID: c.cfg.DeviceID,
		PoolLane: lane,
		Role:     role,
		Token:    c.cfg.Token,
		Services: c.cfg.Announcements(),
		Labels:   c.cfg.Labels,
	}
	drainTimeout := c.cfg.DrainTimeout
	healthInterval := c.cfg.HealthReportInterval
	servicesCopy := append([]ServiceConfig(nil), c.cfg.Services...)
	c.mu.RUnlock()

	_ = ctrlStream.SetDeadline(time.Now().Add(15 * time.Second))
	if err := protocol.WriteFrame(ctrlStream, protocol.FrameRegisterReq, regReq); err != nil {
		return fmt.Errorf("send register request: %w", err)
	}
	var regResp protocol.RegisterResponse
	if err := protocol.ReadTypedFrame(ctrlStream, protocol.FrameRegisterResp, &regResp); err != nil {
		return fmt.Errorf("read register response: %w", err)
	}
	_ = ctrlStream.SetDeadline(time.Time{})

	if !regResp.OK {
		return fmt.Errorf("hub rejected registration [%s]: %s", regResp.Code, regResp.Message)
	}

	hbInterval := time.Duration(regResp.HeartbeatIntervalSec) * time.Second
	if hbInterval <= 0 {
		hbInterval = 15 * time.Second
	}

	c.logger.Info("registered with hub successfully",
		"session_id", regResp.SessionID,
		"transport", activeTransport,
		"lane", lane,
		"role", role,
		"services", len(regReq.Services),
		"heartbeat", hbInterval.String(),
	)
	if lane == 0 {
		c.readyOnce.Do(func() { close(c.readyCh) })
	}

	var ctrlWriteMu sync.Mutex
	writeCtrl := func(frameType uint8, msg any) error {
		ctrlWriteMu.Lock()
		defer ctrlWriteMu.Unlock()
		_ = ctrlStream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		defer func() { _ = ctrlStream.SetWriteDeadline(time.Time{}) }()
		return protocol.WriteFrame(ctrlStream, frameType, msg)
	}

	c.mu.Lock()
	c.activeCtrlMap[lane] = writeCtrl
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.activeCtrlMap, lane)
		c.mu.Unlock()
	}()

	// Registration succeeded: hand off shutdown lifecycle from initWatcher to graceful drain watcher.
	stopInitWatcher()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-parentCtx.Done():
			_ = writeCtrl(protocol.FrameDrain, protocol.DrainMessage{Reason: "agent_shutdown"})
			c.waitDrain(sessionCtx, drainTimeout)
			_ = muxSession.Close()
			cancelSession()
		case <-sessionCtx.Done():
		}
	}()

	ctrlErrCh := make(chan error, 1)
	go func() {
		ctrlErrCh <- c.runControlHeartbeat(sessionCtx, ctrlStream, hbInterval, writeCtrl)
	}()
	// Only lane 0 runs periodic health probes so multi-lane pools don't duplicate local DB probes.
	if lane == 0 {
		go c.runHealthReportLoop(sessionCtx, healthInterval, servicesCopy, writeCtrl)
	}

	acceptErrCh := make(chan error, 1)
	go func() {
		for {
			stream, err := muxSession.AcceptStream()
			if err != nil {
				acceptErrCh <- err
				return
			}
			c.activeStreams.Add(1)
			go func(s net.Conn) {
				defer func() {
					if c.activeStreams.Add(-1) == 0 {
						select {
						case c.streamZeroCh <- struct{}{}:
						default:
						}
					}
				}()
				c.handleDataStream(s)
			}(stream)
		}
	}()

	var exitErr error
	select {
	case exitErr = <-acceptErrCh:
	case exitErr = <-ctrlErrCh:
	}

	cancelSession()
	_ = muxSession.Close()
	<-shutdownDone
	return exitErr
}

// waitDrain waits until activeStreams drops to zero, sessionCtx ends (tunnel died), or timeout elapses
// without racing WaitGroup.Add/Wait or leaking waiter goroutines across multi-lane pools.
func (c *Client) waitDrain(sessionCtx context.Context, timeout time.Duration) {
	if c.activeStreams.Load() == 0 || timeout <= 0 {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.activeStreams.Load() == 0 {
			return
		}
		select {
		case <-c.streamZeroCh:
			if c.activeStreams.Load() == 0 {
				return
			}
		case <-sessionCtx.Done():
			return
		case <-ticker.C:
		case <-timer.C:
			return
		}
	}
}

func (c *Client) runControlHeartbeat(
	ctx context.Context,
	ctrlStream net.Conn,
	interval time.Duration,
	writeCtrl func(uint8, any) error,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			ping := protocol.PingMessage{SentAtUnixNano: time.Now().UnixNano()}
			if err := writeCtrl(protocol.FramePing, ping); err != nil {
				return fmt.Errorf("send ping: %w", err)
			}
			_ = ctrlStream.SetReadDeadline(time.Now().Add(interval))
			var pong protocol.PongMessage
			if err := protocol.ReadTypedFrame(ctrlStream, protocol.FramePong, &pong); err != nil {
				return fmt.Errorf("read pong: %w", err)
			}
			_ = ctrlStream.SetReadDeadline(time.Time{})
		}
	}
}

func (c *Client) handleDataStream(stream net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("recovered panic in agent data stream handler", "panic", r)
		}
		_ = stream.Close()
	}()

	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req protocol.StreamOpenRequest
	if err := protocol.ReadTypedFrame(stream, protocol.FrameStreamOpenReq, &req); err != nil {
		if !errors.Is(err, io.EOF) {
			c.logger.Warn("failed reading stream open request", "error", err)
		}
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	c.mu.RLock()
	audit := c.audit
	globalRx := c.globalRxLimiter
	globalTx := c.globalTxLimiter
	c.mu.RUnlock()

	entry, errCode, err := c.whitelist.Acquire(req.ServiceName, req.Protocol)
	if err != nil {
		audit.Record(AuditEvent{
			Event:       "stream_rejected",
			TraceID:     req.TraceID,
			Traceparent: req.Traceparent,
			TicketID:    req.TicketID,
			Caller:      req.CallerIdentity,
			Purpose:     req.Purpose,
			Service:     req.ServiceName,
			Protocol:    req.Protocol,
			Action:      errCode,
			Reason:      err.Error(),
		})
		_ = protocol.WriteFrame(stream, protocol.FrameStreamOpenResp, protocol.StreamOpenResponse{
			OK:      false,
			Code:    errCode,
			Message: err.Error(),
		})
		return
	}
	defer entry.Release()

	startDial := time.Now()
	localDialer := &net.Dialer{Timeout: entry.DialTimeout, KeepAlive: 30 * time.Second}
	var upstream net.Conn
	if entry.TargetTLS != nil && !entry.UsesStartTLS {
		// Direct TLS for MongoDB (--tlsMode requireTLS), Redis (--tls-port), internal HTTPS, and raw TLS TCP services.
		upstream, err = tls.DialWithDialer(localDialer, "tcp", entry.TargetAddr, entry.TargetTLS.Clone())
	} else {
		// Plaintext TCP (or STARTTLS upgraded inside MySQLProxy / PostgresProxy).
		upstream, err = localDialer.Dial("tcp", entry.TargetAddr)
	}
	if err != nil {
		audit.Record(AuditEvent{
			Event:       "stream_dial_failed",
			TraceID:     req.TraceID,
			Traceparent: req.Traceparent,
			TicketID:    req.TicketID,
			Caller:      req.CallerIdentity,
			Purpose:     req.Purpose,
			Service:     entry.Name,
			Protocol:    req.Protocol,
			Reason:      err.Error(),
		})
		_ = protocol.WriteFrame(stream, protocol.FrameStreamOpenResp, protocol.StreamOpenResponse{
			OK:      false,
			Code:    protocol.CodeDialFailed,
			Message: fmt.Sprintf("dial local service %q failed: %v", entry.Name, err),
		})
		return
	}
	defer func() { _ = upstream.Close() }()

	if err := protocol.WriteFrame(stream, protocol.FrameStreamOpenResp, protocol.StreamOpenResponse{OK: true}); err != nil {
		c.logger.Warn("failed writing stream open ack", "trace_id", req.TraceID, "error", err)
		return
	}

	audit.Record(AuditEvent{
		Event:       "stream_opened",
		TraceID:     req.TraceID,
		Traceparent: req.Traceparent,
		TicketID:    req.TicketID,
		Caller:      req.CallerIdentity,
		Purpose:     req.Purpose,
		Service:     entry.Name,
		Protocol:    req.Protocol,
	})

	shapedStream := transport.WrapConnWithLimiters(
		stream,
		[]*transport.BandwidthLimiter{entry.RxLimiter, globalRx},
		[]*transport.BandwidthLimiter{entry.TxLimiter, globalTx},
	)
	upstreamConn := transport.WrapConnWithIdleTimeout(upstream, entry.IdleTimeout)
	defer func() { _ = shapedStream.Close() }()

	var inBytes, outBytes int64
	if entry.Guard != nil {
		inBytes, outBytes, err = entry.Guard.Proxy(shapedStream, upstreamConn, func(protoName, action, reason string) {
			evName := "query_blocked"
			if protoName == "http" {
				evName = "http_blocked"
			}
			audit.Record(AuditEvent{
				Event:       evName,
				TraceID:     req.TraceID,
				Traceparent: req.Traceparent,
				TicketID:    req.TicketID,
				Caller:      req.CallerIdentity,
				Purpose:     req.Purpose,
				Service:     entry.Name,
				Protocol:    protoName,
				Action:      truncateLog(action, 160),
				Reason:      reason,
			})
		})
		if err != nil && !errors.Is(err, io.EOF) {
			c.logger.Debug("protocol guard session ended", "guard", entry.Guard.Type(), "trace_id", req.TraceID, "service", entry.Name, "error", err)
		}
	} else {
		inBytes, outBytes = transport.BidirectionalPipe(shapedStream, upstreamConn)
	}

	audit.Record(AuditEvent{
		Event:        "stream_closed",
		TraceID:      req.TraceID,
		Traceparent:  req.Traceparent,
		TicketID:     req.TicketID,
		Caller:       req.CallerIdentity,
		Purpose:      req.Purpose,
		Service:      entry.Name,
		Protocol:     req.Protocol,
		BytesFromHub: inBytes,
		BytesToHub:   outBytes,
		DurationMs:   time.Since(startDial).Milliseconds(),
	})
}

func truncateLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (c *Client) runHealthReportLoop(
	ctx context.Context,
	interval time.Duration,
	initialServices []ServiceConfig,
	writeCtrl func(uint8, any) error,
) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	sendOnce := func(svcs []ServiceConfig) {
		statuses := ProbeServicesSanitized(svcs)
		_ = writeCtrl(protocol.FrameHealthReport, protocol.HealthReportMessage{Services: statuses})
	}
	sendOnce(initialServices)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			svcs := append([]ServiceConfig(nil), c.cfg.Services...)
			c.mu.RUnlock()
			sendOnce(svcs)
		}
	}
}

// RotateDeviceCertNow immediately rotates the enrolled device certificate & token on disk.
func (c *Client) RotateDeviceCertNow(ctx context.Context) (*DeviceState, error) {
	c.mu.RLock()
	stateDir := c.cfg.DeviceStateDir
	tlsOpts := c.cfg.Server.TLS
	audit := c.audit
	c.mu.RUnlock()
	if stateDir == "" {
		return nil, errors.New("agent is not configured with device_state_dir")
	}
	newState, err := RenewDevice(ctx, stateDir, tlsOpts)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cfg.Token = newState.DeviceToken
	c.cfg.Server.TLS.CertFile = newState.CertFile
	c.cfg.Server.TLS.KeyFile = newState.KeyFile
	c.mu.Unlock()

	audit.Record(AuditEvent{
		Event:  "device_cert_rotated",
		Reason: fmt.Sprintf("rotated device cert serial=%s expires=%s", newState.CertSerial, newState.ExpiresAt.Format(time.RFC3339)),
	})
	return newState, nil
}

func (c *Client) watchCertRenewalLoop(ctx context.Context) {
	c.mu.RLock()
	stateDir := c.cfg.DeviceStateDir
	interval := c.cfg.CertRenewInterval
	c.mu.RUnlock()
	if stateDir == "" || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st, err := LoadDeviceState(stateDir)
			if err != nil {
				continue
			}
			if time.Until(st.ExpiresAt) < 48*time.Hour {
				if _, err := c.RotateDeviceCertNow(ctx); err != nil {
					c.logger.Warn("auto device cert rotation failed", "error", err)
				}
			}
		}
	}
}
