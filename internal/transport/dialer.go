package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

// TLSOptions configures client or server TLS / mTLS behavior.
type TLSOptions struct {
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	CAFile             string `yaml:"ca_file"`
	ClientCAFile       string `yaml:"client_ca_file"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	RequireClientCert  bool   `yaml:"require_client_cert"`
}

// BuildClientTLSConfig creates a *tls.Config for the agent connecting to the hub.
func BuildClientTLSConfig(opts TLSOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         opts.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	if opts.CAFile != "" {
		pemBytes, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("parse ca_file: no valid PEM certificates found")
		}
		cfg.RootCAs = pool
	}
	if opts.CertFile != "" || opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// BuildServerTLSConfig creates a *tls.Config for the hub accepting agent connections.
func BuildServerTLSConfig(opts TLSOptions) (*tls.Config, error) {
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	caPath := opts.ClientCAFile
	if caPath == "" {
		caPath = opts.CAFile
	}
	if caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("parse client_ca_file: no valid PEM certificates found")
		}
		cfg.ClientCAs = pool
		if opts.RequireClientCert {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if opts.RequireClientCert {
		return nil, fmt.Errorf("require_client_cert is enabled but client_ca_file is empty")
	}
	return cfg, nil
}

// DefaultYamuxConfig returns a yamux configuration tuned for high-throughput
// database result streaming and fast stale-stream cleanup across WAN links.
func DefaultYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024 // 4 MiB per-stream BDP window for WAN DB streaming
	cfg.LogOutput = io.Discard
	return cfg
}

// DialConfig holds parameters for agent outbound tunnel dialing.
type DialConfig struct {
	Mode        string // "wss", "quic", "auto" (quic -> wss fallback), "tls", or "tcp"
	URL         string // e.g. "wss://hub:8443/tunnel/v1/connect" or "hub:8443"
	QUICURL     string // optional QUIC host:port override for "auto" / "quic" mode
	ProxyURL    string // optional HTTP/HTTPS proxy URL for WSS mode
	DialTimeout time.Duration
	TLS         TLSOptions
}

const (
	quicHappyEyeballsDelay = 250 * time.Millisecond
	quicNegativeCacheTTL   = 60 * time.Second
)

var (
	quicNegMu    sync.RWMutex
	quicNegCache = make(map[string]time.Time)
)

func isQUICNegativelyCached(addr string) bool {
	quicNegMu.RLock()
	until, ok := quicNegCache[addr]
	quicNegMu.RUnlock()
	return ok && time.Now().Before(until)
}

func markQUICUnavailable(addr string) {
	if addr == "" {
		return
	}
	quicNegMu.Lock()
	quicNegCache[addr] = time.Now().Add(quicNegativeCacheTTL)
	quicNegMu.Unlock()
}

func clearQUICUnavailable(addr string) {
	if addr == "" {
		return
	}
	quicNegMu.Lock()
	delete(quicNegCache, addr)
	quicNegMu.Unlock()
}

// ClearQUICNegativeCache resets the auto-mode QUIC failure backoff cache (useful in tests).
func ClearQUICNegativeCache() {
	quicNegMu.Lock()
	clear(quicNegCache)
	quicNegMu.Unlock()
}

// DialTunnelMux establishes an outbound multiplexed tunnel session to the hub.
// - "quic": native QUIC over UDP + TLS 1.3 (zero Yamux overhead).
// - "auto": Happy-Eyeballs QUIC-first (250ms head-start) with parallel WSS fallback
//   and 60s negative caching when UDP is blocked by a corporate firewall.
// - "wss" / "tls" / "tcp": dials via DialTunnel and wraps in Yamux.
func DialTunnelMux(sessionCtx context.Context, cfg DialConfig) (StreamMux, string, error) {
	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "wss"
	}

	switch mode {
	case "quic":
		mux, err := dialQUICMux(sessionCtx, cfg, timeout)
		if err != nil {
			return nil, "", err
		}
		return mux, "quic", nil

	case "auto":
		// Skip QUIC immediately if an enterprise HTTP forward proxy is configured.
		if hasOutboundHTTPProxy(cfg) {
			return dialWSSFallbackMux(sessionCtx, cfg)
		}
		quicAddr, addrErr := resolveQUICAddr(cfg)
		if addrErr != nil || isQUICNegativelyCached(quicAddr) {
			return dialWSSFallbackMux(sessionCtx, cfg)
		}
		return dialAutoHappyEyeballs(sessionCtx, cfg, quicAddr, timeout)

	default:
		conn, err := DialTunnel(sessionCtx, cfg)
		if err != nil {
			return nil, "", err
		}
		ymux, err := yamux.Client(conn, DefaultYamuxConfig())
		if err != nil {
			_ = conn.Close()
			return nil, "", fmt.Errorf("init yamux client: %w", err)
		}
		return NewYamuxMux(ymux, conn), mode, nil
	}
}

func dialWSSFallbackMux(sessionCtx context.Context, cfg DialConfig) (StreamMux, string, error) {
	fallbackCfg := cfg
	fallbackCfg.Mode = "wss"
	conn, err := DialTunnel(sessionCtx, fallbackCfg)
	if err != nil {
		return nil, "", fmt.Errorf("auto mode failed (wss fallback failed): %w", err)
	}
	ymux, err := yamux.Client(conn, DefaultYamuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("init yamux client: %w", err)
	}
	return NewYamuxMux(ymux, conn), "wss", nil
}

// dialAutoHappyEyeballs gives QUIC a 250ms head-start; if QUIC hasn't connected yet
// (e.g. corporate firewall silently blackholing UDP), WSS dials in parallel and the
// first successful transport wins while the slower attempt is cleanly canceled.
func dialAutoHappyEyeballs(sessionCtx context.Context, cfg DialConfig, quicAddr string, timeout time.Duration) (StreamMux, string, error) {
	type dialRes struct {
		mux       StreamMux
		transport string
		err       error
	}

	quicCtx, cancelQUIC := context.WithCancel(sessionCtx)
	defer cancelQUIC()
	quicCh := make(chan dialRes, 1)
	go func() {
		probeTimeout := timeout
		if probeTimeout > 3*time.Second {
			probeTimeout = 3 * time.Second
		}
		mux, err := dialQUICMux(quicCtx, cfg, probeTimeout)
		quicCh <- dialRes{mux: mux, transport: "quic", err: err}
	}()

	headStart := quicHappyEyeballsDelay
	if timeout/2 < headStart {
		headStart = timeout / 2
	}
	timer := time.NewTimer(headStart)
	defer timer.Stop()

	select {
	case qres := <-quicCh:
		if qres.err == nil {
			clearQUICUnavailable(quicAddr)
			return qres.mux, "quic", nil
		}
		cancelQUIC()
		markQUICUnavailable(quicAddr)
		return dialWSSFallbackMux(sessionCtx, cfg)

	case <-sessionCtx.Done():
		cancelQUIC()
		go func() {
			if qres := <-quicCh; qres.mux != nil {
				_ = qres.mux.Close()
			}
		}()
		return nil, "", sessionCtx.Err()

	case <-timer.C:
		// QUIC did not finish within head-start; race WSS in parallel!
	}

	wssCtx, cancelWSS := context.WithCancel(sessionCtx)
	wssCh := make(chan dialRes, 1)
	go func() {
		mux, tr, err := dialWSSFallbackMux(wssCtx, cfg)
		if err == nil {
			if ym, ok := mux.(*yamuxMux); ok {
				ym.onClose = cancelWSS
			}
		} else {
			cancelWSS()
		}
		wssCh <- dialRes{mux: mux, transport: tr, err: err}
	}()

	var quicErr, wssErr error
	quicDone, wssDone := false, false
	for !quicDone || !wssDone {
		select {
		case qres := <-quicCh:
			quicDone = true
			if qres.err == nil {
				clearQUICUnavailable(quicAddr)
				cancelWSS()
				if !wssDone {
					go func() {
						if wres := <-wssCh; wres.mux != nil {
							_ = wres.mux.Close()
						}
					}()
				}
				return qres.mux, "quic", nil
			}
			quicErr = qres.err
			markQUICUnavailable(quicAddr)

		case wres := <-wssCh:
			wssDone = true
			if wres.err == nil {
				cancelQUIC()
				markQUICUnavailable(quicAddr)
				if !quicDone {
					go func() {
						if qres := <-quicCh; qres.mux != nil {
							_ = qres.mux.Close()
						}
					}()
				}
				return wres.mux, "wss", nil
			}
			wssErr = wres.err

		case <-sessionCtx.Done():
			cancelQUIC()
			cancelWSS()
			if !quicDone {
				go func() {
					if qres := <-quicCh; qres.mux != nil {
						_ = qres.mux.Close()
					}
				}()
			}
			if !wssDone {
				go func() {
					if wres := <-wssCh; wres.mux != nil {
						_ = wres.mux.Close()
					}
				}()
			}
			return nil, "", sessionCtx.Err()
		}
	}

	cancelQUIC()
	cancelWSS()
	return nil, "", fmt.Errorf("auto mode failed (quic: %v; wss: %w)", quicErr, wssErr)
}

func dialQUICMux(sessionCtx context.Context, cfg DialConfig, timeout time.Duration) (StreamMux, error) {
	addr, err := resolveQUICAddr(cfg)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := BuildClientTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}
	qTLS := PrepareQUICTLSConfig(tlsCfg)
	if qTLS.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			qTLS.ServerName = host
		}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve quic addr %s: %w", addr, err)
	}
	localUDP, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("open local udp socket for quic: %w", err)
	}
	tuneUDPSocketBuffers(localUDP)

	tr := &quic.Transport{Conn: localUDP}
	dialCtx, cancel := context.WithTimeout(sessionCtx, timeout)
	defer cancel()

	qconn, err := tr.Dial(dialCtx, udpAddr, qTLS, DefaultQUICConfig())
	if err != nil {
		_ = tr.Close()
		_ = localUDP.Close()
		return nil, fmt.Errorf("dial quic %s: %w", addr, err)
	}
	return &ownedQUICMux{
		quicMux: quicMux{conn: qconn},
		tr:      tr,
		udpConn: localUDP,
	}, nil
}

type ownedQUICMux struct {
	quicMux
	tr      *quic.Transport
	udpConn *net.UDPConn
}

func (o *ownedQUICMux) Close() error {
	err := o.quicMux.Close()
	if o.tr != nil {
		_ = o.tr.Close()
	}
	if o.udpConn != nil {
		_ = o.udpConn.Close()
	}
	return err
}

func resolveQUICAddr(cfg DialConfig) (string, error) {
	raw := strings.TrimSpace(cfg.QUICURL)
	if raw == "" {
		raw = strings.TrimSpace(cfg.URL)
	}
	raw = strings.TrimPrefix(raw, "quic://")
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse quic target url %q: %w", raw, err)
		}
		host := u.Host
		if host == "" {
			return "", fmt.Errorf("empty host in quic target url %q", raw)
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "443")
		}
		return host, nil
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		return "", fmt.Errorf("invalid quic address %q: %w", raw, err)
	}
	return raw, nil
}

func hasOutboundHTTPProxy(cfg DialConfig) bool {
	if strings.TrimSpace(cfg.ProxyURL) != "" {
		return true
	}
	if u, err := url.Parse(cfg.URL); err == nil && u.Host != "" {
		req := &http.Request{URL: u}
		if p, err := http.ProxyFromEnvironment(req); err == nil && p != nil {
			return true
		}
	}
	return false
}

// DialTunnel establishes an outbound connection to the hub over WSS or raw TLS
// and returns a net.Conn ready for yamux multiplexing.
// sessionCtx bounds the lifetime of the WebSocket NetConn (do NOT pass a short dial timeout context).
func DialTunnel(sessionCtx context.Context, cfg DialConfig) (net.Conn, error) {
	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tlsCfg, err := BuildClientTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "wss"
	}

	switch mode {
	case "wss", "ws":
		proxyFn := http.ProxyFromEnvironment
		if cfg.ProxyURL != "" {
			parsed, err := url.Parse(cfg.ProxyURL)
			if err != nil {
				return nil, fmt.Errorf("parse proxy_url: %w", err)
			}
			proxyFn = http.ProxyURL(parsed)
		}
		httpTransport := &http.Transport{
			Proxy:               proxyFn,
			TLSClientConfig:     tlsCfg,
			DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
		}
		httpClient := &http.Client{Transport: httpTransport}

		dialCtx, cancel := context.WithTimeout(sessionCtx, timeout)
		defer cancel()

		wsConn, _, err := websocket.Dial(dialCtx, cfg.URL, &websocket.DialOptions{
			HTTPClient:   httpClient,
			Subprotocols: []string{"dataproxy-v1"},
		})
		if err != nil {
			httpTransport.CloseIdleConnections()
			return nil, fmt.Errorf("dial wss %s: %w", cfg.URL, err)
		}
		return websocket.NetConn(sessionCtx, wsConn, websocket.MessageBinary), nil

	case "tls":
		addr := strings.TrimPrefix(cfg.URL, "tls://")
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second},
			Config:    tlsCfg,
		}
		dialCtx, cancel := context.WithTimeout(sessionCtx, timeout)
		defer cancel()
		conn, err := dialer.DialContext(dialCtx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dial tls %s: %w", addr, err)
		}
		return conn, nil

	case "tcp":
		addr := strings.TrimPrefix(cfg.URL, "tcp://")
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		dialCtx, cancel := context.WithTimeout(sessionCtx, timeout)
		defer cancel()
		conn, err := dialer.DialContext(dialCtx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dial tcp %s: %w", addr, err)
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unsupported tunnel mode %q (expected wss, tls, or tcp)", cfg.Mode)
	}
}
