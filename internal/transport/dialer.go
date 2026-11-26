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
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
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
	Mode        string // "wss" or "tls"
	URL         string // e.g. "wss://hub:8443/tunnel/v1/connect" or "hub:9443"
	ProxyURL    string // optional HTTP/HTTPS proxy URL for WSS mode
	DialTimeout time.Duration
	TLS         TLSOptions
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
		}
		httpClient := &http.Client{Transport: httpTransport}

		dialCtx, cancel := context.WithTimeout(sessionCtx, timeout)
		defer cancel()

		wsConn, _, err := websocket.Dial(dialCtx, cfg.URL, &websocket.DialOptions{
			HTTPClient:   httpClient,
			Subprotocols: []string{"dataproxy-v1"},
		})
		if err != nil {
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
