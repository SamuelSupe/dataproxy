package hub

import (
	"fmt"
	"os"
	"strings"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/internal/transport"

	"gopkg.in/yaml.v3"
)

// Config holds the full configuration for dataproxy-hub.
type Config struct {
	LogLevel string `yaml:"log_level"`

	// Tunnel listeners (agent -> hub).
	TunnelWSSAddr string               `yaml:"tunnel_wss_addr"` // e.g. ":8443"
	TunnelWSSPath string               `yaml:"tunnel_wss_path"` // default "/tunnel/v1/connect"
	TunnelTLSAddr string               `yaml:"tunnel_tls_addr"` // optional raw mTLS/TLS TCP listener, e.g. ":9443"
	TunnelTLS     transport.TLSOptions `yaml:"tunnel_tls"`

	// Central platform ingress listeners (central callers -> hub).
	ProxyAddr           string `yaml:"proxy_addr"`            // Unified SOCKS5 + HTTP CONNECT listener, e.g. "127.0.0.1:1080"
	HTTPAddr            string `yaml:"http_addr"`             // Standard HTTP/WS reverse proxy listener, e.g. "127.0.0.1:8080"
	PGSmartAddr         string `yaml:"pg_smart_addr"`         // Single-port multi-tenant PostgreSQL Ticket router, e.g. ":5432"
	MySQLSmartAddr      string `yaml:"mysql_smart_addr"`      // Single-port multi-tenant MySQL Ticket router, e.g. ":3306"
	MongoSmartAddr      string `yaml:"mongo_smart_addr"`      // Single-port multi-tenant MongoDB Ticket router (SASL PLAIN), e.g. ":27017"
	RedisSmartAddr      string `yaml:"redis_smart_addr"`      // Single-port multi-tenant Redis Ticket router, e.g. ":6379"
	VirtualDomainSuffix string `yaml:"virtual_domain_suffix"` // e.g. "dataproxy.internal"

	// Control plane, persistence, cluster mesh, short-lived job tickets, and device PKI.
	StateFile          string        `yaml:"state_file"`          // Optional crash-safe JSON control-plane state file
	NodeID             string        `yaml:"node_id"`             // Optional node identifier in multi-node hub cluster
	MeshListenAddr     string        `yaml:"mesh_listen_addr"`    // Optional Hub-to-Hub peer forwarding listener, e.g. ":7946"
	MeshSecret         string        `yaml:"mesh_secret"`         // Shared secret authenticating Hub-to-Hub mesh forwarding
	MeshPeers          []string      `yaml:"mesh_peers"`          // Peer Hub mesh addresses for transparent cross-node routing
	AdminAddr          string        `yaml:"admin_addr"`          // e.g. "127.0.0.1:9090"
	AdminToken         string        `yaml:"admin_token"`         // Bearer token protecting /api/v1/*
	TicketSigningKey   string        `yaml:"ticket_signing_key"`  // HMAC-SHA256 secret for HS256 job tickets
	TicketDefaultTTL   time.Duration `yaml:"ticket_default_ttl"`  // Default 5m
	DeviceCACertFile   string        `yaml:"device_ca_cert_file"` // Optional persistent Device CA cert (auto-generated if empty)
	DeviceCAKeyFile    string        `yaml:"device_ca_key_file"`  // Optional persistent Device CA key
	DeviceCertTTL      time.Duration `yaml:"device_cert_ttl"`     // Short-lived enrolled device cert TTL (default 7d)
	EnrollmentTTL      time.Duration `yaml:"enrollment_ttl"`      // One-time enrollment code TTL (default 15m)
	HeartbeatInterval  time.Duration `yaml:"heartbeat_interval"`
	StreamOpenTimeout  time.Duration `yaml:"stream_open_timeout"`

	// Noisy-neighbor isolation & DoS protection.
	MaxStreamsPerTenant      int     `yaml:"max_streams_per_tenant"`       // Hub-side concurrent stream quota per tenant (0 = unlimited)
	MaxSessionsPerTenant     int     `yaml:"max_sessions_per_tenant"`      // Hub-side concurrent session quota per tenant (0 = unlimited)
	HandshakeRateLimitPerMin float64 `yaml:"handshake_rate_limit_per_min"` // Per-IP rate limit on /tunnel/v1/* (0 = unlimited)
	HandshakeBurst           int     `yaml:"handshake_burst"`              // Per-IP token bucket burst for /tunnel/v1/*

	// Security & initial bindings.
	AllowUnauthenticatedCallers bool                `yaml:"allow_unauthenticated_callers"`
	Tenants                     []auth.TenantRecord `yaml:"tenants"`
	Callers                     []auth.CallerPolicy `yaml:"callers"`
	TCPBindings                 []TCPBindingSpec    `yaml:"tcp_bindings"`
}

// TCPBindingSpec defines a static or dynamically allocated TCP port mapping on the hub.
type TCPBindingSpec struct {
	ID           string        `yaml:"id" json:"id"`
	ListenAddr   string        `yaml:"listen_addr" json:"listen_addr"` // e.g. "127.0.0.1:23306" or "127.0.0.1:0"
	TenantID     string        `yaml:"tenant_id" json:"tenant_id"`
	ServiceName  string        `yaml:"service_name" json:"service_name"`
	AllowedCIDRs []string      `yaml:"allowed_cidrs,omitempty" json:"allowed_cidrs,omitempty"`
	TTL          time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

// LoadConfig reads and validates a hub YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read hub config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse hub config: %w", err)
	}
	cfg.Normalize()
	return &cfg, nil
}

// Normalize applies sensible defaults to optional hub fields.
func (c *Config) Normalize() {
	if strings.TrimSpace(c.TunnelWSSPath) == "" {
		c.TunnelWSSPath = "/tunnel/v1/connect"
	}
	if strings.TrimSpace(c.VirtualDomainSuffix) == "" {
		c.VirtualDomainSuffix = "dataproxy.internal"
	}
	c.VirtualDomainSuffix = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(c.VirtualDomainSuffix)), ".")
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 15 * time.Second
	}
	if c.StreamOpenTimeout <= 0 {
		c.StreamOpenTimeout = 10 * time.Second
	}
}
