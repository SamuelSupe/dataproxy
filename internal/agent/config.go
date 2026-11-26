package agent

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"

	"gopkg.in/yaml.v3"
)

var safeIdentifierRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

// Config holds the full configuration for dataproxy-agent.
type Config struct {
	TenantID             string            `yaml:"tenant_id"`
	AgentID              string            `yaml:"agent_id"`
	DeviceID             string            `yaml:"device_id"`               // Auto-populated from device_state_dir when enrolled
	DeviceStateDir       string            `yaml:"device_state_dir"`        // Directory created by "dataproxy-agent enroll"
	Token                string            `yaml:"token"`
	Labels               map[string]string `yaml:"labels"`
	LogLevel             string            `yaml:"log_level"`
	MaxBandwidth         string            `yaml:"max_bandwidth"`           // Global cap, e.g. "20MB/s"
	Timezone             string            `yaml:"timezone"`                // IANA timezone for allowed_windows (default Local)
	AllowedWindows       []string          `yaml:"allowed_windows"`         // Global schedule, e.g. ["00:00-06:00", "Mon-Fri 22:00-02:00"]
	Audit                AuditConfig       `yaml:"audit"`                   // Local JSONL & optional SIEM/Syslog audit output
	ConfigWatchInterval  time.Duration     `yaml:"config_watch_interval"`   // Hot-reload poll interval (default 3s)
	HealthReportInterval time.Duration     `yaml:"health_report_interval"`  // Local service health probe & report interval (default 30s)
	CertRenewInterval    time.Duration     `yaml:"cert_renew_interval"`     // Enrolled device cert check interval (default 10m)
	PoolSize             int               `yaml:"pool_size"`               // Multi-connection tunnel pool size (1=single, 2..16=control+parallel data lanes)
	DrainTimeout         time.Duration     `yaml:"drain_timeout"`
	ReconnectMinWait     time.Duration     `yaml:"reconnect_min_wait"`
	ReconnectMaxWait     time.Duration     `yaml:"reconnect_max_wait"`
	Server               ServerConfig      `yaml:"server"`
	Services             []ServiceConfig   `yaml:"services"`

	maxBandwidthBytes int64
	globalWindows     *TimeWindowChecker
}

// ServerConfig specifies how the agent dials the central hub.
type ServerConfig struct {
	Mode        string               `yaml:"mode"`     // "wss" (default), "quic", "auto" (quic -> wss fallback), "tls", or "tcp" (dev)
	URL         string               `yaml:"url"`      // WSS/TLS URL (also used as WSS fallback target in "auto" mode)
	QUICURL     string               `yaml:"quic_url"` // Optional QUIC UDP host:port override (defaults to host:port from url)
	ProxyURL    string               `yaml:"proxy_url"`
	DialTimeout time.Duration        `yaml:"dial_timeout"`
	TLS         transport.TLSOptions `yaml:"tls"`
}

// CredentialInjectionConfig configures tenant-local database credential injection
// so real DB usernames/passwords never leave the tenant intranet.
type CredentialInjectionConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Username   string `yaml:"username"`    // Supports literal, "env:VAR", "file:/path"
	Password   string `yaml:"password"`    // Supports literal, "env:VAR", "file:/path"
	AuthSource string `yaml:"auth_source"` // MongoDB auth database (default "admin")
}

// ProtocolGuardConfig is the unified pluggable L7 database guard configuration.
type ProtocolGuardConfig struct {
	Type                string                     `yaml:"type"` // "mysql" | "postgres" | "mongodb" | "redis"
	ReadOnly            bool                       `yaml:"read_only"`
	CredentialInjection *CredentialInjectionConfig `yaml:"credential_injection"`
}

// MySQLCredentialInjection is kept as an alias for backwards compatibility with existing configs.
type MySQLCredentialInjection = CredentialInjectionConfig

// MySQLServiceConfig is kept for backwards compatibility; normalized into ServiceConfig.Guard.
type MySQLServiceConfig struct {
	ReadOnly            bool                       `yaml:"read_only"`
	CredentialInjection *CredentialInjectionConfig `yaml:"credential_injection"`
}

// TargetTLSConfig configures Split-TLS encryption between the tenant agent and
// the tenant's local intranet target (e.g. AWS/Aliyun RDS force_ssl, MySQL
// require_secure_transport=ON, MongoDB requireTLS, Redis TLS, or internal HTTPS).
type TargetTLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CAFile             string `yaml:"ca_file"`              // Optional custom/RDS root CA bundle PEM
	CertFile           string `yaml:"cert_file"`            // Optional client certificate for intranet mTLS
	KeyFile            string `yaml:"key_file"`             // Optional client private key for intranet mTLS
	ServerName         string `yaml:"server_name"`          // Optional SNI / hostname override (defaults to host from target_addr)
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // Skip cert verification (dev/self-signed only)
}

// BuildTLSConfig builds a *tls.Config for dialing targetAddr, or returns (nil, nil) if disabled.
func (t *TargetTLSConfig) BuildTLSConfig(targetAddr string) (*tls.Config, error) {
	if t == nil || !t.Enabled {
		return nil, nil
	}
	serverName := strings.TrimSpace(t.ServerName)
	if serverName == "" {
		if host, _, err := net.SplitHostPort(targetAddr); err == nil {
			serverName = host
		}
	}
	return transport.BuildClientTLSConfig(transport.TLSOptions{
		CAFile:             t.CAFile,
		CertFile:           t.CertFile,
		KeyFile:            t.KeyFile,
		ServerName:         serverName,
		InsecureSkipVerify: t.InsecureSkipVerify,
	})
}

// ServiceConfig declares a single local intranet target permitted in the allowlist.
type ServiceConfig struct {
	Name               string               `yaml:"name"`
	Protocol           string               `yaml:"protocol"`             // "tcp" or "http"
	TargetAddr         string               `yaml:"target_addr"`          // e.g. "10.0.1.15:3306"
	TargetTLS          *TargetTLSConfig     `yaml:"target_tls"`           // Optional Split-TLS for RDS/encrypted intranet backends
	Description        string               `yaml:"description"`
	MaxConns           int                  `yaml:"max_conns"`
	MaxBandwidth       string               `yaml:"max_bandwidth"`        // Per-service cap, e.g. "10MB/s"
	AllowedWindows     []string             `yaml:"allowed_windows"`      // Per-service schedule override/restriction
	DialTimeout        time.Duration        `yaml:"dial_timeout"`
	IdleTimeout        time.Duration        `yaml:"idle_timeout"`         // Optional idle connection reclamation timeout (e.g. 10m)
	AllowedHTTPMethods []string             `yaml:"allowed_http_methods"` // e.g. ["GET", "HEAD"] for read-only HTTP
	InjectHeaders      map[string]string    `yaml:"inject_headers"`       // Local HTTP credential header injection (e.g. Authorization: "Bearer env:ERP_TOKEN")
	Guard              *ProtocolGuardConfig `yaml:"guard"`                // Unified DB guard (mysql|postgres|mongodb|redis)
	MySQL              *MySQLServiceConfig  `yaml:"mysql"`                // Legacy shorthand for guard.type=mysql

	maxBandwidthBytes int64
	windows           *TimeWindowChecker
	targetTLSConfig   *tls.Config
}

// EffectiveGuard returns the normalized L7 database guard configuration for this service.
func (s *ServiceConfig) EffectiveGuard() *ProtocolGuardConfig {
	if s.Guard != nil {
		return s.Guard
	}
	if s.MySQL != nil {
		return &ProtocolGuardConfig{
			Type:                "mysql",
			ReadOnly:            s.MySQL.ReadOnly,
			CredentialInjection: s.MySQL.CredentialInjection,
		}
	}
	return nil
}

// LoadConfig reads, defaults, and validates an agent YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent config: %w", err)
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// NormalizeAndValidate applies sensible defaults and enforces strict config safety.
func (c *Config) NormalizeAndValidate() error {
	// If enrolled via "dataproxy-agent enroll", automatically hydrate identity & mTLS cert from device_state_dir.
	if strings.TrimSpace(c.DeviceStateDir) != "" {
		st, err := LoadDeviceState(c.DeviceStateDir)
		if err != nil {
			return fmt.Errorf("load device_state_dir: %w", err)
		}
		if c.TenantID == "" {
			c.TenantID = st.TenantID
		}
		c.DeviceID = st.DeviceID
		c.Token = st.DeviceToken
		if c.AgentID == "" {
			c.AgentID = st.DeviceID
		}
		if c.Server.TLS.CertFile == "" {
			c.Server.TLS.CertFile = st.CertFile
			c.Server.TLS.KeyFile = st.KeyFile
		}
	}

	c.TenantID = strings.TrimSpace(c.TenantID)
	if !safeIdentifierRe.MatchString(c.TenantID) {
		return fmt.Errorf("invalid tenant_id %q: must match %s", c.TenantID, safeIdentifierRe.String())
	}
	c.AgentID = strings.TrimSpace(c.AgentID)
	if c.AgentID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "agent-1"
		}
		c.AgentID = host
	}
	if strings.TrimSpace(c.Token) == "" {
		return errors.New("agent token cannot be empty")
	}
	if strings.TrimSpace(c.Server.URL) == "" {
		return errors.New("server.url cannot be empty")
	}
	if c.Server.Mode == "" {
		c.Server.Mode = "wss"
	}
	if c.Server.DialTimeout <= 0 {
		c.Server.DialTimeout = 15 * time.Second
	}
	if c.DrainTimeout <= 0 {
		c.DrainTimeout = 10 * time.Second
	}
	if c.ReconnectMinWait <= 0 {
		c.ReconnectMinWait = 1 * time.Second
	}
	if c.ReconnectMaxWait <= 0 {
		c.ReconnectMaxWait = 30 * time.Second
	}
	if c.ConfigWatchInterval <= 0 {
		c.ConfigWatchInterval = 3 * time.Second
	}
	if c.HealthReportInterval <= 0 {
		c.HealthReportInterval = 30 * time.Second
	}
	if c.CertRenewInterval <= 0 {
		c.CertRenewInterval = 10 * time.Minute
	}
	if c.PoolSize <= 0 {
		c.PoolSize = 1
	}
	if c.PoolSize > 16 {
		c.PoolSize = 16
	}

	globalBW, err := transport.ParseBandwidth(c.MaxBandwidth)
	if err != nil {
		return fmt.Errorf("global max_bandwidth: %w", err)
	}
	c.maxBandwidthBytes = globalBW

	globalWin, err := NewTimeWindowChecker(c.AllowedWindows, c.Timezone)
	if err != nil {
		return fmt.Errorf("global allowed_windows: %w", err)
	}
	c.globalWindows = globalWin

	if len(c.Services) == 0 {
		return errors.New("at least one whitelisted service must be configured")
	}

	seen := make(map[string]struct{}, len(c.Services))
	for i := range c.Services {
		svc := &c.Services[i]
		svc.Name = strings.TrimSpace(svc.Name)
		if !safeIdentifierRe.MatchString(svc.Name) {
			return fmt.Errorf("invalid service name %q: must match %s", svc.Name, safeIdentifierRe.String())
		}
		if _, dup := seen[svc.Name]; dup {
			return fmt.Errorf("duplicate service name %q", svc.Name)
		}
		seen[svc.Name] = struct{}{}

		svc.Protocol = strings.ToLower(strings.TrimSpace(svc.Protocol))
		if svc.Protocol != protocol.ProtocolTCP && svc.Protocol != protocol.ProtocolHTTP {
			return fmt.Errorf("service %q: unsupported protocol %q (expected tcp or http)", svc.Name, svc.Protocol)
		}
		if _, _, err := net.SplitHostPort(svc.TargetAddr); err != nil {
			return fmt.Errorf("service %q: invalid target_addr %q: %w", svc.Name, svc.TargetAddr, err)
		}
		if svc.MaxConns <= 0 {
			svc.MaxConns = 128
		}
		if svc.DialTimeout <= 0 {
			svc.DialTimeout = 5 * time.Second
		}

		svcBW, err := transport.ParseBandwidth(svc.MaxBandwidth)
		if err != nil {
			return fmt.Errorf("service %q max_bandwidth: %w", svc.Name, err)
		}
		svc.maxBandwidthBytes = svcBW

		svcWin, err := NewTimeWindowChecker(svc.AllowedWindows, c.Timezone)
		if err != nil {
			return fmt.Errorf("service %q allowed_windows: %w", svc.Name, err)
		}
		svc.windows = svcWin

		tlsCfg, err := svc.TargetTLS.BuildTLSConfig(svc.TargetAddr)
		if err != nil {
			return fmt.Errorf("service %q target_tls: %w", svc.Name, err)
		}
		svc.targetTLSConfig = tlsCfg

		if (len(svc.AllowedHTTPMethods) > 0 || len(svc.InjectHeaders) > 0) && svc.Protocol != protocol.ProtocolHTTP {
			return fmt.Errorf("service %q: allowed_http_methods and inject_headers are only valid for http services", svc.Name)
		}

		// Normalize legacy mysql shorthand into unified Guard.
		if svc.Guard == nil && svc.MySQL != nil {
			svc.Guard = &ProtocolGuardConfig{
				Type:                "mysql",
				ReadOnly:            svc.MySQL.ReadOnly,
				CredentialInjection: svc.MySQL.CredentialInjection,
			}
		}

		if svc.Guard != nil {
			svc.Guard.Type = strings.ToLower(strings.TrimSpace(svc.Guard.Type))
			switch svc.Guard.Type {
			case "mysql", "doris", "starrocks":
				// Apache Doris and StarRocks speak native MySQL v10 wire protocol.
				svc.Guard.Type = "mysql"
			case "postgres", "postgresql", "pg":
				svc.Guard.Type = "postgres"
			case "mongodb", "mongo":
				svc.Guard.Type = "mongodb"
			case "redis":
			case "mssql", "sqlserver":
				svc.Guard.Type = "mssql"
			case "oracle":
			case "clickhouse", "ch":
				svc.Guard.Type = "clickhouse"
			default:
				return fmt.Errorf("service %q: unsupported guard.type %q (expected mysql, doris, starrocks, postgres, mongodb, redis, mssql, oracle, or clickhouse)", svc.Name, svc.Guard.Type)
			}

			if svc.Protocol != protocol.ProtocolTCP && svc.Guard.Type != "clickhouse" {
				return fmt.Errorf("service %q: database guard %q is only valid for tcp services", svc.Name, svc.Guard.Type)
			}

			if inj := svc.Guard.CredentialInjection; inj != nil && inj.Enabled {
				if svc.Guard.Type != "redis" && strings.TrimSpace(inj.Username) == "" {
					return fmt.Errorf("service %q: guard.credential_injection.username is required for %s", svc.Name, svc.Guard.Type)
				}
				if svc.Guard.Type == "redis" && strings.TrimSpace(inj.Password) == "" {
					return fmt.Errorf("service %q: guard.credential_injection.password is required for redis", svc.Name)
				}
			}
		}
	}
	return nil
}

// Announcements returns the privacy-preserving logical service metadata sent to the hub.
// Notice target_addr and local DB credentials are strictly withheld from the announcement.
func (c *Config) Announcements() []protocol.ServiceAnnouncement {
	out := make([]protocol.ServiceAnnouncement, 0, len(c.Services))
	for _, s := range c.Services {
		out = append(out, protocol.ServiceAnnouncement{
			Name:        s.Name,
			Protocol:    s.Protocol,
			Description: s.Description,
		})
	}
	return out
}
