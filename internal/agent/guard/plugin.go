package guard

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
)

// BlockCallback reports a blocked protocol operation (e.g. write SQL, disallowed HTTP method)
// for structured tenant compliance audit logging.
type BlockCallback func(proto, action, reason string)

// GuardSpec is the uniform configuration passed to ProtocolGuard factories.
type GuardSpec struct {
	Type               string
	ReadOnly           bool
	InjectCreds        bool
	UsernameSpec       string
	PasswordSpec       string
	AuthSource         string
	TargetTLS          *tls.Config // Optional Split-TLS config (STARTTLS for mysql/postgres)
	AllowedHTTPMethods []string
	InjectHeaders      map[string]string
}

// ProtocolGuard is the pluggable L7 tenant-side protocol interceptor interface.
// Adding a new database or RPC protocol (e.g. ClickHouse, SQL Server, Kafka)
// only requires implementing this interface and calling RegisterGuardFactory.
type ProtocolGuard interface {
	Type() string
	Proxy(clientConn, upstreamConn net.Conn, onBlocked BlockCallback) (bytesIn, bytesOut int64, err error)
	BlockedCount() int64
}

// GuardFactory constructs a ProtocolGuard from a GuardSpec. Returning (nil, nil) means pass-through.
type GuardFactory func(spec GuardSpec) (ProtocolGuard, error)

var (
	guardRegistryMu sync.RWMutex
	guardFactories  = make(map[string]GuardFactory)
)

// RegisterGuardFactory registers a named L7 protocol guard plugin.
func RegisterGuardFactory(name string, factory GuardFactory) {
	guardRegistryMu.Lock()
	guardFactories[strings.ToLower(strings.TrimSpace(name))] = factory
	guardRegistryMu.Unlock()
}

// BuildGuard looks up the registered factory for spec.Type and builds a ProtocolGuard.
func BuildGuard(spec GuardSpec) (ProtocolGuard, error) {
	kind := strings.ToLower(strings.TrimSpace(spec.Type))
	if kind == "" {
		return nil, nil
	}
	guardRegistryMu.RLock()
	factory, ok := guardFactories[kind]
	guardRegistryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("guard: unsupported protocol guard type %q", spec.Type)
	}
	return factory(spec)
}

func init() {
	RegisterGuardFactory("mysql", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := MySQLGuardConfig{
			ReadOnly:     spec.ReadOnly,
			InjectCreds:  spec.InjectCreds,
			UsernameSpec: spec.UsernameSpec,
			PasswordSpec: spec.PasswordSpec,
			TargetTLS:    spec.TargetTLS,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &mysqlGuardAdapter{p: NewMySQLProxy(cfg)}, nil
	})

	RegisterGuardFactory("postgres", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := PostgresGuardConfig{
			ReadOnly:     spec.ReadOnly,
			InjectCreds:  spec.InjectCreds,
			UsernameSpec: spec.UsernameSpec,
			PasswordSpec: spec.PasswordSpec,
			TargetTLS:    spec.TargetTLS,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &postgresGuardAdapter{p: NewPostgresProxy(cfg)}, nil
	})

	RegisterGuardFactory("mongodb", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := MongoGuardConfig{
			ReadOnly:     spec.ReadOnly,
			InjectCreds:  spec.InjectCreds,
			UsernameSpec: spec.UsernameSpec,
			PasswordSpec: spec.PasswordSpec,
			AuthSource:   spec.AuthSource,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &mongoGuardAdapter{p: NewMongoProxy(cfg)}, nil
	})

	RegisterGuardFactory("redis", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := RedisGuardConfig{
			ReadOnly:     spec.ReadOnly,
			InjectCreds:  spec.InjectCreds,
			UsernameSpec: spec.UsernameSpec,
			PasswordSpec: spec.PasswordSpec,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &redisGuardAdapter{p: NewRedisProxy(cfg)}, nil
	})

	RegisterGuardFactory("http", func(spec GuardSpec) (ProtocolGuard, error) {
		g := NewHTTPMethodGuard(spec.AllowedHTTPMethods, spec.InjectHeaders)
		if g == nil {
			return nil, nil
		}
		return &httpGuardAdapter{g: g}, nil
	})

	RegisterGuardFactory("mssql", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := MSSQLGuardConfig{
			ReadOnly:     spec.ReadOnly,
			InjectCreds:  spec.InjectCreds,
			UsernameSpec: spec.UsernameSpec,
			PasswordSpec: spec.PasswordSpec,
			TargetTLS:    spec.TargetTLS,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &mssqlGuardAdapter{p: NewMSSQLProxy(cfg)}, nil
	})

	RegisterGuardFactory("oracle", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := OracleGuardConfig{
			ReadOnly:  spec.ReadOnly,
			TargetTLS: spec.TargetTLS,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &oracleGuardAdapter{p: NewOracleProxy(cfg)}, nil
	})

	RegisterGuardFactory("clickhouse", func(spec GuardSpec) (ProtocolGuard, error) {
		cfg := ClickHouseGuardConfig{
			ReadOnly:     spec.ReadOnly,
			InjectCreds:  spec.InjectCreds,
			UsernameSpec: spec.UsernameSpec,
			PasswordSpec: spec.PasswordSpec,
		}
		if !cfg.Enabled() {
			return nil, nil
		}
		return &clickhouseGuardAdapter{p: NewClickHouseProxy(cfg)}, nil
	})
}

type mysqlGuardAdapter struct{ p *MySQLProxy }

func (a *mysqlGuardAdapter) Type() string        { return "mysql" }
func (a *mysqlGuardAdapter) BlockedCount() int64 { return a.p.BlockedQueries() }
func (a *mysqlGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(_ byte, sqlText, reason string) {
		if onBlocked != nil {
			onBlocked("mysql", sqlText, reason)
		}
	})
}

type postgresGuardAdapter struct{ p *PostgresProxy }

func (a *postgresGuardAdapter) Type() string        { return "postgres" }
func (a *postgresGuardAdapter) BlockedCount() int64 { return a.p.BlockedQueries() }
func (a *postgresGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(_ byte, sqlText, reason string) {
		if onBlocked != nil {
			onBlocked("postgres", sqlText, reason)
		}
	})
}

type mongoGuardAdapter struct{ p *MongoProxy }

func (a *mongoGuardAdapter) Type() string        { return "mongodb" }
func (a *mongoGuardAdapter) BlockedCount() int64 { return a.p.BlockedCommands() }
func (a *mongoGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(cmd, reason string) {
		if onBlocked != nil {
			onBlocked("mongodb", cmd, reason)
		}
	})
}

type redisGuardAdapter struct{ p *RedisProxy }

func (a *redisGuardAdapter) Type() string        { return "redis" }
func (a *redisGuardAdapter) BlockedCount() int64 { return a.p.BlockedCommands() }
func (a *redisGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(cmd, reason string) {
		if onBlocked != nil {
			onBlocked("redis", cmd, reason)
		}
	})
}

type httpGuardAdapter struct{ g *HTTPMethodGuard }

func (a *httpGuardAdapter) Type() string        { return "http" }
func (a *httpGuardAdapter) BlockedCount() int64 { return a.g.BlockedCount() }
func (a *httpGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	inB, outB := a.g.Proxy(c, u, func(method, path string) {
		if onBlocked != nil {
			onBlocked("http", method+" "+path, "HTTP method blocked by tenant read-only policy")
		}
	})
	return inB, outB, nil
}

type mssqlGuardAdapter struct{ p *MSSQLProxy }

func (a *mssqlGuardAdapter) Type() string        { return "mssql" }
func (a *mssqlGuardAdapter) BlockedCount() int64 { return a.p.BlockedQueries() }
func (a *mssqlGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(action, reason string) {
		if onBlocked != nil {
			onBlocked("mssql", action, reason)
		}
	})
}

type oracleGuardAdapter struct{ p *OracleProxy }

func (a *oracleGuardAdapter) Type() string        { return "oracle" }
func (a *oracleGuardAdapter) BlockedCount() int64 { return a.p.BlockedQueries() }
func (a *oracleGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(sqlText, reason string) {
		if onBlocked != nil {
			onBlocked("oracle", sqlText, reason)
		}
	})
}

type clickhouseGuardAdapter struct{ p *ClickHouseProxy }

func (a *clickhouseGuardAdapter) Type() string        { return "clickhouse" }
func (a *clickhouseGuardAdapter) BlockedCount() int64 { return a.p.BlockedQueries() }
func (a *clickhouseGuardAdapter) Proxy(c, u net.Conn, onBlocked BlockCallback) (int64, int64, error) {
	return a.p.Proxy(c, u, func(sqlText, reason string) {
		if onBlocked != nil {
			onBlocked("clickhouse", sqlText, reason)
		}
	})
}
