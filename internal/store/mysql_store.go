package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
)

const mysqlOpTimeout = 5 * time.Second

// MySQLStore implements ClusterStore backed by a shared MySQL/MariaDB database
// for 3+ node HA Hub clusters, providing atomic Device CA bootstrap, cross-node
// single-use enrollment codes, and real-time synchronization of device revocations,
// device credentials, tenants, and TCP bindings.
type MySQLStore struct {
	db                    *sql.DB
	lastEnrollCleanupUnix atomic.Int64
}

var _ ClusterStore = (*MySQLStore)(nil)

// NewMySQLStore connects to MySQL using dsn (accepting either Go MySQL DSN format
// "user:pass@tcp(host:3306)/db" or URI format "mysql://user:pass@host:3306/db"),
// verifies connectivity, and auto-migrates the dataproxy control-plane schema.
func NewMySQLStore(dsn string) (*MySQLStore, error) {
	normalized, err := normalizeMySQLDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("store/mysql: invalid dsn: %w", err)
	}
	db, err := sql.Open("mysql", normalized)
	if err != nil {
		return nil, fmt.Errorf("store/mysql: open: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store/mysql: ping: %w", err)
	}

	ms := &MySQLStore{db: db}
	if err := ms.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store/mysql: migrate schema: %w", err)
	}
	return ms, nil
}

func normalizeMySQLDSN(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty mysql dsn")
	}
	if strings.HasPrefix(raw, "mysql://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		cfg := mysql.NewConfig()
		if u.User != nil {
			cfg.User = u.User.Username()
			cfg.Passwd, _ = u.User.Password()
		}
		host := u.Host
		if !strings.Contains(host, ":") {
			host += ":3306"
		}
		cfg.Net = "tcp"
		cfg.Addr = host
		cfg.DBName = strings.TrimPrefix(u.Path, "/")
		cfg.ParseTime = true
		cfg.Loc = time.UTC
		cfg.Timeout = 5 * time.Second
		cfg.ReadTimeout = 5 * time.Second
		cfg.WriteTimeout = 5 * time.Second
		if tlsMode := u.Query().Get("tls"); tlsMode != "" {
			cfg.TLSConfig = tlsMode
		}
		return cfg.FormatDSN(), nil
	}

	cfg, err := mysql.ParseDSN(raw)
	if err != nil {
		return "", err
	}
	cfg.ParseTime = true
	if cfg.Loc == nil {
		cfg.Loc = time.UTC
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return cfg.FormatDSN(), nil
}

func (m *MySQLStore) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS dpx_device_ca (
			id TINYINT NOT NULL PRIMARY KEY,
			cert_pem MEDIUMTEXT NOT NULL,
			key_pem MEDIUMTEXT NOT NULL,
			updated_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS dpx_tenants (
			tenant_id VARCHAR(128) NOT NULL PRIMARY KEY,
			token_hash VARCHAR(128) NOT NULL,
			disabled TINYINT(1) NOT NULL DEFAULT 0,
			require_mtls TINYINT(1) NOT NULL DEFAULT 0,
			updated_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS dpx_devices (
			device_id VARCHAR(128) NOT NULL PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			device_name VARCHAR(255) NOT NULL DEFAULT '',
			cert_serial VARCHAR(128) NOT NULL,
			token_hash_hex CHAR(64) NOT NULL,
			enrolled_at DATETIME(6) NOT NULL,
			cert_expires_at DATETIME(6) NOT NULL,
			last_rotated_at DATETIME(6) NULL,
			revoked TINYINT(1) NOT NULL DEFAULT 0,
			revoked_at DATETIME(6) NULL,
			revoked_reason VARCHAR(512) NOT NULL DEFAULT '',
			updated_at DATETIME(6) NOT NULL,
			INDEX idx_dpx_devices_tenant (tenant_id),
			INDEX idx_dpx_devices_updated (updated_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS dpx_enrollments (
			code VARCHAR(128) NOT NULL PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			device_name VARCHAR(255) NOT NULL DEFAULT '',
			expires_at DATETIME(6) NOT NULL,
			used TINYINT(1) NOT NULL DEFAULT 0,
			created_at DATETIME(6) NOT NULL,
			INDEX idx_dpx_enrollments_exp (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		`CREATE TABLE IF NOT EXISTS dpx_bindings (
			id VARCHAR(128) NOT NULL PRIMARY KEY,
			listen_addr VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			service_name VARCHAR(128) NOT NULL,
			allowed_cidrs_json TEXT NOT NULL,
			updated_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
	for _, stmt := range stmts {
		if _, err := m.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (m *MySQLStore) Close() error {
	if m == nil || m.db == nil {
		return nil
	}
	return m.db.Close()
}

func (m *MySQLStore) Load() (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()

	snap := &Snapshot{
		Tenants:  make(map[string]PersistedTenant),
		Devices:  make(map[string]PersistedDevice),
		Bindings: make(map[string]PersistedBinding),
	}

	var certPEM, keyPEM string
	err := m.db.QueryRowContext(ctx, `SELECT cert_pem, key_pem FROM dpx_device_ca WHERE id = 1`).Scan(&certPEM, &keyPEM)
	if err == nil {
		snap.DeviceCACertPEM = certPEM
		snap.DeviceCAKeyPEM = keyPEM
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store/mysql: load device ca: %w", err)
	}

	devices, tenants, err := m.loadClusterSyncCtx(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range tenants {
		snap.Tenants[t.TenantID] = t
	}
	for _, d := range devices {
		snap.Devices[d.DeviceID] = d
	}

	rows, err := m.db.QueryContext(ctx, `SELECT id, listen_addr, tenant_id, service_name, allowed_cidrs_json FROM dpx_bindings`)
	if err != nil {
		return nil, fmt.Errorf("store/mysql: load bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var b PersistedBinding
		var cidrsJSON string
		if err := rows.Scan(&b.ID, &b.ListenAddr, &b.TenantID, &b.ServiceName, &cidrsJSON); err != nil {
			return nil, err
		}
		if cidrsJSON != "" {
			_ = json.Unmarshal([]byte(cidrsJSON), &b.AllowedCIDRs)
		}
		snap.Bindings[b.ID] = b
	}
	return snap, rows.Err()
}

func (m *MySQLStore) SaveDeviceCA(certPEM, keyPEM string) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO dpx_device_ca (id, cert_pem, key_pem, updated_at)
		VALUES (1, ?, ?, ?)
		ON DUPLICATE KEY UPDATE cert_pem = VALUES(cert_pem), key_pem = VALUES(key_pem), updated_at = VALUES(updated_at)`,
		certPEM, keyPEM, time.Now().UTC(),
	)
	return err
}

func (m *MySQLStore) SaveDeviceCAIfAbsent(certPEM, keyPEM string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	if _, err := m.db.ExecContext(ctx, `
		INSERT IGNORE INTO dpx_device_ca (id, cert_pem, key_pem, updated_at)
		VALUES (1, ?, ?, ?)`,
		certPEM, keyPEM, time.Now().UTC(),
	); err != nil {
		return "", "", err
	}
	var finalCert, finalKey string
	if err := m.db.QueryRowContext(ctx, `SELECT cert_pem, key_pem FROM dpx_device_ca WHERE id = 1`).Scan(&finalCert, &finalKey); err != nil {
		return "", "", err
	}
	return finalCert, finalKey, nil
}

func (m *MySQLStore) SaveTenant(t PersistedTenant) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO dpx_tenants (tenant_id, token_hash, disabled, require_mtls, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			token_hash = VALUES(token_hash),
			disabled = VALUES(disabled),
			require_mtls = VALUES(require_mtls),
			updated_at = VALUES(updated_at)`,
		t.TenantID, t.TokenHash, boolToInt(t.Disabled), boolToInt(t.RequireMTLS), time.Now().UTC(),
	)
	return err
}

func (m *MySQLStore) DeleteTenant(tenantID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `DELETE FROM dpx_tenants WHERE tenant_id = ?`, tenantID)
	return err
}

func (m *MySQLStore) SaveDevice(d PersistedDevice) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO dpx_devices (
			device_id, tenant_id, device_name, cert_serial, token_hash_hex,
			enrolled_at, cert_expires_at, last_rotated_at,
			revoked, revoked_at, revoked_reason, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			tenant_id = VALUES(tenant_id),
			device_name = VALUES(device_name),
			cert_serial = VALUES(cert_serial),
			token_hash_hex = VALUES(token_hash_hex),
			cert_expires_at = VALUES(cert_expires_at),
			last_rotated_at = VALUES(last_rotated_at),
			revoked = VALUES(revoked),
			revoked_at = VALUES(revoked_at),
			revoked_reason = VALUES(revoked_reason),
			updated_at = VALUES(updated_at)`,
		d.DeviceID, d.TenantID, d.DeviceName, d.CertSerial, d.TokenHashHex,
		d.EnrolledAt.UTC(), d.CertExpiresAt.UTC(), nullTime(d.LastRotatedAt),
		boolToInt(d.Revoked), nullTime(d.RevokedAt), d.RevokedReason, time.Now().UTC(),
	)
	return err
}

func (m *MySQLStore) GetDevice(deviceID string) (*PersistedDevice, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	row := m.db.QueryRowContext(ctx, `
		SELECT device_id, tenant_id, device_name, cert_serial, token_hash_hex,
		       enrolled_at, cert_expires_at, last_rotated_at,
		       revoked, revoked_at, revoked_reason
		FROM dpx_devices WHERE device_id = ?`, deviceID)
	d, err := scanDeviceRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (m *MySQLStore) SaveEnrollment(e PersistedEnrollment) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	now := time.Now().UTC()
	// Throttle expired enrollment cleanup to at most once per 60s to avoid write/binlog churn.
	nowSec := now.Unix()
	prev := m.lastEnrollCleanupUnix.Load()
	if nowSec-prev >= 60 && m.lastEnrollCleanupUnix.CompareAndSwap(prev, nowSec) {
		_, _ = m.db.ExecContext(ctx, `DELETE FROM dpx_enrollments WHERE expires_at < ? OR (used = 1 AND created_at < ?)`, now, now.Add(-1*time.Hour))
	}
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO dpx_enrollments (code, tenant_id, device_name, expires_at, used, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		e.Code, e.TenantID, e.DeviceName, e.ExpiresAt.UTC(), boolToInt(e.Used), now,
	)
	return err
}

// ClusterWatermark returns a compact single-query signature of (device_count, max_device_updated,
// tenant_count, max_tenant_updated) using index bounds so steady-state multi-node polling skips
// full table scans and in-memory write locks when nothing changed.
func (m *MySQLStore) ClusterWatermark() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	var devCnt, tenCnt int64
	var devMax, tenMax sql.NullTime
	err := m.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM dpx_devices),
			(SELECT MAX(updated_at) FROM dpx_devices),
			(SELECT COUNT(*) FROM dpx_tenants),
			(SELECT MAX(updated_at) FROM dpx_tenants)`).
		Scan(&devCnt, &devMax, &tenCnt, &tenMax)
	if err != nil {
		return "", err
	}
	var devNs, tenNs int64
	if devMax.Valid {
		devNs = devMax.Time.UnixNano()
	}
	if tenMax.Valid {
		tenNs = tenMax.Time.UnixNano()
	}
	return fmt.Sprintf("%d:%d:%d:%d", devCnt, devNs, tenCnt, tenNs), nil
}

// ConsumeEnrollment atomically marks a single-use enrollment code as consumed using row locking
// so concurrent enrollment attempts across multiple Hub nodes can NEVER replay the same code.
func (m *MySQLStore) ConsumeEnrollment(code string) (*PersistedEnrollment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()

	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var e PersistedEnrollment
	var usedInt int
	err = tx.QueryRowContext(ctx, `
		SELECT code, tenant_id, device_name, expires_at, used
		FROM dpx_enrollments WHERE code = ? FOR UPDATE`, code).
		Scan(&e.Code, &e.TenantID, &e.DeviceName, &e.ExpiresAt, &usedInt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Used = usedInt != 0
	if e.Used || time.Now().UTC().After(e.ExpiresAt) {
		return nil, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dpx_enrollments SET used = 1 WHERE code = ?`, code); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	e.Used = true
	return &e, nil
}

func (m *MySQLStore) LoadClusterSync() ([]PersistedDevice, []PersistedTenant, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	return m.loadClusterSyncCtx(ctx)
}

func (m *MySQLStore) loadClusterSyncCtx(ctx context.Context) ([]PersistedDevice, []PersistedTenant, error) {
	devRows, err := m.db.QueryContext(ctx, `
		SELECT device_id, tenant_id, device_name, cert_serial, token_hash_hex,
		       enrolled_at, cert_expires_at, last_rotated_at,
		       revoked, revoked_at, revoked_reason
		FROM dpx_devices`)
	if err != nil {
		return nil, nil, fmt.Errorf("store/mysql: query devices: %w", err)
	}
	defer func() { _ = devRows.Close() }()

	var devices []PersistedDevice
	for devRows.Next() {
		d, err := scanDeviceRow(devRows)
		if err != nil {
			return nil, nil, err
		}
		devices = append(devices, d)
	}
	if err := devRows.Err(); err != nil {
		return nil, nil, err
	}

	tRows, err := m.db.QueryContext(ctx, `SELECT tenant_id, token_hash, disabled, require_mtls FROM dpx_tenants`)
	if err != nil {
		return nil, nil, fmt.Errorf("store/mysql: query tenants: %w", err)
	}
	defer func() { _ = tRows.Close() }()

	var tenants []PersistedTenant
	for tRows.Next() {
		var t PersistedTenant
		var disabled, reqMTLS int
		if err := tRows.Scan(&t.TenantID, &t.TokenHash, &disabled, &reqMTLS); err != nil {
			return nil, nil, err
		}
		t.Disabled = disabled != 0
		t.RequireMTLS = reqMTLS != 0
		tenants = append(tenants, t)
	}
	return devices, tenants, tRows.Err()
}

func (m *MySQLStore) SaveBinding(b PersistedBinding) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	cidrsBytes, _ := json.Marshal(b.AllowedCIDRs)
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO dpx_bindings (id, listen_addr, tenant_id, service_name, allowed_cidrs_json, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			listen_addr = VALUES(listen_addr),
			tenant_id = VALUES(tenant_id),
			service_name = VALUES(service_name),
			allowed_cidrs_json = VALUES(allowed_cidrs_json),
			updated_at = VALUES(updated_at)`,
		b.ID, b.ListenAddr, b.TenantID, b.ServiceName, string(cidrsBytes), time.Now().UTC(),
	)
	return err
}

func (m *MySQLStore) DeleteBinding(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), mysqlOpTimeout)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `DELETE FROM dpx_bindings WHERE id = ?`, id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDeviceRow(r rowScanner) (PersistedDevice, error) {
	var d PersistedDevice
	var lastRot, revAt sql.NullTime
	var revInt int
	err := r.Scan(
		&d.DeviceID, &d.TenantID, &d.DeviceName, &d.CertSerial, &d.TokenHashHex,
		&d.EnrolledAt, &d.CertExpiresAt, &lastRot,
		&revInt, &revAt, &d.RevokedReason,
	)
	if err != nil {
		return d, err
	}
	d.Revoked = revInt != 0
	if lastRot.Valid {
		d.LastRotatedAt = lastRot.Time.UTC()
	}
	if revAt.Valid {
		d.RevokedAt = revAt.Time.UTC()
	}
	d.EnrolledAt = d.EnrolledAt.UTC()
	d.CertExpiresAt = d.CertExpiresAt.UTC()
	return d, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}
