package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PersistedTenant stores a dynamically registered tenant's hashed credentials.
type PersistedTenant struct {
	TenantID    string `json:"tenant_id"`
	TokenHash   string `json:"token_hash"` // "sha256:<hex>"
	Disabled    bool   `json:"disabled"`
	RequireMTLS bool   `json:"require_mtls"`
}

// PersistedDevice stores an enrolled agent device and its revocation state so restarts
// never invalidate enrolled devices or resurrect revoked ones.
type PersistedDevice struct {
	DeviceID      string    `json:"device_id"`
	TenantID      string    `json:"tenant_id"`
	DeviceName    string    `json:"device_name,omitempty"`
	CertSerial    string    `json:"cert_serial"`
	TokenHashHex  string    `json:"token_hash_hex"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	CertExpiresAt time.Time `json:"cert_expires_at"`
	LastRotatedAt time.Time `json:"last_rotated_at,omitempty"`
	Revoked       bool      `json:"revoked"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
}

// PersistedBinding stores a dynamically created TCP port binding.
type PersistedBinding struct {
	ID           string   `json:"id"`
	ListenAddr   string   `json:"listen_addr"`
	TenantID     string   `json:"tenant_id"`
	ServiceName  string   `json:"service_name"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

// Snapshot is the complete control-plane state persisted by a Store implementation.
type Snapshot struct {
	DeviceCACertPEM string                      `json:"device_ca_cert_pem,omitempty"`
	DeviceCAKeyPEM  string                      `json:"device_ca_key_pem,omitempty"`
	Tenants         map[string]PersistedTenant  `json:"tenants,omitempty"`
	Devices         map[string]PersistedDevice  `json:"devices,omitempty"`
	Bindings        map[string]PersistedBinding `json:"bindings,omitempty"`
}

// Store abstracts control-plane persistence (default: atomic JSON FileStore;
// pluggable for PostgreSQL / Etcd / SQLite in large clusters).
type Store interface {
	Load() (*Snapshot, error)
	SaveDeviceCA(certPEM, keyPEM string) error
	SaveTenant(t PersistedTenant) error
	DeleteTenant(tenantID string) error
	SaveDevice(d PersistedDevice) error
	SaveBinding(b PersistedBinding) error
	DeleteBinding(id string) error
	Close() error
}

// FileStore is a zero-dependency crash-safe JSON file Store using atomic write-temp + rename.
type FileStore struct {
	path string
	mu   sync.Mutex
	snap Snapshot
}

// NewFileStore opens or initializes an atomic JSON file store at path.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("store: state file path cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", filepath.Dir(path), err)
	}
	fs := &FileStore{
		path: path,
		snap: Snapshot{
			Tenants:  make(map[string]PersistedTenant),
			Devices:  make(map[string]PersistedDevice),
			Bindings: make(map[string]PersistedBinding),
		},
	}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &fs.snap); err != nil {
			return nil, fmt.Errorf("store: parse state file %q: %w", path, err)
		}
		if fs.snap.Tenants == nil {
			fs.snap.Tenants = make(map[string]PersistedTenant)
		}
		if fs.snap.Devices == nil {
			fs.snap.Devices = make(map[string]PersistedDevice)
		}
		if fs.snap.Bindings == nil {
			fs.snap.Bindings = make(map[string]PersistedBinding)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("store: read state file %q: %w", path, err)
	}
	return fs, nil
}

func (f *FileStore) Load() (*Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := Snapshot{
		DeviceCACertPEM: f.snap.DeviceCACertPEM,
		DeviceCAKeyPEM:  f.snap.DeviceCAKeyPEM,
		Tenants:         make(map[string]PersistedTenant, len(f.snap.Tenants)),
		Devices:         make(map[string]PersistedDevice, len(f.snap.Devices)),
		Bindings:        make(map[string]PersistedBinding, len(f.snap.Bindings)),
	}
	for k, v := range f.snap.Tenants {
		cp.Tenants[k] = v
	}
	for k, v := range f.snap.Devices {
		cp.Devices[k] = v
	}
	for k, v := range f.snap.Bindings {
		cp.Bindings[k] = v
	}
	return &cp, nil
}

func (f *FileStore) SaveDeviceCA(certPEM, keyPEM string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.DeviceCACertPEM = certPEM
	f.snap.DeviceCAKeyPEM = keyPEM
	return f.flushLocked()
}

func (f *FileStore) SaveTenant(t PersistedTenant) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.Tenants[t.TenantID] = t
	return f.flushLocked()
}

func (f *FileStore) DeleteTenant(tenantID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.snap.Tenants, tenantID)
	return f.flushLocked()
}

func (f *FileStore) SaveDevice(d PersistedDevice) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.Devices[d.DeviceID] = d
	return f.flushLocked()
}

func (f *FileStore) SaveBinding(b PersistedBinding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.Bindings[b.ID] = b
	return f.flushLocked()
}

func (f *FileStore) DeleteBinding(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.snap.Bindings, id)
	return f.flushLocked()
}

func (f *FileStore) Close() error { return nil }

func (f *FileStore) flushLocked() error {
	data, err := json.MarshalIndent(f.snap, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, ".hub-state-*.tmp")
	if err != nil {
		return fmt.Errorf("store: create temp state: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return fmt.Errorf("store: chmod temp state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("store: write temp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("store: fsync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store: close temp state: %w", err)
	}
	if err := os.Rename(tmpPath, f.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store: atomic rename state: %w", err)
	}
	return nil
}
