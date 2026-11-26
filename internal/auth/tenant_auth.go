package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"dataproxy/internal/store"
)

var (
	ErrUnknownTenant = errors.New("auth: unknown tenant")
	ErrInvalidToken  = errors.New("auth: invalid tenant token")
	ErrCertMismatch  = errors.New("auth: client certificate identity does not match tenant_id")
)

// TenantRecord stores authentication metadata for a tenant.
type TenantRecord struct {
	TenantID   string `yaml:"tenant_id" json:"tenant_id"`
	TokenHash  string `yaml:"token" json:"-"` // Accepts raw secret or "sha256:<hex>"
	Disabled   bool   `yaml:"disabled" json:"disabled"`
	RequireTLS bool   `yaml:"require_mtls" json:"require_mtls"`
}

// TenantAuthenticator verifies agent identity via constant-time token matching
// and optional mTLS peer certificate CN/SAN binding, with optional persistent Store.
type TenantAuthenticator struct {
	mu      sync.RWMutex
	tenants map[string]tenantEntry
	st      store.Store
}

type tenantEntry struct {
	hashBytes   [32]byte
	disabled    bool
	requireMTLS bool
}

// NewTenantAuthenticator constructs an authenticator from initial tenant records.
func NewTenantAuthenticator(records []TenantRecord) (*TenantAuthenticator, error) {
	return NewTenantAuthenticatorWithStore(records, nil)
}

// NewTenantAuthenticatorWithStore loads persisted tenants from st (if provided) and merges config records.
func NewTenantAuthenticatorWithStore(records []TenantRecord, st store.Store) (*TenantAuthenticator, error) {
	a := &TenantAuthenticator{
		tenants: make(map[string]tenantEntry, len(records)),
		st:      st,
	}
	if st != nil {
		if snap, err := st.Load(); err == nil && snap != nil {
			for _, pt := range snap.Tenants {
				_ = a.upsertInternal(TenantRecord{
					TenantID:   pt.TenantID,
					TokenHash:  pt.TokenHash,
					Disabled:   pt.Disabled,
					RequireTLS: pt.RequireMTLS,
				}, false)
			}
		}
	}
	for _, r := range records {
		if err := a.upsertInternal(r, false); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// Upsert registers or updates a tenant's authentication record (and persists if Store is enabled).
func (a *TenantAuthenticator) Upsert(rec TenantRecord) error {
	return a.upsertInternal(rec, true)
}

func (a *TenantAuthenticator) upsertInternal(rec TenantRecord, persist bool) error {
	tid := strings.TrimSpace(rec.TenantID)
	if tid == "" {
		return fmt.Errorf("auth: tenant_id cannot be empty")
	}
	hashBytes, err := normalizeTokenHash(rec.TokenHash)
	if err != nil {
		return fmt.Errorf("auth: tenant %q: %w", tid, err)
	}

	a.mu.Lock()
	a.tenants[tid] = tenantEntry{
		hashBytes:   hashBytes,
		disabled:    rec.Disabled,
		requireMTLS: rec.RequireTLS,
	}
	st := a.st
	a.mu.Unlock()

	if persist && st != nil {
		_ = st.SaveTenant(store.PersistedTenant{
			TenantID:    tid,
			TokenHash:   "sha256:" + hex.EncodeToString(hashBytes[:]),
			Disabled:    rec.Disabled,
			RequireMTLS: rec.RequireTLS,
		})
	}
	return nil
}

// Delete removes a tenant from the authenticator (and persistent Store if enabled).
func (a *TenantAuthenticator) Delete(tenantID string) bool {
	a.mu.Lock()
	_, ok := a.tenants[tenantID]
	if ok {
		delete(a.tenants, tenantID)
	}
	st := a.st
	a.mu.Unlock()
	if ok && st != nil {
		_ = st.DeleteTenant(tenantID)
	}
	return ok
}

// ListTenantIDs returns all configured tenant IDs.
func (a *TenantAuthenticator) ListTenantIDs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ids := make([]string, 0, len(a.tenants))
	for id := range a.tenants {
		ids = append(ids, id)
	}
	return ids
}

// Authenticate validates tenantID, raw token, and optional verified TLS peer certificates.
func (a *TenantAuthenticator) Authenticate(tenantID, token string, peerCerts []*x509.Certificate) error {
	a.mu.RLock()
	entry, ok := a.tenants[tenantID]
	a.mu.RUnlock()

	if !ok || entry.disabled {
		return ErrUnknownTenant
	}

	provided := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(entry.hashBytes[:], provided[:]) != 1 {
		return ErrInvalidToken
	}

	if entry.requireMTLS || len(peerCerts) > 0 {
		if len(peerCerts) == 0 {
			return ErrCertMismatch
		}
		if !certMatchesTenant(peerCerts[0], tenantID) {
			return ErrCertMismatch
		}
	}
	return nil
}

func certMatchesTenant(cert *x509.Certificate, tenantID string) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.CommonName == tenantID {
		return true
	}
	expectedURI := "spiffe://dataproxy/tenant/" + tenantID
	for _, u := range cert.URIs {
		if u.String() == expectedURI {
			return true
		}
	}
	for _, dns := range cert.DNSNames {
		if dns == tenantID {
			return true
		}
	}
	return false
}

func normalizeTokenHash(raw string) ([32]byte, error) {
	var out [32]byte
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, errors.New("token cannot be empty")
	}
	if strings.HasPrefix(raw, "sha256:") {
		hexStr := strings.TrimPrefix(raw, "sha256:")
		b, err := hex.DecodeString(hexStr)
		if err != nil || len(b) != 32 {
			return out, errors.New("invalid sha256 token digest")
		}
		copy(out[:], b)
		return out, nil
	}
	return sha256.Sum256([]byte(raw)), nil
}
