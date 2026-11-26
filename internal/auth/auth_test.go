package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
)

func TestTenantAuthenticator(t *testing.T) {
	sum := sha256.Sum256([]byte("super-secret-b"))
	a, err := NewTenantAuthenticator([]TenantRecord{
		{TenantID: "tenant-a", TokenHash: "raw-secret-a"},
		{TenantID: "tenant-b", TokenHash: "sha256:" + hex.EncodeToString(sum[:]), RequireTLS: true},
	})
	if err != nil {
		t.Fatalf("NewTenantAuthenticator failed: %v", err)
	}

	if err := a.Authenticate("tenant-a", "raw-secret-a", nil); err != nil {
		t.Fatalf("expected tenant-a auth success, got %v", err)
	}
	if err := a.Authenticate("tenant-a", "wrong", nil); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if err := a.Authenticate("tenant-b", "super-secret-b", nil); !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("expected ErrCertMismatch when mTLS required without cert, got %v", err)
	}

	spiffeURI, _ := url.Parse("spiffe://dataproxy/tenant/tenant-b")
	goodCert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "other"},
		URIs:    []*url.URL{spiffeURI},
	}
	if err := a.Authenticate("tenant-b", "super-secret-b", []*x509.Certificate{goodCert}); err != nil {
		t.Fatalf("expected mTLS SPIFFE URI match to succeed, got %v", err)
	}

	badCert := &x509.Certificate{Subject: pkix.Name{CommonName: "tenant-a"}}
	if err := a.Authenticate("tenant-b", "super-secret-b", []*x509.Certificate{badCert}); !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("expected ErrCertMismatch for mismatched CN, got %v", err)
	}
}

func TestCallerACL(t *testing.T) {
	acl, err := NewCallerACL([]CallerPolicy{
		{
			CallerID:        "etl-worker-a",
			Secret:          "secret-1",
			AllowedTenants:  []string{"tenant-a"},
			AllowedServices: []string{"mysql-orders"},
		},
		{
			CallerID:       "platform-admin",
			Secret:         "secret-all",
			AllowedTenants: []string{"*"},
		},
	}, false)
	if err != nil {
		t.Fatalf("NewCallerACL failed: %v", err)
	}

	id, err := acl.AuthenticateBasic("etl-worker-a", "secret-1")
	if err != nil || id != "etl-worker-a" {
		t.Fatalf("AuthenticateBasic failed: id=%q err=%v", id, err)
	}
	if err := acl.Authorize(id, "tenant-a", "mysql-orders"); err != nil {
		t.Fatalf("expected allowed tenant/service, got %v", err)
	}
	if err := acl.Authorize(id, "tenant-b", "mysql-orders"); !errors.Is(err, ErrCallerForbidden) {
		t.Fatalf("expected cross-tenant denial, got %v", err)
	}
	if err := acl.Authorize(id, "tenant-a", "redis-internal"); !errors.Is(err, ErrCallerForbidden) {
		t.Fatalf("expected unallowed service denial, got %v", err)
	}

	adminID, err := acl.AuthenticateBearer("secret-all")
	if err != nil || adminID != "platform-admin" {
		t.Fatalf("AuthenticateBearer failed: id=%q err=%v", adminID, err)
	}
	if err := acl.Authorize(adminID, "tenant-z", "any-svc"); err != nil {
		t.Fatalf("expected wildcard caller to pass, got %v", err)
	}
}
