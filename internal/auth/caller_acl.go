package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	ErrCallerUnauthorized = errors.New("auth: invalid caller credentials")
	ErrCallerForbidden    = errors.New("auth: caller not authorized for target tenant or service")
)

// CallerPolicy defines a central platform caller's credentials and tenant/service ACLs.
type CallerPolicy struct {
	CallerID        string   `yaml:"caller_id" json:"caller_id"`
	Secret          string   `yaml:"secret" json:"-"` // Raw secret or "sha256:<hex>"
	AllowedTenants  []string `yaml:"allowed_tenants" json:"allowed_tenants"`   // ["*"] or ["tenant-a", ...]
	AllowedServices []string `yaml:"allowed_services" json:"allowed_services"` // Empty or ["*"] allows any exposed service
}

type callerEntry struct {
	secretHash      [32]byte
	allowAllTenants bool
	tenants         map[string]struct{}
	allowAllSvcs    bool
	services        map[string]struct{}
}

// CallerACL authenticates central platform callers (SOCKS5 / HTTP CONNECT / HTTP proxy)
// and enforces strict multi-tenant access boundaries.
type CallerACL struct {
	mu            sync.RWMutex
	allowNoAuth   bool
	callers       map[string]callerEntry
	bearerToIDMap map[[32]byte]string
}

// NewCallerACL constructs a CallerACL. If allowNoAuth is true and no policies are configured,
// unauthenticated local dev access is permitted; in production set allowNoAuth=false.
func NewCallerACL(policies []CallerPolicy, allowNoAuth bool) (*CallerACL, error) {
	acl := &CallerACL{
		allowNoAuth:   allowNoAuth,
		callers:       make(map[string]callerEntry, len(policies)),
		bearerToIDMap: make(map[[32]byte]string, len(policies)),
	}
	for _, p := range policies {
		if err := acl.Upsert(p); err != nil {
			return nil, err
		}
	}
	return acl, nil
}

// AllowNoAuth reports whether unauthenticated callers are permitted (dev mode only).
func (c *CallerACL) AllowNoAuth() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.allowNoAuth
}

// Upsert adds or updates a caller policy.
func (c *CallerACL) Upsert(p CallerPolicy) error {
	id := strings.TrimSpace(p.CallerID)
	if id == "" {
		return fmt.Errorf("auth: caller_id cannot be empty")
	}
	hash, err := normalizeTokenHash(p.Secret)
	if err != nil {
		return fmt.Errorf("auth: caller %q: %w", id, err)
	}

	entry := callerEntry{
		secretHash: hash,
		tenants:    make(map[string]struct{}),
		services:   make(map[string]struct{}),
	}
	for _, t := range p.AllowedTenants {
		if t == "*" {
			entry.allowAllTenants = true
		} else if t != "" {
			entry.tenants[t] = struct{}{}
		}
	}
	if len(p.AllowedServices) == 0 {
		entry.allowAllSvcs = true
	} else {
		for _, s := range p.AllowedServices {
			if s == "*" {
				entry.allowAllSvcs = true
			} else if s != "" {
				entry.services[s] = struct{}{}
			}
		}
	}

	c.mu.Lock()
	c.callers[id] = entry
	c.bearerToIDMap[hash] = id
	c.mu.Unlock()
	return nil
}

// AuthenticateBasic verifies callerID + secret (used by SOCKS5 RFC 1929 and Basic auth).
func (c *CallerACL) AuthenticateBasic(callerID, secret string) (string, error) {
	c.mu.RLock()
	entry, ok := c.callers[callerID]
	c.mu.RUnlock()
	if !ok {
		return "", ErrCallerUnauthorized
	}
	provided := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(entry.secretHash[:], provided[:]) != 1 {
		return "", ErrCallerUnauthorized
	}
	return callerID, nil
}

// AuthenticateBearer verifies a single bearer token (used by HTTP reverse proxy headers).
// Supports either "<caller_id>:<secret>" or standalone "<secret>".
func (c *CallerACL) AuthenticateBearer(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		if c.AllowNoAuth() {
			return "anonymous-dev", nil
		}
		return "", ErrCallerUnauthorized
	}
	if id, secret, hasColon := strings.Cut(token, ":"); hasColon {
		return c.AuthenticateBasic(id, secret)
	}
	provided := sha256.Sum256([]byte(token))
	c.mu.RLock()
	id, ok := c.bearerToIDMap[provided]
	c.mu.RUnlock()
	if !ok {
		return "", ErrCallerUnauthorized
	}
	return id, nil
}

// Authorize checks whether an already-authenticated callerID may access (tenantID, serviceName).
func (c *CallerACL) Authorize(callerID, tenantID, serviceName string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.allowNoAuth && callerID == "anonymous-dev" {
		return nil
	}
	entry, ok := c.callers[callerID]
	if !ok {
		return ErrCallerUnauthorized
	}
	if !entry.allowAllTenants {
		if _, allowed := entry.tenants[tenantID]; !allowed {
			return fmt.Errorf("%w: tenant %q denied for caller %q", ErrCallerForbidden, tenantID, callerID)
		}
	}
	if !entry.allowAllSvcs {
		if _, allowed := entry.services[serviceName]; !allowed {
			return fmt.Errorf("%w: service %q denied for caller %q", ErrCallerForbidden, serviceName, callerID)
		}
	}
	return nil
}
