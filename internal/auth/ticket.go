package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidTicket = errors.New("auth: invalid or tampered job ticket")
	ErrExpiredTicket = errors.New("auth: job ticket expired")
	ErrTicketScope   = errors.New("auth: job ticket does not match requested tenant/service")
)

// JobTicketClaims represents a short-lived, single-tenant, single-service job ticket
// issued by the central platform to prevent cross-tenant confused-deputy access and
// propagate structured business purpose into tenant-local audit logs.
type JobTicketClaims struct {
	TicketID    string            `json:"jti"`
	TenantID    string            `json:"tid"`
	ServiceName string            `json:"svc"`
	Purpose     map[string]string `json:"purpose,omitempty"`
	IssuedAt    int64             `json:"iat"`
	ExpiresAt   int64             `json:"exp"`
}

// IssuedTicket is returned by POST /api/v1/tickets for consumption by central workers.
type IssuedTicket struct {
	TicketID      string            `json:"ticket_id"`
	JWT           string            `json:"ticket"`         // Self-contained HS256 JWT (for PG/Redis/HTTP)
	MySQLUser     string            `json:"mysql_user"`     // Short username for stock MySQL CLI/JDBC single-port routing
	MySQLPassword string            `json:"mysql_password"` // Ticket secret verified against MySQL native SHA1 scramble
	RouteUser     string            `json:"route_user"`     // "<tenant_id>.<service_name>" for PG single-port routing
	TenantID      string            `json:"tenant_id"`
	ServiceName   string            `json:"service_name"`
	Purpose       map[string]string `json:"purpose,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
}

type storedTicket struct {
	claims JobTicketClaims
	secret string
}

const (
	jwtHeaderHS256          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // base64url({"alg":"HS256","typ":"JWT"})
	ticketPruneMinInterval  = 30                                     // seconds
	ticketPruneHighWater    = 10000
	ticketPruneFastInterval = 5     // seconds when above high water mark
	maxStoredTickets        = 65536 // hard memory cap; stateless JWT/MySQL HMAC verify still works after eviction
)

// TicketManager issues and verifies short-lived HS256 job tickets and tracks compact
// ticket IDs for protocols whose wire handshake hashes passwords (e.g. stock MySQL CLI).
type TicketManager struct {
	signingKey []byte
	defaultTTL time.Duration

	mu          sync.RWMutex
	tickets     map[string]storedTicket
	lastPruneAt int64
}

// NewTicketManager initializes a TicketManager. If signingKey is empty, a random 32-byte key is generated.
func NewTicketManager(signingKey string, defaultTTL time.Duration) *TicketManager {
	var keyBytes []byte
	if strings.TrimSpace(signingKey) != "" {
		sum := sha256.Sum256([]byte(signingKey))
		keyBytes = sum[:]
	} else {
		keyBytes = make([]byte, 32)
		_, _ = rand.Read(keyBytes)
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	return &TicketManager{
		signingKey: keyBytes,
		defaultTTL: defaultTTL,
		tickets:    make(map[string]storedTicket),
	}
}

// Issue creates a short-lived job ticket locked strictly to (tenantID, serviceName).
func (tm *TicketManager) Issue(tenantID, serviceName string, ttl time.Duration, purpose map[string]string) (*IssuedTicket, error) {
	tenantID = strings.TrimSpace(tenantID)
	serviceName = strings.TrimSpace(serviceName)
	if tenantID == "" || serviceName == "" {
		return nil, errors.New("tenant_id and service_name are required to issue ticket")
	}
	if ttl <= 0 {
		ttl = tm.defaultTTL
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}

	now := time.Now().UTC()
	exp := now.Add(ttl)
	ticketID := "tkt_" + randomHex(8)
	// Stateless cross-node MySQL username encodes tenant, service, expiry, and nonce,
	// while the password is deterministically derived via HMAC-SHA256(signingKey, mysqlUser)
	// so ANY Hub node in a cluster can verify a MySQL scramble with ZERO shared DB/RAM lookup!
	mysqlUser := fmt.Sprintf("%s.%s:%x:%s", tenantID, serviceName, exp.Unix(), randomHex(3))
	secret := tm.deriveStatelessMySQLSecret(mysqlUser)

	var purposeCopy map[string]string
	if len(purpose) > 0 {
		purposeCopy = make(map[string]string, len(purpose))
		for k, v := range purpose {
			purposeCopy[k] = v
		}
	}

	claims := JobTicketClaims{
		TicketID:    ticketID,
		TenantID:    tenantID,
		ServiceName: serviceName,
		Purpose:     purposeCopy,
		IssuedAt:    now.Unix(),
		ExpiresAt:   exp.Unix(),
	}

	jwtStr, err := tm.signJWT(claims)
	if err != nil {
		return nil, err
	}

	tm.mu.Lock()
	nowUnix := now.Unix()
	if len(tm.tickets) >= maxStoredTickets {
		tm.pruneExpiredLocked(nowUnix)
		tm.lastPruneAt = nowUnix
		if len(tm.tickets) >= maxStoredTickets {
			evict := maxStoredTickets / 8
			for id := range tm.tickets {
				delete(tm.tickets, id)
				evict--
				if evict <= 0 {
					break
				}
			}
		}
	} else if (len(tm.tickets) >= ticketPruneHighWater && nowUnix-tm.lastPruneAt >= ticketPruneFastInterval) ||
		nowUnix-tm.lastPruneAt >= ticketPruneMinInterval {
		tm.pruneExpiredLocked(nowUnix)
		tm.lastPruneAt = nowUnix
	}
	tm.tickets[ticketID] = storedTicket{claims: claims, secret: secret}
	tm.tickets[mysqlUser] = storedTicket{claims: claims, secret: secret}
	tm.mu.Unlock()

	return &IssuedTicket{
		TicketID:      ticketID,
		JWT:           jwtStr,
		MySQLUser:     mysqlUser,
		MySQLPassword: secret,
		RouteUser:     tenantID + "." + serviceName,
		TenantID:      tenantID,
		ServiceName:   serviceName,
		Purpose:       purposeCopy,
		ExpiresAt:     exp,
	}, nil
}

// VerifyJWT validates an HS256 JWT ticket and checks expiration.
func (tm *TicketManager) VerifyJWT(token string) (*JobTicketClaims, error) {
	token = strings.TrimSpace(token)
	dot1 := strings.IndexByte(token, '.')
	if dot1 <= 0 {
		return nil, ErrInvalidTicket
	}
	dot2Off := strings.IndexByte(token[dot1+1:], '.')
	if dot2Off <= 0 {
		return nil, ErrInvalidTicket
	}
	dot2 := dot1 + 1 + dot2Off
	if strings.IndexByte(token[dot2+1:], '.') >= 0 {
		return nil, ErrInvalidTicket
	}

	signingInput := token[:dot2]
	payloadPart := token[dot1+1 : dot2]
	sigPart := token[dot2+1:]

	mac := hmac.New(sha256.New, tm.signingKey)
	_, _ = mac.Write([]byte(signingInput))
	var expectedBuf [sha256.Size]byte
	expectedSig := mac.Sum(expectedBuf[:0])

	var sigBuf [64]byte
	if base64.RawURLEncoding.DecodedLen(len(sigPart)) > len(sigBuf) {
		return nil, ErrInvalidTicket
	}
	nSig, err := base64.RawURLEncoding.Decode(sigBuf[:], []byte(sigPart))
	if err != nil || !hmac.Equal(sigBuf[:nSig], expectedSig) {
		return nil, ErrInvalidTicket
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, ErrInvalidTicket
	}
	var claims JobTicketClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidTicket
	}
	if claims.TenantID == "" || claims.ServiceName == "" {
		return nil, ErrInvalidTicket
	}
	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return nil, ErrExpiredTicket
	}
	return &claims, nil
}

// VerifySecret validates either a self-contained JWT (when secretOrJWT looks like a JWT)
// or a (ticketID, secret) pair issued by this TicketManager.
func (tm *TicketManager) VerifySecret(ticketID, secretOrJWT string) (*JobTicketClaims, error) {
	if strings.Count(secretOrJWT, ".") == 2 {
		return tm.VerifyJWT(secretOrJWT)
	}
	tm.mu.RLock()
	st, ok := tm.tickets[ticketID]
	tm.mu.RUnlock()
	if !ok {
		return nil, ErrInvalidTicket
	}
	if time.Now().UTC().Unix() > st.claims.ExpiresAt {
		return nil, ErrExpiredTicket
	}
	if subtle.ConstantTimeCompare([]byte(st.secret), []byte(secretOrJWT)) != 1 {
		return nil, ErrInvalidTicket
	}
	c := st.claims
	return &c, nil
}

// VerifyMySQLNativeScramble verifies a stock MySQL client's HandshakeResponse41
// scramble (supporting both caching_sha2_password 32-byte SHA-256 and
// mysql_native_password 20-byte SHA-1) against the issued ticket's secret and hubSalt.
// Supports BOTH local-node lookup (preserving full Purpose) AND stateless cross-node
// HMAC-derived verification so ANY Hub node in a cluster can verify a MySQL ticket!
func (tm *TicketManager) VerifyMySQLNativeScramble(ticketUser string, hubSalt, clientAuthResp []byte) (*JobTicketClaims, error) {
	tm.mu.RLock()
	st, ok := tm.tickets[ticketUser]
	tm.mu.RUnlock()

	if ok {
		if time.Now().UTC().Unix() > st.claims.ExpiresAt {
			return nil, ErrExpiredTicket
		}
		if verifyMySQLScrambles(st.secret, hubSalt, clientAuthResp) {
			c := st.claims
			return &c, nil
		}
		return nil, ErrInvalidTicket
	}

	// Stateless cross-node path: parse "<tenant>.<service>:<expHex>:<nonce>"
	claims, err := parseStatelessMySQLUser(ticketUser)
	if err != nil {
		return nil, ErrInvalidTicket
	}
	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return nil, ErrExpiredTicket
	}
	derivedSecret := tm.deriveStatelessMySQLSecret(ticketUser)
	if !verifyMySQLScrambles(derivedSecret, hubSalt, clientAuthResp) {
		return nil, ErrInvalidTicket
	}
	return claims, nil
}

func (tm *TicketManager) deriveStatelessMySQLSecret(mysqlUser string) string {
	mac := hmac.New(sha256.New, tm.signingKey)
	mac.Write([]byte("mysql-ticket-v1:"))
	mac.Write([]byte(mysqlUser))
	return "sec_" + hex.EncodeToString(mac.Sum(nil)[:14])
}

func parseStatelessMySQLUser(u string) (*JobTicketClaims, error) {
	parts := strings.Split(u, ":")
	if len(parts) != 3 {
		return nil, ErrInvalidTicket
	}
	tenant, svc, ok := strings.Cut(parts[0], ".")
	if !ok || tenant == "" || svc == "" {
		return nil, ErrInvalidTicket
	}
	expUnix, err := strconv.ParseInt(parts[1], 16, 64)
	if err != nil || expUnix <= 0 {
		return nil, ErrInvalidTicket
	}
	return &JobTicketClaims{
		TicketID:    "tkt_sl_" + parts[2],
		TenantID:    tenant,
		ServiceName: svc,
		ExpiresAt:   expUnix,
	}, nil
}

func verifyMySQLScrambles(secret string, hubSalt, clientAuthResp []byte) bool {
	switch len(clientAuthResp) {
	case sha256.Size:
		expectedSHA256 := computeMySQLCachingSHA2Scramble(secret, hubSalt)
		return subtle.ConstantTimeCompare(clientAuthResp, expectedSHA256) == 1
	case sha1.Size:
		expectedSHA1 := computeMySQLNativeScramble(secret, hubSalt)
		return subtle.ConstantTimeCompare(clientAuthResp, expectedSHA1) == 1
	default:
		return false
	}
}

func computeMySQLCachingSHA2Scramble(password string, salt []byte) []byte {
	s1 := sha256.Sum256([]byte(password))
	s2 := sha256.Sum256(s1[:])
	h := sha256.New()
	h.Write(s2[:])
	h.Write(salt)
	sc := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s1[i] ^ sc[i]
	}
	return out
}

func computeMySQLNativeScramble(password string, salt []byte) []byte {
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	sc := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s1[i] ^ sc[i]
	}
	return out
}

func (tm *TicketManager) signJWT(claims JobTicketClaims) (string, error) {
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := jwtHeaderHS256 + "." + payload
	mac := hmac.New(sha256.New, tm.signingKey)
	_, _ = mac.Write([]byte(signingInput))
	var sigBuf [sha256.Size]byte
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(sigBuf[:0]))
	return signingInput + "." + sig, nil
}

func (tm *TicketManager) pruneExpiredLocked(nowUnix int64) {
	for id, st := range tm.tickets {
		if nowUnix > st.claims.ExpiresAt {
			delete(tm.tickets, id)
		}
	}
}

func randomHex(numBytes int) string {
	b := make([]byte, numBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
