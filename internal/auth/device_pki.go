package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dataproxy/internal/store"
)

var (
	ErrInvalidEnrollment = errors.New("auth: invalid, expired, or already-used enrollment code")
	ErrUnknownDevice     = errors.New("auth: unknown device_id")
	ErrDeviceRevoked     = errors.New("auth: device has been revoked")
	ErrDeviceCertExpired = errors.New("auth: device certificate expired")
)

// EnrollmentInfo is returned when an admin generates a 15-minute single-use mount code.
type EnrollmentInfo struct {
	Code       string    `json:"enrollment_code"`
	TenantID   string    `json:"tenant_id"`
	DeviceName string    `json:"device_name,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// DeviceRecord tracks an enrolled agent device, its short-lived certificate, and revocation status.
type DeviceRecord struct {
	DeviceID        string    `json:"device_id"`
	TenantID        string    `json:"tenant_id"`
	DeviceName      string    `json:"device_name,omitempty"`
	CertSerial      string    `json:"cert_serial"`
	EnrolledAt      time.Time `json:"enrolled_at"`
	CertExpiresAt   time.Time `json:"cert_expires_at"`
	LastRotatedAt   time.Time `json:"last_rotated_at,omitempty"`
	Revoked         bool      `json:"revoked"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	RevokedReason   string    `json:"revoked_reason,omitempty"`
	tokenHash       [32]byte
}

// DeviceCertBundle is returned to the tenant agent upon successful enrollment or certificate rotation.
type DeviceCertBundle struct {
	DeviceID    string    `json:"device_id"`
	TenantID    string    `json:"tenant_id"`
	CertPEM     string    `json:"cert_pem"`
	CAPEM       string    `json:"ca_pem"`
	DeviceToken string    `json:"device_token"`
	CertSerial  string    `json:"cert_serial"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type enrollmentEntry struct {
	tenantID   string
	deviceName string
	expiresAt  time.Time
	used       bool
}

// DeviceManager implements an ECDSA/KMS-pluggable Device PKI (using standard crypto.Signer)
// for one-time enrollment, short-lived device certificate signing/auto-rotation, persistence
// via store.Store, and single-device revocation.
type DeviceManager struct {
	caCert    *x509.Certificate
	caSigner  crypto.Signer // Plug in local ECDSA key OR cloud KMS / HashiCorp Vault crypto.Signer!
	caCertPEM []byte
	certTTL   time.Duration
	enrollTTL time.Duration
	st        store.Store

	mu          sync.RWMutex
	enrollments map[string]*enrollmentEntry
	devices     map[string]*DeviceRecord
}

// NewDeviceManager initializes the device PKI with optional persistent Store.
// If caCertFile/caKeyFile are empty, it loads any persisted CA from st or generates a new ECDSA P-256 CA.
func NewDeviceManager(caCertFile, caKeyFile string, certTTL, enrollTTL time.Duration, st store.Store) (*DeviceManager, error) {
	if certTTL <= 0 {
		certTTL = 7 * 24 * time.Hour
	}
	if enrollTTL <= 0 {
		enrollTTL = 15 * time.Minute
	}

	var caCert *x509.Certificate
	var caSigner crypto.Signer
	var caPEM []byte

	var snap *store.Snapshot
	if st != nil {
		var err error
		snap, err = st.Load()
		if err != nil {
			return nil, fmt.Errorf("load device store: %w", err)
		}
	}

	if strings.TrimSpace(caCertFile) != "" && strings.TrimSpace(caKeyFile) != "" {
		certBytes, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("read device ca cert: %w", err)
		}
		keyBytes, err := os.ReadFile(caKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read device ca key: %w", err)
		}
		caCert, caSigner, err = parseCAPair(certBytes, keyBytes)
		if err != nil {
			return nil, err
		}
		caPEM = certBytes
	} else if snap != nil && snap.DeviceCACertPEM != "" && snap.DeviceCAKeyPEM != "" {
		var err error
		caCert, caSigner, err = parseCAPair([]byte(snap.DeviceCACertPEM), []byte(snap.DeviceCAKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse persisted device ca: %w", err)
		}
		caPEM = []byte(snap.DeviceCACertPEM)
	} else {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate device ca key: %w", err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "dataproxy-device-ca"},
			NotBefore:             time.Now().Add(-5 * time.Minute),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			return nil, fmt.Errorf("create device ca cert: %w", err)
		}
		caCert, err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		caSigner = priv
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if st != nil {
			keyDER, _ := x509.MarshalECPrivateKey(priv)
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
			if cs, ok := st.(store.ClusterStore); ok {
				finalCertPEM, finalKeyPEM, err := cs.SaveDeviceCAIfAbsent(string(caPEM), string(keyPEM))
				if err != nil {
					return nil, fmt.Errorf("persist shared cluster device ca: %w", err)
				}
				if finalCertPEM != string(caPEM) {
					// Another Hub node initialized the cluster CA concurrently; converge onto it.
					caCert, caSigner, err = parseCAPair([]byte(finalCertPEM), []byte(finalKeyPEM))
					if err != nil {
						return nil, fmt.Errorf("parse converged cluster device ca: %w", err)
					}
					caPEM = []byte(finalCertPEM)
				}
			} else {
				_ = st.SaveDeviceCA(string(caPEM), string(keyPEM))
			}
		}
	}

	dm, err := NewDeviceManagerWithSigner(caCert, caSigner, caPEM, certTTL, enrollTTL, st)
	if err != nil {
		return nil, err
	}
	if snap != nil {
		for _, pd := range snap.Devices {
			var th [32]byte
			if b, err := hex.DecodeString(pd.TokenHashHex); err == nil && len(b) == 32 {
				copy(th[:], b)
			}
			dm.devices[pd.DeviceID] = &DeviceRecord{
				DeviceID:      pd.DeviceID,
				TenantID:      pd.TenantID,
				DeviceName:    pd.DeviceName,
				CertSerial:    pd.CertSerial,
				EnrolledAt:    pd.EnrolledAt,
				CertExpiresAt: pd.CertExpiresAt,
				LastRotatedAt: pd.LastRotatedAt,
				Revoked:       pd.Revoked,
				RevokedAt:     pd.RevokedAt,
				RevokedReason: pd.RevokedReason,
				tokenHash:     th,
			}
		}
	}
	return dm, nil
}

// NewDeviceManagerWithSigner constructs a DeviceManager backed by any crypto.Signer
// (e.g. AWS KMS, GCP KMS, HashiCorp Vault, HSM, or local ECDSA key).
func NewDeviceManagerWithSigner(caCert *x509.Certificate, signer crypto.Signer, caCertPEM []byte, certTTL, enrollTTL time.Duration, st store.Store) (*DeviceManager, error) {
	if caCert == nil || signer == nil {
		return nil, errors.New("caCert and crypto.Signer are required")
	}
	if len(caCertPEM) == 0 {
		caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	}
	return &DeviceManager{
		caCert:      caCert,
		caSigner:    signer,
		caCertPEM:   caCertPEM,
		certTTL:     certTTL,
		enrollTTL:   enrollTTL,
		st:          st,
		enrollments: make(map[string]*enrollmentEntry),
		devices:     make(map[string]*DeviceRecord),
	}, nil
}

func parseCAPair(certBytes, keyBytes []byte) (*x509.Certificate, crypto.Signer, error) {
	cBlk, _ := pem.Decode(certBytes)
	if cBlk == nil {
		return nil, nil, errors.New("invalid device ca cert PEM")
	}
	caCert, err := x509.ParseCertificate(cBlk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse device ca cert: %w", err)
	}
	kBlk, _ := pem.Decode(keyBytes)
	if kBlk == nil {
		return nil, nil, errors.New("invalid device ca key PEM")
	}
	if k, err := x509.ParseECPrivateKey(kBlk.Bytes); err == nil {
		return caCert, k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(kBlk.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return caCert, s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(kBlk.Bytes); err == nil {
		return caCert, k, nil
	}
	return nil, nil, errors.New("unsupported device ca private key format")
}

// CACert returns the device CA certificate (can be added to Hub TLS ClientCAs).
func (dm *DeviceManager) CACert() *x509.Certificate {
	return dm.caCert
}

// CreateEnrollment generates a single-use, time-limited enrollment code for a tenant.
func (dm *DeviceManager) CreateEnrollment(tenantID, deviceName string, ttl time.Duration) (*EnrollmentInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if ttl <= 0 {
		ttl = dm.enrollTTL
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}

	code := "enroll_" + randomHex(16)
	now := time.Now().UTC()
	exp := now.Add(ttl)
	cleanDeviceName := strings.TrimSpace(deviceName)

	if cs, ok := dm.st.(store.ClusterStore); ok {
		if err := cs.SaveEnrollment(store.PersistedEnrollment{
			Code:       code,
			TenantID:   tenantID,
			DeviceName: cleanDeviceName,
			ExpiresAt:  exp,
		}); err != nil {
			return nil, fmt.Errorf("persist cluster enrollment code: %w", err)
		}
	} else {
		dm.mu.Lock()
		// Prune expired or already-used enrollment codes to bound memory usage.
		for k, v := range dm.enrollments {
			if v.used || now.After(v.expiresAt) {
				delete(dm.enrollments, k)
			}
		}
		dm.enrollments[code] = &enrollmentEntry{
			tenantID:   tenantID,
			deviceName: cleanDeviceName,
			expiresAt:  exp,
		}
		dm.mu.Unlock()
	}

	return &EnrollmentInfo{
		Code:       code,
		TenantID:   tenantID,
		DeviceName: cleanDeviceName,
		ExpiresAt:  exp,
	}, nil
}

// CompleteEnrollment atomically consumes a one-time enrollment code, verifies the agent's
// CSR signature (the agent's private key never leaves the customer host), and signs a
// short-lived device certificate bound to a brand-new unique device_id.
func (dm *DeviceManager) CompleteEnrollment(code, csrPEM string) (*DeviceCertBundle, error) {
	csr, err := parseAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	var tenantID, deviceName string
	trimmedCode := strings.TrimSpace(code)
	if cs, ok := dm.st.(store.ClusterStore); ok {
		enr, err := cs.ConsumeEnrollment(trimmedCode)
		if err != nil {
			return nil, fmt.Errorf("consume cluster enrollment code: %w", err)
		}
		if enr == nil {
			return nil, ErrInvalidEnrollment
		}
		tenantID = enr.TenantID
		deviceName = enr.DeviceName
	} else {
		dm.mu.Lock()
		enr, ok := dm.enrollments[trimmedCode]
		if !ok || enr.used || time.Now().UTC().After(enr.expiresAt) {
			dm.mu.Unlock()
			return nil, ErrInvalidEnrollment
		}
		// Mark single-use immediately under lock to eliminate TOCTOU replay!
		enr.used = true
		tenantID = enr.tenantID
		deviceName = enr.deviceName
		dm.mu.Unlock()
	}

	deviceID := "dev_" + randomHex(8)
	deviceToken := "dpxdev_" + randomHex(24)

	certPEM, serialHex, expiresAt, err := dm.signDeviceCert(csr.PublicKey, tenantID, deviceID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rec := &DeviceRecord{
		DeviceID:      deviceID,
		TenantID:      tenantID,
		DeviceName:    deviceName,
		CertSerial:    serialHex,
		EnrolledAt:    now,
		CertExpiresAt: expiresAt,
		LastRotatedAt: now,
		tokenHash:     sha256.Sum256([]byte(deviceToken)),
	}

	dm.mu.Lock()
	dm.devices[deviceID] = rec
	dm.mu.Unlock()
	dm.persistDevice(rec)

	return &DeviceCertBundle{
		DeviceID:    deviceID,
		TenantID:    tenantID,
		CertPEM:     string(certPEM),
		CAPEM:       string(dm.caCertPEM),
		DeviceToken: deviceToken,
		CertSerial:  serialHex,
		ExpiresAt:   expiresAt,
	}, nil
}

// RenewDevice validates an active (non-revoked) device's current credentials and issues
// a freshly signed short-lived certificate + rotated device token from a new CSR.
func (dm *DeviceManager) RenewDevice(deviceID, currentToken, csrPEM string, peerCerts []*x509.Certificate) (*DeviceCertBundle, error) {
	csr, err := parseAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	rec, ok := dm.lookupDeviceReadThrough(deviceID)
	if !ok {
		return nil, ErrUnknownDevice
	}
	if rec.Revoked {
		return nil, ErrDeviceRevoked
	}
	tenantID := rec.TenantID
	expectedHash := rec.tokenHash

	// Authenticate using current device token (and peer cert if present).
	provided := sha256.Sum256([]byte(currentToken))
	if subtle.ConstantTimeCompare(expectedHash[:], provided[:]) != 1 {
		return nil, ErrInvalidToken
	}
	if len(peerCerts) > 0 && !certMatchesDevice(peerCerts[0], tenantID, deviceID) {
		return nil, ErrCertMismatch
	}

	newToken := "dpxdev_" + randomHex(24)
	certPEM, serialHex, expiresAt, err := dm.signDeviceCert(csr.PublicKey, tenantID, deviceID)
	if err != nil {
		return nil, err
	}

	dm.mu.Lock()
	recPtr := dm.devices[deviceID]
	if recPtr == nil || recPtr.Revoked {
		dm.mu.Unlock()
		return nil, ErrDeviceRevoked
	}
	recPtr.CertSerial = serialHex
	recPtr.CertExpiresAt = expiresAt
	recPtr.LastRotatedAt = time.Now().UTC()
	recPtr.tokenHash = sha256.Sum256([]byte(newToken))
	copyForSave := *recPtr
	dm.mu.Unlock()
	dm.persistDevice(&copyForSave)

	return &DeviceCertBundle{
		DeviceID:    deviceID,
		TenantID:    tenantID,
		CertPEM:     string(certPEM),
		CAPEM:       string(dm.caCertPEM),
		DeviceToken: newToken,
		CertSerial:  serialHex,
		ExpiresAt:   expiresAt,
	}, nil
}

// AuthenticateDevice verifies an enrolled agent connecting over a tunnel using its device_id,
// device_token, and optional mTLS client certificate, rejecting revoked or expired devices.
// When backed by a shared ClusterStore (e.g. MySQL), it reads through to the shared store
// so new enrollments and revocations performed on any peer Hub node take effect immediately.
func (dm *DeviceManager) AuthenticateDevice(tenantID, deviceID, deviceToken string, peerCerts []*x509.Certificate) error {
	rec, ok := dm.lookupDeviceReadThrough(deviceID)
	if !ok {
		return ErrUnknownDevice
	}
	revoked := rec.Revoked
	recTenant := rec.TenantID
	exp := rec.CertExpiresAt
	expectedHash := rec.tokenHash

	if revoked {
		return ErrDeviceRevoked
	}
	if recTenant != tenantID {
		return ErrCertMismatch
	}
	if time.Now().UTC().After(exp) {
		return ErrDeviceCertExpired
	}
	provided := sha256.Sum256([]byte(deviceToken))
	if subtle.ConstantTimeCompare(expectedHash[:], provided[:]) != 1 {
		return ErrInvalidToken
	}
	if len(peerCerts) > 0 && !certMatchesDevice(peerCerts[0], tenantID, deviceID) {
		return ErrCertMismatch
	}
	return nil
}

// lookupDeviceReadThrough fetches the freshest device state from ClusterStore when available
// (falling back to local memory if the store is unavailable or single-node).
func (dm *DeviceManager) lookupDeviceReadThrough(deviceID string) (DeviceRecord, bool) {
	if cs, ok := dm.st.(store.ClusterStore); ok {
		if pd, err := cs.GetDevice(deviceID); err == nil {
			if pd == nil {
				return DeviceRecord{}, false
			}
			rec := persistedToDeviceRecord(*pd)
			dm.mu.Lock()
			dm.devices[deviceID] = rec
			dm.mu.Unlock()
			return *rec, true
		}
	}
	dm.mu.RLock()
	rec, ok := dm.devices[deviceID]
	var cp DeviceRecord
	if ok {
		cp = *rec
	}
	dm.mu.RUnlock()
	return cp, ok
}

// SyncDevices merges the latest device table from a shared ClusterStore into memory
// and returns all revoked device IDs so the Hub can immediately evict any live sessions
// belonging to devices revoked on peer Hub nodes.
func (dm *DeviceManager) SyncDevices(persisted []store.PersistedDevice) (revokedIDs []string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	for _, pd := range persisted {
		rec := persistedToDeviceRecord(pd)
		dm.devices[pd.DeviceID] = rec
		if rec.Revoked {
			revokedIDs = append(revokedIDs, rec.DeviceID)
		}
	}
	return revokedIDs
}

func persistedToDeviceRecord(pd store.PersistedDevice) *DeviceRecord {
	var th [32]byte
	if b, err := hex.DecodeString(pd.TokenHashHex); err == nil && len(b) == 32 {
		copy(th[:], b)
	}
	return &DeviceRecord{
		DeviceID:      pd.DeviceID,
		TenantID:      pd.TenantID,
		DeviceName:    pd.DeviceName,
		CertSerial:    pd.CertSerial,
		EnrolledAt:    pd.EnrolledAt,
		CertExpiresAt: pd.CertExpiresAt,
		LastRotatedAt: pd.LastRotatedAt,
		Revoked:       pd.Revoked,
		RevokedAt:     pd.RevokedAt,
		RevokedReason: pd.RevokedReason,
		tokenHash:     th,
	}
}

// RevokeDevice permanently revokes a single device_id without impacting other HA devices of the same tenant.
func (dm *DeviceManager) RevokeDevice(deviceID, reason string) (*DeviceRecord, error) {
	// Ensure a device enrolled on another Hub node is loaded into local cache before revoking.
	if _, ok := dm.lookupDeviceReadThrough(deviceID); !ok {
		return nil, ErrUnknownDevice
	}
	dm.mu.Lock()
	rec, ok := dm.devices[deviceID]
	if !ok {
		dm.mu.Unlock()
		return nil, ErrUnknownDevice
	}
	rec.Revoked = true
	rec.RevokedAt = time.Now().UTC()
	rec.RevokedReason = strings.TrimSpace(reason)
	copyRec := *rec
	dm.mu.Unlock()
	dm.persistDevice(&copyRec)
	return &copyRec, nil
}

func (dm *DeviceManager) persistDevice(rec *DeviceRecord) {
	if dm.st == nil || rec == nil {
		return
	}
	_ = dm.st.SaveDevice(store.PersistedDevice{
		DeviceID:      rec.DeviceID,
		TenantID:      rec.TenantID,
		DeviceName:    rec.DeviceName,
		CertSerial:    rec.CertSerial,
		TokenHashHex:  hex.EncodeToString(rec.tokenHash[:]),
		EnrolledAt:    rec.EnrolledAt,
		CertExpiresAt: rec.CertExpiresAt,
		LastRotatedAt: rec.LastRotatedAt,
		Revoked:       rec.Revoked,
		RevokedAt:     rec.RevokedAt,
		RevokedReason: rec.RevokedReason,
	})
}

// ListDevices returns all enrolled devices sorted by DeviceID.
func (dm *DeviceManager) ListDevices() []DeviceRecord {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	out := make([]DeviceRecord, 0, len(dm.devices))
	for _, r := range dm.devices {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

func (dm *DeviceManager) signDeviceCert(pubKey any, tenantID, deviceID string) (certPEM []byte, serialHex string, expiresAt time.Time, err error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt = now.Add(dm.certTTL)
	spiffeURI, _ := url.Parse(fmt.Sprintf("spiffe://dataproxy/tenant/%s/device/%s", tenantID, deviceID))

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         tenantID,
			OrganizationalUnit: []string{deviceID},
		},
		URIs:        []*url.URL{spiffeURI},
		NotBefore:   now.Add(-2 * time.Minute),
		NotAfter:    expiresAt,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, dm.caCert, pubKey, dm.caSigner)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("sign device cert: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serialHex = hex.EncodeToString(serial.Bytes())
	return certPEM, serialHex, expiresAt, nil
}

func parseAndVerifyCSR(csrPEM string) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return csr, nil
}

func certMatchesDevice(cert *x509.Certificate, tenantID, deviceID string) bool {
	if cert == nil {
		return false
	}
	wantURI := fmt.Sprintf("spiffe://dataproxy/tenant/%s/device/%s", tenantID, deviceID)
	for _, u := range cert.URIs {
		if u.String() == wantURI {
			return true
		}
	}
	return false
}
