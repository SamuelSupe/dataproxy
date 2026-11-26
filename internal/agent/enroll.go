package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/internal/transport"
)

// DeviceState is persisted locally inside device_state_dir on the customer host.
// The private key (device.key) is generated locally and NEVER leaves the customer host.
type DeviceState struct {
	DeviceID    string    `json:"device_id"`
	TenantID    string    `json:"tenant_id"`
	DeviceToken string    `json:"device_token"`
	CertSerial  string    `json:"cert_serial"`
	ExpiresAt   time.Time `json:"expires_at"`
	HubBaseURL  string    `json:"hub_base_url"`
	CertFile    string    `json:"cert_file"`
	KeyFile     string    `json:"key_file"`
	CAFile      string    `json:"ca_file"`
}

// EnrollOptions specifies parameters for one-time device enrollment via "dataproxy-agent enroll".
type EnrollOptions struct {
	HubBaseURL string // e.g. "https://hub.example.com:8443"
	Code       string // 15-minute single-use enrollment code "enroll_..."
	StateDir   string // Local directory to store device.key, device.crt, device.json
	TLS        transport.TLSOptions
}

// EnrollDevice generates a local ECDSA P-256 private key + CSR, exchanges the one-time
// enrollment code at Hub POST /tunnel/v1/enroll for a short-lived signed device certificate,
// and saves the state securely to StateDir.
func EnrollDevice(ctx context.Context, opts EnrollOptions) (*DeviceState, error) {
	if strings.TrimSpace(opts.HubBaseURL) == "" || strings.TrimSpace(opts.Code) == "" || strings.TrimSpace(opts.StateDir) == "" {
		return nil, errors.New("hub url, enrollment code, and state_dir are required")
	}
	if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	// 1. Generate local ECDSA P-256 private key (never leaves tenant machine!).
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	csrPEM, err := createDeviceCSR(privKey, "dataproxy-agent")
	if err != nil {
		return nil, err
	}

	// 2. Call Hub POST /tunnel/v1/enroll.
	baseURL := normalizeHubHTTPBase(opts.HubBaseURL)
	httpClient, err := buildEnrollHTTPClient(opts.TLS)
	if err != nil {
		return nil, err
	}

	reqBody, _ := json.Marshal(map[string]string{
		"code":    strings.TrimSpace(opts.Code),
		"csr_pem": string(csrPEM),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/tunnel/v1/enroll", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("hub rejected enrollment (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var bundle auth.DeviceCertBundle
	if err := json.Unmarshal(respBytes, &bundle); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}

	return persistDeviceState(opts.StateDir, baseURL, keyPEM, &bundle)
}

// RenewDevice rotates the device's short-lived certificate and token using its existing
// local private key and current valid device credentials via Hub POST /tunnel/v1/renew.
func RenewDevice(ctx context.Context, stateDir string, tlsOpts transport.TLSOptions) (*DeviceState, error) {
	st, err := LoadDeviceState(stateDir)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(st.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read local device key: %w", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("invalid local device key PEM")
	}
	privKey, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse local device key: %w", err)
	}

	csrPEM, err := createDeviceCSR(privKey, st.TenantID)
	if err != nil {
		return nil, err
	}

	// Present current device cert for mTLS renewal if available.
	if tlsOpts.CertFile == "" {
		tlsOpts.CertFile = st.CertFile
		tlsOpts.KeyFile = st.KeyFile
	}
	httpClient, err := buildEnrollHTTPClient(tlsOpts)
	if err != nil {
		return nil, err
	}

	reqBody, _ := json.Marshal(map[string]string{
		"device_id":    st.DeviceID,
		"device_token": st.DeviceToken,
		"csr_pem":      string(csrPEM),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, st.HubBaseURL+"/tunnel/v1/renew", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device renew request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub rejected device renewal (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var bundle auth.DeviceCertBundle
	if err := json.Unmarshal(respBytes, &bundle); err != nil {
		return nil, fmt.Errorf("parse renewal response: %w", err)
	}

	return persistDeviceState(stateDir, st.HubBaseURL, keyPEM, &bundle)
}

// LoadDeviceState reads persisted device credentials from stateDir.
func LoadDeviceState(stateDir string) (*DeviceState, error) {
	metaPath := filepath.Join(stateDir, "device.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read device state %q: %w", metaPath, err)
	}
	var st DeviceState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse device state: %w", err)
	}
	return &st, nil
}

func persistDeviceState(stateDir, hubBaseURL string, keyPEM []byte, bundle *auth.DeviceCertBundle) (*DeviceState, error) {
	keyPath := filepath.Join(stateDir, "device.key")
	certPath := filepath.Join(stateDir, "device.crt")
	caPath := filepath.Join(stateDir, "device_ca.crt")
	metaPath := filepath.Join(stateDir, "device.json")

	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, []byte(bundle.CertPEM), 0644); err != nil {
		return nil, err
	}
	if bundle.CAPEM != "" {
		if err := writeFileAtomic(caPath, []byte(bundle.CAPEM), 0644); err != nil {
			return nil, err
		}
	}

	st := &DeviceState{
		DeviceID:    bundle.DeviceID,
		TenantID:    bundle.TenantID,
		DeviceToken: bundle.DeviceToken,
		CertSerial:  bundle.CertSerial,
		ExpiresAt:   bundle.ExpiresAt,
		HubBaseURL:  hubBaseURL,
		CertFile:    certPath,
		KeyFile:     keyPath,
		CAFile:      caPath,
	}
	metaBytes, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(metaPath, metaBytes, 0600); err != nil {
		return nil, err
	}
	return st, nil
}

// writeFileAtomic writes data via temp file + chmod + fsync + atomic rename so a crash or
// concurrent tunnel reconnect during cert rotation can never observe a truncated key/cert/state file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dpx-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func createDeviceCSR(privKey *ecdsa.PrivateKey, cn string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, privKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func normalizeHubHTTPBase(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	u = strings.Replace(u, "wss://", "https://", 1)
	u = strings.Replace(u, "ws://", "http://", 1)
	if idx := strings.Index(u, "/tunnel/"); idx > 0 {
		u = u[:idx]
	}
	return u
}

func buildEnrollHTTPClient(tlsOpts transport.TLSOptions) (*http.Client, error) {
	tlsCfg, err := transport.BuildClientTLSConfig(tlsOpts)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			TLSClientConfig:   tlsCfg,
			DisableKeepAlives: true,
		},
	}, nil
}
