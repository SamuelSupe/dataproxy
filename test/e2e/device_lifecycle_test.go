package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/auth"
	"dataproxy/internal/hub"
	"dataproxy/internal/transport"
)

func TestDevicePKI_EnrollRotateRevoke_HTTPInjectHeaders_HealthTelemetry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	// Tenant internal ERP HTTP service that strictly requires tenant-local API credentials.
	t.Setenv("DPX_E2E_ERP_BEARER", "TenantOnlyERPToken!999")
	apiKeyFile := filepath.Join(t.TempDir(), "erp_api_key")
	if err := os.WriteFile(apiKeyFile, []byte("VaultAPIKey-777\n"), 0600); err != nil {
		t.Fatalf("write api key file: %v", err)
	}

	erpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Header.Get("Authorization") != "Bearer TenantOnlyERPToken!999" {
			http.Error(w, "missing injected bearer token", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-API-Key") != "VaultAPIKey-777" {
			http.Error(w, "missing injected api key", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "erp-authenticated-locally")
	}))
	defer erpSrv.Close()
	erpAddr := strings.TrimPrefix(erpSrv.URL, "http://")

	// Allocate a guaranteed-closed port for testing unhealthy sanitized telemetry!
	deadLn, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()

	// Start Hub WITHOUT any static tenant token configured for "tenant-pki" (100% enrolled via PKI!).
	hubCfg := &hub.Config{
		TunnelWSSAddr:    "127.0.0.1:0",
		HTTPAddr:         "127.0.0.1:0",
		AdminAddr:        "127.0.0.1:0",
		AdminToken:       "pki-admin-token",
		TicketSigningKey: "pki-ticket-key",
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
	}
	srv, err := hub.NewServer(hubCfg, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("hub Start: %v", err)
	}
	defer srv.Close()

	httpCli := &http.Client{Timeout: 5 * time.Second}
	createEnrollment := func(devName string) auth.EnrollmentInfo {
		body, _ := json.Marshal(map[string]any{
			"tenant_id":   "tenant-pki",
			"device_name": devName,
			"ttl_seconds": 900,
		})
		req, _ := http.NewRequest("POST", "http://"+srv.AdminAddr()+"/api/v1/enrollments", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer pki-admin-token")
		resp, err := httpCli.Do(req)
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("create enrollment failed: err=%v resp=%v", err, resp)
		}
		defer func() { _ = resp.Body.Close() }()
		var info auth.EnrollmentInfo
		_ = json.NewDecoder(resp.Body).Decode(&info)
		return info
	}

	// 1. Enroll TWO HA devices (devA and devB) via one-time 15-min enrollment codes.
	enrA := createEnrollment("dc-node-a")
	enrB := createEnrollment("dc-node-b")

	stateDirA := filepath.Join(t.TempDir(), "state-a")
	stateDirB := filepath.Join(t.TempDir(), "state-b")
	hubHTTPS := "https://" + srv.WSSAddr()
	tlsOpts := transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"}

	stA, err := agent.EnrollDevice(context.Background(), agent.EnrollOptions{
		HubBaseURL: hubHTTPS,
		Code:       enrA.Code,
		StateDir:   stateDirA,
		TLS:        tlsOpts,
	})
	if err != nil {
		t.Fatalf("EnrollDevice A failed: %v", err)
	}

	// Replay check: reusing enrA.Code MUST be rejected!
	if _, err := agent.EnrollDevice(context.Background(), agent.EnrollOptions{
		HubBaseURL: hubHTTPS,
		Code:       enrA.Code,
		StateDir:   filepath.Join(t.TempDir(), "replay"),
		TLS:        tlsOpts,
	}); err == nil {
		t.Fatalf("expected one-time enrollment code replay to be rejected")
	}

	stB, err := agent.EnrollDevice(context.Background(), agent.EnrollOptions{
		HubBaseURL: hubHTTPS,
		Code:       enrB.Code,
		StateDir:   stateDirB,
		TLS:        tlsOpts,
	})
	if err != nil {
		t.Fatalf("EnrollDevice B failed: %v", err)
	}

	// 2. Start BOTH enrolled HA agents using ONLY device_state_dir (zero static tokens!).
	startEnrolledAgent := func(ctx context.Context, stateDir string) *agent.Client {
		cfg := &agent.Config{
			DeviceStateDir:       stateDir,
			HealthReportInterval: 200 * time.Millisecond,
			Server: agent.ServerConfig{
				Mode: "wss",
				URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
				TLS:  tlsOpts,
			},
			Services: []agent.ServiceConfig{
				{
					Name:               "erp-live",
					Protocol:           "http",
					TargetAddr:         erpAddr,
					AllowedHTTPMethods: []string{"GET"},
					InjectHeaders: map[string]string{
						"Authorization": "Bearer env:DPX_E2E_ERP_BEARER",
						"X-API-Key":     "file:" + apiKeyFile,
					},
				},
				{
					Name:       "dead-mysql",
					Protocol:   "tcp",
					TargetAddr: deadAddr,
				},
			},
		}
		cli, err := agent.NewClient(cfg, logger)
		if err != nil {
			t.Fatalf("NewClient enrolled: %v", err)
		}
		go func() { _ = cli.Run(ctx) }()
		select {
		case <-cli.Ready():
		case <-time.After(5 * time.Second):
			t.Fatalf("enrolled agent failed to register")
		}
		return cli
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	cliA := startEnrolledAgent(ctxA, stateDirA)

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	_ = startEnrolledAgent(ctxB, stateDirB)

	// 3. Test HTTP Local Header Credential Injection via Job Ticket (zero ERP secret in center!).
	tkt, err := srv.Tickets().Issue("tenant-pki", "erp-live", 2*time.Minute, map[string]string{"job_id": "erp-sync-1"})
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	reqHTTP, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/v1/data", nil)
	reqHTTP.Header.Set(hub.HeaderTicket, tkt.JWT)
	respHTTP, err := httpCli.Do(reqHTTP)
	if err != nil {
		t.Fatalf("HTTP call failed: %v", err)
	}
	httpBody, _ := io.ReadAll(respHTTP.Body)
	_ = respHTTP.Body.Close()
	if respHTTP.StatusCode != http.StatusOK || string(httpBody) != "erp-authenticated-locally" {
		t.Fatalf("expected HTTP inject_headers auth success, got status=%d body=%q", respHTTP.StatusCode, string(httpBody))
	}

	// 4. Verify Sanitized Health Report (FrameHealthReport) reached Hub WITHOUT leaking internal IP!
	deadline := time.Now().Add(3 * time.Second)
	var healthVerified bool
	for time.Now().Before(deadline) {
		tReq, _ := http.NewRequest("GET", "http://"+srv.AdminAddr()+"/api/v1/tenants", nil)
		tReq.Header.Set("Authorization", "Bearer pki-admin-token")
		tResp, err := httpCli.Do(tReq)
		if err == nil {
			b, _ := io.ReadAll(tResp.Body)
			_ = tResp.Body.Close()
			txt := string(b)
			if strings.Contains(txt, `"erp-live"`) && strings.Contains(txt, `"dead-mysql"`) && strings.Contains(txt, "正常 (HTTP 200)") && strings.Contains(txt, "拒绝连接") {
				if strings.Contains(txt, deadAddr) || strings.Contains(txt, erpAddr) {
					t.Fatalf("SECURITY VIOLATION: internal target IP leaked in health report: %s", txt)
				}
				healthVerified = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthVerified {
		t.Fatalf("did not receive expected sanitized health telemetry on Hub /api/v1/tenants")
	}

	// Verify Prometheus health gauge!
	mResp, _ := httpCli.Get("http://" + srv.AdminAddr() + "/metrics")
	mBytes, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	if !strings.Contains(string(mBytes), `dataproxy_tenant_service_healthy{tenant_id="tenant-pki"`) {
		t.Fatalf("expected dataproxy_tenant_service_healthy metric in /metrics")
	}

	// 5. Rotate devA's short-lived certificate & verify new serial number!
	rotatedA, err := cliA.RotateDeviceCertNow(context.Background())
	if err != nil {
		t.Fatalf("RotateDeviceCertNow failed: %v", err)
	}
	if rotatedA.CertSerial == stA.CertSerial {
		t.Fatalf("expected rotated certificate serial to differ from original")
	}

	// 6. Revoke ONLY devA -> devA is kicked immediately & cannot renew, while sibling HA devB keeps serving!
	revReq, _ := http.NewRequest("POST", "http://"+srv.AdminAddr()+"/api/v1/devices/"+stA.DeviceID+"/revoke", strings.NewReader(`{"reason":"decommissioned VM"}`))
	revReq.Header.Set("Authorization", "Bearer pki-admin-token")
	revResp, err := httpCli.Do(revReq)
	if err != nil || revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke devA failed: err=%v resp=%v", err, revResp)
	}
	_ = revResp.Body.Close()

	// Revoked devA MUST be blocked from renewing its certificate!
	if _, err := cliA.RotateDeviceCertNow(context.Background()); err == nil {
		t.Fatalf("expected revoked device A renewal to be rejected")
	}

	// Sibling HA device B MUST remain online and keep serving traffic uninterrupted!
	time.Sleep(150 * time.Millisecond)
	snaps := srv.Registry().Snapshot()
	if len(snaps) != 1 || len(snaps[0].Sessions) != 1 || snaps[0].Sessions[0].DeviceID != stB.DeviceID {
		t.Fatalf("expected ONLY devB (%s) to remain online, got: %+v", stB.DeviceID, snaps)
	}
	reqAfterRevoke, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/v1/still-alive", nil)
	reqAfterRevoke.Header.Set(hub.HeaderTicket, tkt.JWT)
	respAfter, err := httpCli.Do(reqAfterRevoke)
	if err != nil || respAfter.StatusCode != http.StatusOK {
		t.Fatalf("expected HA sibling devB to serve traffic after devA revocation: err=%v resp=%v", err, respAfter)
	}
	_ = respAfter.Body.Close()
}
