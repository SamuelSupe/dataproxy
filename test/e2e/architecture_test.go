package e2e

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/auth"
	"dataproxy/internal/hub"
	"dataproxy/internal/transport"
)

// TestArchitecture_HubClusterMesh_StatelessCrossNodeTickets verifies:
// 1) Multi-node Hub Cluster Mesh transparent forwarding (Caller -> Hub-1 -> Mesh -> Hub-2 -> Agent -> Backend).
// 2) Stateless cross-node MySQL Ticket HMAC verification (Ticket issued on Hub-2, verified on Hub-1 with zero shared RAM).
func TestArchitecture_HubClusterMesh_StatelessCrossNodeTickets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "mesh-ok:%s", r.URL.Path)
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	const sharedTicketKey = "cluster-shared-ticket-hmac-key"
	const sharedMeshSecret = "cluster-shared-mesh-secret"

	// Start Hub-2 (the node holding the tenant agent tunnel).
	hub2, err := hub.NewServer(&hub.Config{
		NodeID:           "hub-node-2",
		TunnelWSSAddr:    "127.0.0.1:0",
		MeshListenAddr:   "127.0.0.1:0",
		MeshSecret:       sharedMeshSecret,
		TicketSigningKey: sharedTicketKey,
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-mesh", TokenHash: "tok-mesh"},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer hub2: %v", err)
	}
	if err := hub2.Start(); err != nil {
		t.Fatalf("hub2 Start: %v", err)
	}
	defer hub2.Close()

	// Start Hub-1 (NO local tenant agent! Routes to Hub-2 via MeshPeers).
	hub1, err := hub.NewServer(&hub.Config{
		NodeID:           "hub-node-1",
		HTTPAddr:         "127.0.0.1:0",
		AdminAddr:        "127.0.0.1:0",
		MeshListenAddr:   "127.0.0.1:0",
		MeshSecret:       sharedMeshSecret,
		MeshPeers:        []string{hub2.MeshAddr()},
		TicketSigningKey: sharedTicketKey,
	}, logger)
	if err != nil {
		t.Fatalf("NewServer hub1: %v", err)
	}
	if err := hub1.Start(); err != nil {
		t.Fatalf("hub1 Start: %v", err)
	}
	defer hub1.Close()

	// Connect tenant-mesh Agent ONLY to Hub-2.
	agentCfg := &agent.Config{
		TenantID: "tenant-mesh",
		AgentID:  "mesh-agent-01",
		Token:    "tok-mesh",
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + hub2.WSSAddr() + "/tunnel/v1/connect",
			TLS:  transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"},
		},
		Services: []agent.ServiceConfig{
			{Name: "erp-api", Protocol: "http", TargetAddr: backendAddr},
		},
	}
	cli, err := agent.NewClient(agentCfg, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli.Run(ctx) }()

	waitUntil(t, 5*time.Second, func() bool {
		return len(hub2.Registry().Snapshot()) == 1
	}, "tenant-mesh online on hub2")

	// Verify Hub-1 has ZERO local agent sessions!
	if snaps := hub1.Registry().Snapshot(); len(snaps) != 0 {
		t.Fatalf("expected 0 local sessions on hub1, got %d", len(snaps))
	}

	// Issue an HTTP Job Ticket on Hub-2, then send the HTTP request to Hub-1!
	issued, err := hub2.Tickets().Issue("tenant-mesh", "erp-api", time.Minute, map[string]string{
		"job_id": "cross-node-job-1",
	})
	if err != nil {
		t.Fatalf("issue ticket on hub2: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://"+hub1.HTTPAddr()+"/orders/42", nil)
	req.Header.Set(hub.HeaderTicket, issued.JWT)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP request to hub1 failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "mesh-ok:/orders/42" {
		t.Fatalf("unexpected mesh response: status=%d body=%q", resp.StatusCode, string(body))
	}

	if forwarded := hub1.Metrics().MeshForwardedStreams.Load(); forwarded < 1 {
		t.Fatalf("expected hub1 MeshForwardedStreams >= 1, got %d", forwarded)
	}

	// Verify stateless cross-node MySQL Ticket verification:
	// Ticket was issued ONLY on hub2; hub1 must verify its MySQL native scramble purely via shared TicketSigningKey!
	salt := []byte("0123456789abcdefghij")
	scramble := computeMySQLNativeScramble(issued.MySQLPassword, salt)
	claims, err := hub1.Tickets().VerifyMySQLNativeScramble(issued.MySQLUser, salt, scramble)
	if err != nil {
		t.Fatalf("stateless cross-node VerifyMySQLNativeScramble on hub1 failed: %v", err)
	}
	if claims.TenantID != "tenant-mesh" || claims.ServiceName != "erp-api" {
		t.Fatalf("unexpected stateless MySQL claims: %+v", claims)
	}

	// Tampered MySQL scramble MUST be rejected on hub1.
	badScramble := append([]byte(nil), scramble...)
	badScramble[0] ^= 0xFF
	if _, err := hub1.Tickets().VerifyMySQLNativeScramble(issued.MySQLUser, salt, badScramble); err == nil {
		t.Fatalf("expected tampered MySQL scramble to fail stateless verification")
	}
}

func computeMySQLNativeScramble(password string, salt []byte) []byte {
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	stage := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s1[i] ^ stage[i]
	}
	return out
}

// TestArchitecture_ControlPlanePersistence_SurvivesHubRestart verifies that Device CA,
// enrolled devices, device revocations, and dynamic tenants survive a full Hub restart via FileStore.
func TestArchitecture_ControlPlanePersistence_SurvivesHubRestart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)
	stateFile := filepath.Join(t.TempDir(), "hub-state.json")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "persisted-ok")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	newHub := func() *hub.Server {
		s, err := hub.NewServer(&hub.Config{
			StateFile:        stateFile,
			TunnelWSSAddr:    "127.0.0.1:0",
			HTTPAddr:         "127.0.0.1:0",
			AdminAddr:        "127.0.0.1:0",
			AdminToken:       "persist-admin",
			TicketSigningKey: "persist-ticket-key",
			TunnelTLS: transport.TLSOptions{
				CertFile: certs.ServerCertFile,
				KeyFile:  certs.ServerKeyFile,
			},
		}, logger)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if err := s.Start(); err != nil {
			t.Fatalf("hub Start: %v", err)
		}
		return s
	}

	// Boot Hub #1, enroll two devices (dev1 & dev2), revoke dev2, upsert dynamic tenant.
	hub1 := newHub()
	httpCli := &http.Client{Timeout: 5 * time.Second}

	enr1, err := hub1.Devices().CreateEnrollment("tenant-persist", "node-1", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollment 1: %v", err)
	}
	enr2, err := hub1.Devices().CreateEnrollment("tenant-persist", "node-2", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollment 2: %v", err)
	}

	tlsOpts := transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"}
	stateDir1 := filepath.Join(t.TempDir(), "dev1")
	stateDir2 := filepath.Join(t.TempDir(), "dev2")

	st1, err := agent.EnrollDevice(context.Background(), agent.EnrollOptions{
		HubBaseURL: "https://" + hub1.WSSAddr(),
		Code:       enr1.Code,
		StateDir:   stateDir1,
		TLS:        tlsOpts,
	})
	if err != nil {
		t.Fatalf("EnrollDevice 1: %v", err)
	}
	st2, err := agent.EnrollDevice(context.Background(), agent.EnrollOptions{
		HubBaseURL: "https://" + hub1.WSSAddr(),
		Code:       enr2.Code,
		StateDir:   stateDir2,
		TLS:        tlsOpts,
	})
	if err != nil {
		t.Fatalf("EnrollDevice 2: %v", err)
	}

	// Revoke dev2 BEFORE Hub #1 shuts down.
	if _, err := hub1.Devices().RevokeDevice(st2.DeviceID, "compromised host"); err != nil {
		t.Fatalf("RevokeDevice 2: %v", err)
	}

	// Dynamically upsert a tenant via Admin API.
	upsertBody, _ := json.Marshal(map[string]any{"tenant_id": "tenant-dyn", "token": "dyn-secret-123"})
	upsertReq, _ := http.NewRequest("POST", "http://"+hub1.AdminAddr()+"/api/v1/tenants", bytes.NewReader(upsertBody))
	upsertReq.Header.Set("Authorization", "Bearer persist-admin")
	upsertResp, err := httpCli.Do(upsertReq)
	if err != nil || upsertResp.StatusCode != http.StatusOK {
		t.Fatalf("upsert dynamic tenant failed: err=%v resp=%v", err, upsertResp)
	}
	_ = upsertResp.Body.Close()

	// Completely shut down Hub #1!
	hub1.Close()

	// Boot brand-new Hub #2 reading the SAME stateFile.
	hub2 := newHub()
	defer hub2.Close()

	// 1. Verify revoked dev2 is STILL rejected after restart.
	if err := hub2.Devices().AuthenticateDevice("tenant-persist", st2.DeviceID, st2.DeviceToken, nil); err == nil {
		t.Fatalf("expected revoked device %s to remain rejected after Hub restart", st2.DeviceID)
	}

	// 2. Verify dev1 connects to Hub #2 WITHOUT re-enrolling and serves traffic!
	cfg1 := &agent.Config{
		TenantID:       "tenant-persist",
		AgentID:        "node-1",
		DeviceStateDir: stateDir1,
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + hub2.WSSAddr() + "/tunnel/v1/connect",
			TLS:  tlsOpts,
		},
		Services: []agent.ServiceConfig{
			{Name: "app", Protocol: "http", TargetAddr: backendAddr},
		},
	}
	cli1, err := agent.NewClient(cfg1, logger)
	if err != nil {
		t.Fatalf("NewClient dev1: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli1.Run(ctx) }()

	waitUntil(t, 5*time.Second, func() bool {
		return len(hub2.Registry().Snapshot()) == 1
	}, "dev1 reconnected after Hub restart")

	ticket, err := hub2.Tickets().Issue("tenant-persist", "app", time.Minute, nil)
	if err != nil {
		t.Fatalf("issue ticket on hub2: %v", err)
	}
	req, _ := http.NewRequest("GET", "http://"+hub2.HTTPAddr()+"/", nil)
	req.Header.Set(hub.HeaderTicket, ticket.JWT)
	resp, err := httpCli.Do(req)
	if err != nil {
		t.Fatalf("HTTP through restarted hub2 failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "persisted-ok" {
		t.Fatalf("unexpected response after restart: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 3. Verify /metrics exposes cert expiry gauge for active dev1 and omits revoked dev2.
	mResp, err := httpCli.Get("http://" + hub2.AdminAddr() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	mBody, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	metricsText := string(mBody)
	if !strings.Contains(metricsText, fmt.Sprintf(`dataproxy_device_cert_expiry_seconds{tenant_id="tenant-persist",device_id=%q}`, st1.DeviceID)) {
		t.Fatalf("missing cert expiry gauge for active dev1 in /metrics:\n%s", metricsText)
	}
	if strings.Contains(metricsText, st2.DeviceID) {
		t.Fatalf("revoked dev2 should not appear in cert expiry gauge:\n%s", metricsText)
	}

	// 4. Verify dynamic tenant persisted across restart.
	tReq, _ := http.NewRequest("GET", "http://"+hub2.AdminAddr()+"/api/v1/tenants", nil)
	tReq.Header.Set("Authorization", "Bearer persist-admin")
	tResp, err := httpCli.Do(tReq)
	if err != nil {
		t.Fatalf("GET /api/v1/tenants failed: %v", err)
	}
	tBody, _ := io.ReadAll(tResp.Body)
	_ = tResp.Body.Close()
	if !strings.Contains(string(tBody), "tenant-dyn") {
		t.Fatalf("expected persisted dynamic tenant-dyn after restart, got: %s", string(tBody))
	}
}

// TestArchitecture_MultiLaneTunnelPool_ControlDataSeparation verifies pool_size: 3 creates
// 1 control lane (lane 0) + 2 data lanes (lanes 1 & 2) and distributes data traffic across data lanes.
func TestArchitecture_MultiLaneTunnelPool_ControlDataSeparation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		_, _ = io.WriteString(w, "pooled-ok")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	srv, err := hub.NewServer(&hub.Config{
		TunnelWSSAddr:               "127.0.0.1:0",
		HTTPAddr:                    "127.0.0.1:0",
		AllowUnauthenticatedCallers: true,
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-pool", TokenHash: "tok-pool"},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	cli, err := agent.NewClient(&agent.Config{
		TenantID: "tenant-pool",
		AgentID:  "pool-agent-01",
		Token:    "tok-pool",
		PoolSize: 3, // Lane 0 = control, Lane 1 & 2 = data
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			TLS:  transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"},
		},
		Services: []agent.ServiceConfig{
			{Name: "api", Protocol: "http", TargetAddr: backendAddr},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli.Run(ctx) }()

	// Wait until all 3 lanes are registered simultaneously (proving lane 1/2 do NOT evict lane 0!).
	waitUntil(t, 5*time.Second, func() bool {
		snaps := srv.Registry().Snapshot()
		return len(snaps) == 1 && len(snaps[0].Sessions) == 3
	}, "3 pooled tunnel lanes online")

	// Fire 16 concurrent HTTP requests using fresh connections (DisableKeepAlives so each opens a stream).
	tr := &http.Transport{DisableKeepAlives: true}
	httpCli := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/data", nil)
			req.Header.Set(hub.HeaderTenant, "tenant-pool")
			req.Header.Set(hub.HeaderService, "api")
			resp, err := httpCli.Do(req)
			if err != nil {
				errCh <- err
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "pooled-ok" {
				errCh <- fmt.Errorf("unexpected status=%d body=%q", resp.StatusCode, string(body))
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("pooled request failed: %v", err)
	}

	snaps := srv.Registry().Snapshot()
	var controlStreams, dataLanesUsed int64
	for _, s := range snaps[0].Sessions {
		if s.Role == "control" {
			controlStreams += s.TotalStreams
		} else if s.Role == "data" && s.TotalStreams > 0 {
			dataLanesUsed++
		}
	}
	if controlStreams != 0 {
		t.Fatalf("expected control lane (lane 0) to carry 0 data streams while data lanes are healthy, got %d", controlStreams)
	}
	if dataLanesUsed != 2 {
		t.Fatalf("expected traffic distributed across both data lanes, got %d active data lanes (sessions=%+v)", dataLanesUsed, snaps[0].Sessions)
	}
}

// TestArchitecture_NoisyNeighborQuotas_And_HandshakeRateLimit verifies Hub-side per-tenant
// max_streams_per_tenant isolation and per-IP handshake rate limiting (429 Too Many Requests).
func TestArchitecture_NoisyNeighborQuotas_And_HandshakeRateLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	releaseCh := make(chan struct{})
	var releaseOnce sync.Once
	releaseSlow := func() { releaseOnce.Do(func() { close(releaseCh) }) }
	slowBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-releaseCh
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer func() {
		releaseSlow()
		slowBackend.Close()
	}()
	backendAddr := strings.TrimPrefix(slowBackend.URL, "http://")

	srv, err := hub.NewServer(&hub.Config{
		TunnelWSSAddr:               "127.0.0.1:0",
		HTTPAddr:                    "127.0.0.1:0",
		AdminAddr:                   "127.0.0.1:0",
		AllowUnauthenticatedCallers: true,
		MaxStreamsPerTenant:         2,
		HandshakeRateLimitPerMin:    120, // 2/sec
		HandshakeBurst:              4,   // Allows 2 initial agents + 2 burst enrolls, then 429!
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-noisy", TokenHash: "tok-noisy"},
			{TenantID: "tenant-quiet", TokenHash: "tok-quiet"},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	startAgent := func(tid, tok string) context.CancelFunc {
		cli, err := agent.NewClient(&agent.Config{
			TenantID: tid,
			AgentID:  tid + "-node",
			Token:    tok,
			Server: agent.ServerConfig{
				Mode: "wss",
				URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
				TLS:  transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"},
			},
			Services: []agent.ServiceConfig{
				{Name: "svc", Protocol: "http", TargetAddr: backendAddr},
			},
		}, logger)
		if err != nil {
			t.Fatalf("NewClient %s: %v", tid, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = cli.Run(ctx) }()
		return cancel
	}
	cancelNoisy := startAgent("tenant-noisy", "tok-noisy")
	defer cancelNoisy()
	cancelQuiet := startAgent("tenant-quiet", "tok-quiet")
	defer cancelQuiet()

	waitUntil(t, 5*time.Second, func() bool {
		return len(srv.Registry().Snapshot()) == 2
	}, "both tenants online")

	// Occupy both stream slots for tenant-noisy with slow requests.
	tr := &http.Transport{DisableKeepAlives: true}
	httpCli := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	var slowWG sync.WaitGroup
	for i := 0; i < 2; i++ {
		slowWG.Add(1)
		go func() {
			defer slowWG.Done()
			req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/slow", nil)
			req.Header.Set(hub.HeaderTenant, "tenant-noisy")
			req.Header.Set(hub.HeaderService, "svc")
			resp, err := httpCli.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}

	// Wait until 2 streams are active on tenant-noisy.
	waitUntil(t, 3*time.Second, func() bool {
		for _, ts := range srv.Registry().Snapshot() {
			if ts.TenantID == "tenant-noisy" && len(ts.Sessions) > 0 && ts.Sessions[0].ActiveStreams == 2 {
				return true
			}
		}
		return false
	}, "tenant-noisy holding 2 active streams")

	// 3rd concurrent stream on tenant-noisy MUST be rejected with 429 Too Many Requests!
	req3, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/fast", nil)
	req3.Header.Set(hub.HeaderTenant, "tenant-noisy")
	req3.Header.Set(hub.HeaderService, "svc")
	resp3, err := httpCli.Do(req3)
	if err != nil {
		t.Fatalf("3rd request error: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests when tenant-noisy exceeds quota, got %d", resp3.StatusCode)
	}

	// Meanwhile, tenant-quiet MUST be 100% unaffected and succeed with 200 OK!
	reqQuiet, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/fast", nil)
	reqQuiet.Header.Set(hub.HeaderTenant, "tenant-quiet")
	reqQuiet.Header.Set(hub.HeaderService, "svc")
	respQuiet, err := httpCli.Do(reqQuiet)
	if err != nil {
		t.Fatalf("tenant-quiet request failed: %v", err)
	}
	_ = respQuiet.Body.Close()
	if respQuiet.StatusCode != http.StatusOK {
		t.Fatalf("expected tenant-quiet to be unaffected (200 OK), got %d", respQuiet.StatusCode)
	}
	releaseSlow()
	slowWG.Wait()

	// Verify per-IP Handshake Rate Limiter returns 429 on rapid bursts to /tunnel/v1/enroll.
	caPEM, _ := os.ReadFile(certs.CAFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tlsCli := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
		},
	}
	got429 := false
	for i := 0; i < 10; i++ {
		r, err := tlsCli.Post("https://"+srv.WSSAddr()+"/tunnel/v1/enroll", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("POST /tunnel/v1/enroll failed: %v", err)
		}
		_ = r.Body.Close()
		if r.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("expected per-IP handshake rate limiter to return 429 on rapid /tunnel/v1/enroll burst")
	}
	if srv.Metrics().QuotaRejectedStreams.Load() < 1 || srv.Metrics().RateLimitedHandshakes.Load() < 1 {
		t.Fatalf("expected quota & rate-limit metrics >= 1, got quota=%d ratelimit=%d",
			srv.Metrics().QuotaRejectedStreams.Load(), srv.Metrics().RateLimitedHandshakes.Load())
	}
}

// TestArchitecture_W3CTraceparent_And_PrometheusHistograms verifies end-to-end W3C traceparent
// propagation (HTTP header + tenant-local JSONL audit log) and Prometheus latency histograms.
func TestArchitecture_W3CTraceparent_And_PrometheusHistograms(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	var mu sync.Mutex
	var seenTraceparents []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		mu.Lock()
		seenTraceparents = append(seenTraceparents, r.Header.Get("traceparent"))
		mu.Unlock()
		_, _ = io.WriteString(w, "traced-ok")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	auditFile := filepath.Join(t.TempDir(), "trace-audit.jsonl")

	srv, err := hub.NewServer(&hub.Config{
		TunnelWSSAddr:               "127.0.0.1:0",
		HTTPAddr:                    "127.0.0.1:0",
		AdminAddr:                   "127.0.0.1:0",
		TicketSigningKey:            "obs-ticket-key",
		HeartbeatInterval:           1 * time.Second,
		AllowUnauthenticatedCallers: true,
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-obs", TokenHash: "tok-obs"},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	cli, err := agent.NewClient(&agent.Config{
		TenantID: "tenant-obs",
		AgentID:  "obs-node-01",
		Token:    "tok-obs",
		Audit:    agent.AuditConfig{File: auditFile},
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			TLS:  transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"},
		},
		Services: []agent.ServiceConfig{
			{Name: "erp", Protocol: "http", TargetAddr: backendAddr},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli.Run(ctx) }()

	waitUntil(t, 5*time.Second, func() bool {
		return len(srv.Registry().Snapshot()) == 1
	}, "tenant-obs online")

	const incomingTP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	httpCli := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}

	// Issue two separate Job Tickets so each job opens its own isolated tenant stream & audit record.
	tk1, err := srv.Tickets().Issue("tenant-obs", "erp", time.Minute, map[string]string{"job_id": "trace-job-1"})
	if err != nil {
		t.Fatalf("issue tk1: %v", err)
	}
	tk2, err := srv.Tickets().Issue("tenant-obs", "erp", time.Minute, map[string]string{"job_id": "trace-job-2"})
	if err != nil {
		t.Fatalf("issue tk2: %v", err)
	}

	// 1. Explicit W3C traceparent propagates untouched to backend AND tenant audit log.
	req1, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/v1/items", nil)
	req1.Header.Set(hub.HeaderTicket, tk1.JWT)
	req1.Header.Set("traceparent", incomingTP)
	resp1, err := httpCli.Do(req1)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("traced req1 failed: err=%v resp=%v", err, resp1)
	}
	_ = resp1.Body.Close()

	// 2. Request without traceparent gets a fresh valid W3C traceparent auto-generated by Hub.
	req2, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/v1/items", nil)
	req2.Header.Set(hub.HeaderTicket, tk2.JWT)
	resp2, err := httpCli.Do(req2)
	if err != nil || resp2.StatusCode != http.StatusOK {
		t.Fatalf("traced req2 failed: err=%v resp=%v", err, resp2)
	}
	_ = resp2.Body.Close()

	mu.Lock()
	tps := append([]string(nil), seenTraceparents...)
	mu.Unlock()
	if len(tps) != 2 || tps[0] != incomingTP || !strings.HasPrefix(tps[1], "00-") || len(tps[1]) != 55 {
		t.Fatalf("unexpected backend traceparent headers: %+v", tps)
	}

	// Wait for async audit writer to flush & verify incomingTP was recorded in tenant-local JSONL audit file.
	waitUntil(t, 3*time.Second, func() bool {
		b, err := os.ReadFile(auditFile)
		return err == nil && strings.Contains(string(b), incomingTP) && strings.Contains(string(b), tps[1])
	}, "traceparents written to tenant-local audit JSONL")

	// Wait for at least 1 heartbeat RTT observation (HeartbeatInterval=200ms).
	waitUntil(t, 3*time.Second, func() bool {
		return srv.Metrics().TunnelRTT.Count() >= 1
	}, "at least 1 tunnel RTT sample recorded")

	// Scrape Prometheus /metrics and verify histograms + counters.
	mResp, err := httpCli.Get("http://" + srv.AdminAddr() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	mBody, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	text := string(mBody)
	for _, want := range []string{
		`dataproxy_stream_open_duration_seconds_bucket{le="0.01"}`,
		`dataproxy_stream_open_duration_seconds_count 2`,
		`dataproxy_tunnel_rtt_seconds_bucket{le="+Inf"}`,
		`dataproxy_mesh_forwarded_streams_total 0`,
		`dataproxy_quota_rejected_streams_total 0`,
		`dataproxy_rate_limited_handshakes_total 0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing expected Prometheus metric %q in /metrics:\n%s", want, text)
		}
	}
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", timeout, desc)
}
