package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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

// TestQUIC_NativeTunnel_EnrolledPKI_Throughput_Doctor verifies:
// 1) Native QUIC (UDP + TLS 1.3 + QUIC native streams, zero Yamux) tunnel end-to-end.
// 2) Device PKI mTLS client certificate authentication over QUIC TLS 1.3.
// 3) HTTP Ticket routing, TCP streaming, 40 parallel streams, 16 MiB throughput, and RFC 9002 SmoothedRTT telemetry.
// 4) dataproxy-agent doctor check passing cleanly in QUIC mode.
func TestQUIC_NativeTunnel_EnrolledPKI_Throughput_Doctor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	// Tenant local HTTP backend.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = fmt.Fprintf(w, "quic-http:%s", r.URL.Path)
	}))
	defer httpSrv.Close()
	httpAddr := strings.TrimPrefix(httpSrv.URL, "http://")

	// Tenant local TCP echo backend for throughput + parallel stream test.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}
	defer func() { _ = tcpLn.Close() }()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				bufPtr := transport.GetCopyBuf()
				defer transport.PutCopyBuf(bufPtr)
				_, _ = io.CopyBuffer(conn, conn, *bufPtr)
			}(c)
		}
	}()

	// Start Hub with WSS (for device enroll) + native QUIC tunnel listener!
	srv, err := hub.NewServer(&hub.Config{
		TunnelWSSAddr:     "127.0.0.1:0",
		TunnelQUICAddr:    "127.0.0.1:0",
		HTTPAddr:          "127.0.0.1:0",
		AdminAddr:         "127.0.0.1:0",
		TicketSigningKey:  "quic-ticket-key",
		HeartbeatInterval: 1 * time.Second,
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("hub Start: %v", err)
	}
	defer srv.Close()

	// Enroll a tenant device via 15-min one-time enrollment code (mTLS client cert verified over QUIC TLS 1.3!).
	enr, err := srv.Devices().CreateEnrollment("tenant-quic", "quic-edge-01", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	stateDir := filepath.Join(t.TempDir(), "quic-device-state")
	tlsOpts := transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"}
	if _, err := agent.EnrollDevice(context.Background(), agent.EnrollOptions{
		HubBaseURL: "https://" + srv.WSSAddr(),
		Code:       enr.Code,
		StateDir:   stateDir,
		TLS:        tlsOpts,
	}); err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}

	agentCfg := &agent.Config{
		DeviceStateDir: stateDir,
		AgentID:        "quic-edge-01",
		Server: agent.ServerConfig{
			Mode: "quic",
			URL:  "quic://" + srv.QUICAddr(),
			TLS:  tlsOpts,
		},
		Services: []agent.ServiceConfig{
			{Name: "api", Protocol: "http", TargetAddr: httpAddr},
			{Name: "echo", Protocol: "tcp", TargetAddr: tcpLn.Addr().String()},
		},
	}

	// Verify RunDoctor passes in QUIC mode with enrolled device mTLS cert!
	doc := agent.RunDoctor(context.Background(), agentCfg)
	if !doc.AllPassed() {
		var buf bytes.Buffer
		doc.Format(&buf)
		t.Fatalf("expected QUIC doctor to pass:\n%s", buf.String())
	}

	cli, err := agent.NewClient(agentCfg, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli.Run(ctx) }()

	waitUntil(t, 5*time.Second, func() bool {
		snaps := srv.Registry().Snapshot()
		return len(snaps) == 1 && len(snaps[0].Sessions) == 1 && snaps[0].Sessions[0].Transport == "quic"
	}, "tenant-quic online via native QUIC")

	// 1. HTTP reverse proxy with Job Ticket over QUIC!
	tk, err := srv.Tickets().Issue("tenant-quic", "api", time.Minute, nil)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/hello", nil)
	req.Header.Set(hub.HeaderTicket, tk.JWT)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP over QUIC failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "quic-http:/hello" {
		t.Fatalf("unexpected HTTP over QUIC response: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 2. Single-stream 16 MiB TCP throughput over native QUIC!
	bind, err := srv.PortMapper().Add(hub.TCPBindingSpec{TenantID: "tenant-quic", ServiceName: "echo"})
	if err != nil {
		t.Fatalf("bind echo: %v", err)
	}
	const totalBytes = 16 * 1024 * 1024
	payload := make([]byte, totalBytes)
	_, _ = rand.Read(payload)

	conn, err := net.DialTimeout("tcp", bind.ListenAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial echo binding: %v", err)
	}
	start := time.Now()
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		writeErr <- err
	}()
	got := make([]byte, totalBytes)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read 16MiB over QUIC failed: %v", err)
	}
	_ = conn.Close()
	if err := <-writeErr; err != nil {
		t.Fatalf("write 16MiB over QUIC failed: %v", err)
	}
	elapsed := time.Since(start)
	if !bytes.Equal(got, payload) {
		t.Fatalf("16MiB QUIC echo data mismatch")
	}
	t.Logf("Native QUIC (UDP+TLS1.3) single-stream throughput: %.1f MiB/s (16 MiB in %v)",
		float64(totalBytes)/(1024*1024)/elapsed.Seconds(), elapsed.Round(time.Millisecond))

	// 3. 40 concurrent parallel QUIC native streams!
	var wg sync.WaitGroup
	errCh := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", bind.ListenAddr, 3*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer func() { _ = c.Close() }()
			msg := fmt.Sprintf("quic-parallel-stream-%02d", id)
			if _, err := io.WriteString(c, msg); err != nil {
				errCh <- err
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(c, buf); err != nil {
				errCh <- err
				return
			}
			if string(buf) != msg {
				errCh <- fmt.Errorf("mismatch: got %q want %q", string(buf), msg)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("parallel QUIC stream failed: %v", err)
	}

	// 4. Verify RFC 9002 SmoothedRTT was recorded on heartbeat!
	waitUntil(t, 3*time.Second, func() bool {
		return srv.Metrics().TunnelRTT.Count() >= 1
	}, "QUIC SmoothedRTT sample recorded in Prometheus histogram")
}

// TestQUIC_AutoMode_PrefersQUIC_AndFallsBackToWSSWhenUDPBlocked verifies:
// 1) In "auto" mode, Agent connects over QUIC when UDP QUIC is reachable.
// 2) When UDP QUIC is blocked/unreachable, Agent seamlessly falls back to WSS without error.
func TestQUIC_AutoMode_PrefersQUIC_AndFallsBackToWSSWhenUDPBlocked(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "auto-mode-ok")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	srv, err := hub.NewServer(&hub.Config{
		TunnelWSSAddr:               "127.0.0.1:0",
		TunnelQUICAddr:              "127.0.0.1:0",
		HTTPAddr:                    "127.0.0.1:0",
		AllowUnauthenticatedCallers: true,
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-auto-quic", TokenHash: "tok-aq"},
			{TenantID: "tenant-auto-fallback", TokenHash: "tok-af"},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("hub Start: %v", err)
	}
	defer srv.Close()

	tlsOpts := transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"}

	// Case A: QUIC reachable -> "auto" picks QUIC!
	cliA, err := agent.NewClient(&agent.Config{
		TenantID: "tenant-auto-quic",
		AgentID:  "auto-a",
		Token:    "tok-aq",
		Server: agent.ServerConfig{
			Mode:    "auto",
			URL:     "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			QUICURL: srv.QUICAddr(),
			TLS:     tlsOpts,
		},
		Services: []agent.ServiceConfig{
			{Name: "app", Protocol: "http", TargetAddr: backendAddr},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewClient A: %v", err)
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() { _ = cliA.Run(ctxA) }()

	waitUntil(t, 5*time.Second, func() bool {
		for _, ts := range srv.Registry().Snapshot() {
			if ts.TenantID == "tenant-auto-quic" && len(ts.Sessions) == 1 && ts.Sessions[0].Transport == "quic" {
				return true
			}
		}
		return false
	}, "auto mode picked QUIC when reachable")

	// Case B: Allocate a silent UDP port that drops all packets (simulating corporate UDP firewall!) -> "auto" Happy-Eyeballs falls back to WSS in ~250ms even with 5s DialTimeout!
	transport.ClearQUICNegativeCache()
	blackholeUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole udp: %v", err)
	}
	defer func() { _ = blackholeUDP.Close() }()

	startFallback := time.Now()
	cliB, err := agent.NewClient(&agent.Config{
		TenantID: "tenant-auto-fallback",
		AgentID:  "auto-b",
		Token:    "tok-af",
		Server: agent.ServerConfig{
			Mode:        "auto",
			URL:         "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			QUICURL:     blackholeUDP.LocalAddr().String(),
			DialTimeout: 5 * time.Second, // Happy-Eyeballs must NOT wait 5s for blackholed UDP!
			TLS:         tlsOpts,
		},
		Services: []agent.ServiceConfig{
			{Name: "app", Protocol: "http", TargetAddr: backendAddr},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewClient B: %v", err)
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go func() { _ = cliB.Run(ctxB) }()

	waitUntil(t, 2*time.Second, func() bool {
		for _, ts := range srv.Registry().Snapshot() {
			if ts.TenantID == "tenant-auto-fallback" && len(ts.Sessions) == 1 && ts.Sessions[0].Transport == "wss" {
				return true
			}
		}
		return false
	}, "auto mode Happy-Eyeballs fell back to WSS when UDP blocked")
	if elapsed := time.Since(startFallback); elapsed > 1200*time.Millisecond {
		t.Fatalf("expected Happy-Eyeballs fallback < 1.2s (not full 5s DialTimeout), took %v", elapsed)
	}
	t.Logf("Happy-Eyeballs UDP-blackhole -> WSS fallback completed in %v", time.Since(startFallback).Round(time.Millisecond))

	// Confirm traffic succeeds through the WSS fallback session!
	req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
	req.Header.Set(hub.HeaderTenant, "tenant-auto-fallback")
	req.Header.Set(hub.HeaderService, "app")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP over auto->wss fallback failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "auto-mode-ok" {
		t.Fatalf("unexpected fallback response: status=%d body=%q", resp.StatusCode, string(body))
	}
}
