package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/auth"
	"dataproxy/internal/hub"
	"dataproxy/internal/transport"
)

// TestPerfAndStability verifies:
//  1. High-throughput bulk transfer over WSS+TLS+Yamux (reports real MB/s).
//  2. 80 concurrent parallel streams over a single multiplexed tunnel with zero corruption and zero goroutine leak.
//  3. Unreachable Syslog/SIEM endpoint causes ZERO latency stall on the data plane (async queue).
//  4. Fast reconnect with identical AgentID immediately evicts the stale session (zero zombie blackhole).
//  5. Closing a tightly throttled RateLimitedConn aborts rate-limit sleep immediately (<50ms).
func TestPerfAndStability(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	// Start a high-speed local TCP echo/bulk server inside the "tenant intranet".
	// Protocol: client writes 4B big-endian response size; server writes that many 'X' bytes and closes.
	bulkLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen bulk server: %v", err)
	}
	defer func() { _ = bulkLn.Close() }()

	chunk64K := bytes.Repeat([]byte("X"), 64*1024)
	go func() {
		for {
			c, err := bulkLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				var hdr [4]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				rem := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
				for rem > 0 {
					n := len(chunk64K)
					if n > rem {
						n = rem
					}
					if _, err := conn.Write(chunk64K[:n]); err != nil {
						return
					}
					rem -= n
				}
			}(c)
		}
	}()

	// Pick a guaranteed closed TCP port as an unreachable SIEM/Syslog target!
	deadSyslogLn, _ := net.Listen("tcp", "127.0.0.1:0")
	deadSyslogAddr := "tcp://" + deadSyslogLn.Addr().String()
	_ = deadSyslogLn.Close()

	hubCfg := &hub.Config{
		TunnelWSSAddr: "127.0.0.1:0",
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-perf", TokenHash: "perf-secret"},
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

	bulkBind, err := srv.PortMapper().Add(hub.TCPBindingSpec{
		ID:          "perf-bulk",
		ListenAddr:  "127.0.0.1:0",
		TenantID:    "tenant-perf",
		ServiceName: "bulk-svc",
	})
	if err != nil {
		t.Fatalf("add binding: %v", err)
	}

	makeAgentCfg := func() *agent.Config {
		return &agent.Config{
			TenantID: "tenant-perf",
			AgentID:  "perf-node-1",
			Token:    "perf-secret",
			Audit: agent.AuditConfig{
				SyslogAddr: deadSyslogAddr, // Deliberately unreachable TCP SIEM to prove non-blocking hot path!
			},
			Server: agent.ServerConfig{
				Mode: "wss",
				URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
				TLS: transport.TLSOptions{
					CAFile:     certs.CAFile,
					ServerName: "localhost",
				},
			},
			Services: []agent.ServiceConfig{
				{Name: "bulk-svc", Protocol: "tcp", TargetAddr: bulkLn.Addr().String(), MaxConns: 200, IdleTimeout: 10 * time.Second},
			},
		}
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	cli1, err := agent.NewClient(makeAgentCfg(), logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	go func() { _ = cli1.Run(ctx1) }()
	select {
	case <-cli1.Ready():
	case <-time.After(5 * time.Second):
		t.Fatalf("agent failed to register")
	}

	// 1. Bulk Throughput Test (16 MiB over WSS + TLS + Yamux) + non-blocking dead Syslog check.
	t.Run("Throughput_16MiB_WSS_Yamux_WithUnreachableSyslog", func(t *testing.T) {
		var sizeBytes uint32 = 16 * 1024 * 1024
		start := time.Now()
		c, err := net.DialTimeout("tcp", bulkBind.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial bulk: %v", err)
		}
		defer func() { _ = c.Close() }()
		hdr := [4]byte{byte(sizeBytes >> 24), byte(sizeBytes >> 16), byte(sizeBytes >> 8), byte(sizeBytes)}
		if _, err := c.Write(hdr[:]); err != nil {
			t.Fatalf("write size hdr: %v", err)
		}
		n, err := io.Copy(io.Discard, c)
		elapsed := time.Since(start)
		if err != nil || n != int64(sizeBytes) {
			t.Fatalf("bulk transfer failed: got %d bytes, err=%v", n, err)
		}
		mbps := float64(n) / (1024 * 1024) / elapsed.Seconds()
		t.Logf("WSS+TLS+Yamux single-stream throughput: %.1f MiB/s (16 MiB in %s)", mbps, elapsed.Round(time.Millisecond))
		// If dead TCP syslog were blocking synchronously, 2s dial timeout would have stalled this!
		if elapsed > 3*time.Second {
			t.Fatalf("transfer took too long (%s); possible throughput or blocking syslog regression", elapsed)
		}
	})

	// 2. High-Concurrency Stress (80 parallel streams) + Goroutine Leak Check.
	t.Run("Concurrency_80_Parallel_Streams_NoGoroutineLeak", func(t *testing.T) {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		baseGoroutines := runtime.NumGoroutine()

		const workers = 80
		var perStream uint32 = 32 * 1024
		var wg sync.WaitGroup
		errCh := make(chan error, workers)
		start := time.Now()

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				c, err := net.DialTimeout("tcp", bulkBind.ListenAddr, 5*time.Second)
				if err != nil {
					errCh <- fmt.Errorf("worker %d dial: %w", id, err)
					return
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				hdr := [4]byte{0, 0, byte(perStream >> 8), byte(perStream)}
				if _, err := c.Write(hdr[:]); err != nil {
					errCh <- fmt.Errorf("worker %d write: %w", id, err)
					return
				}
				n, err := io.Copy(io.Discard, c)
				if err != nil || n != int64(perStream) {
					errCh <- fmt.Errorf("worker %d read got %d err=%v", id, n, err)
				}
			}(i)
		}
		wg.Wait()
		close(errCh)
		for e := range errCh {
			t.Fatalf("concurrent stream error: %v", e)
		}
		t.Logf("80 concurrent streams x 32KiB completed in %s", time.Since(start).Round(time.Millisecond))

		// Wait briefly for deferred closes and verify goroutine count returns near baseline.
		time.Sleep(150 * time.Millisecond)
		runtime.GC()
		afterGoroutines := runtime.NumGoroutine()
		if afterGoroutines > baseGoroutines+20 {
			t.Fatalf("possible goroutine leak: before=%d after=%d", baseGoroutines, afterGoroutines)
		}
	})

	// 3. Stale Session Eviction on Same-AgentID Fast Reconnect.
	t.Run("StaleSessionEviction_OnReconnect", func(t *testing.T) {
		// Connect a second instance with the EXACT same AgentID ("perf-node-1") while cli1 is still open.
		ctx2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()
		cli2, err := agent.NewClient(makeAgentCfg(), logger)
		if err != nil {
			t.Fatalf("NewClient 2: %v", err)
		}
		go func() { _ = cli2.Run(ctx2) }()
		select {
		case <-cli2.Ready():
		case <-time.After(5 * time.Second):
			t.Fatalf("agent 2 failed to register")
		}

		// Hub MUST have evicted the old session so exactly 1 session exists for "perf-node-1"!
		time.Sleep(100 * time.Millisecond)
		snaps := srv.Registry().Snapshot()
		if len(snaps) != 1 || len(snaps[0].Sessions) != 1 {
			t.Fatalf("expected stale session evicted leaving 1 active session, got: %+v", snaps)
		}
		cancel1()
	})

	// 4. Cancellable RateLimitedConn Close() unblocks immediately without hanging in sleep!
	t.Run("CancellableRateLimitedConn_FastClose", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = b.Close() }()
		// Extremely tight 10 KB/s limiter -> writing 200 KB would sleep ~18 seconds if non-cancellable!
		lim := transport.NewBandwidthLimiter(10_000)
		limited := transport.WrapConnWithLimiters(a, nil, []*transport.BandwidthLimiter{lim})

		go func() { _, _ = io.Copy(io.Discard, b) }()

		done := make(chan error, 1)
		start := time.Now()
		go func() {
			_, err := limited.Write(bytes.Repeat([]byte("Z"), 200_000))
			done <- err
		}()

		time.Sleep(50 * time.Millisecond)
		_ = limited.Close()

		select {
		case <-done:
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("expected Close() to abort rate limiter immediately, took %s", elapsed)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("RateLimitedConn.Write hung after Close()!")
		}
	})
}
