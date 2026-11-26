package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// TestClient_CancelDuringSlowDial_ExitsImmediately verifies that canceling the agent
// context aborts an in-flight Hub dial immediately instead of waiting for DialTimeout.
func TestClient_CancelDuringSlowDial_ExitsImmediately(t *testing.T) {
	// Open a TCP listener that accepts nothing / holds handshake forever so WS upgrade blocks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold connection open silently without replying to HTTP Upgrade.
			go func(conn net.Conn) {
				time.Sleep(15 * time.Second)
				_ = conn.Close()
			}(c)
		}
	}()

	cli, err := NewClient(&Config{
		TenantID: "tenant-cancel",
		AgentID:  "cancel-node",
		Token:    "tok-cancel",
		Server: ServerConfig{
			Mode:        "wss",
			URL:         "ws://" + ln.Addr().String() + "/tunnel/v1/connect",
			DialTimeout: 10 * time.Second,
		},
		Services: []ServiceConfig{
			{Name: "svc", Protocol: "tcp", TargetAddr: "127.0.0.1:9"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- cli.Run(ctx)
	}()

	// Give client 80ms to enter the blocking DialTunnel call, then cancel!
	time.Sleep(80 * time.Millisecond)
	startCancel := time.Now()
	cancel()

	select {
	case <-done:
		if elapsed := time.Since(startCancel); elapsed > 500*time.Millisecond {
			t.Fatalf("expected agent shutdown during slow dial < 500ms, took %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("agent hung on shutdown during in-flight Hub dial")
	}
}
