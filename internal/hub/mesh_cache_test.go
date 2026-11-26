package hub

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestMeshPeer_StickyRouteCache_SkipsUnrelatedPeers verifies that after discovering which
// peer Hub holds a tenant, subsequent ForwardStream calls hit the cached peer directly (O(1))
// instead of repeatedly probing earlier peers in the cluster list.
func TestMeshPeer_StickyRouteCache_SkipsUnrelatedPeers(t *testing.T) {
	// Peer 1: always replies offline and counts how many times it was probed.
	var peer1Probes atomic.Int64
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen peer1: %v", err)
	}
	defer func() { _ = ln1.Close() }()
	go func() {
		for {
			c, err := ln1.Accept()
			if err != nil {
				return
			}
			peer1Probes.Add(1)
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				var req PeerForwardRequest
				if err := readMeshJSON(conn, &req); err != nil {
					return
				}
				_ = writeMeshJSON(conn, PeerForwardResponse{OK: false, ErrorCode: "offline", Message: "not here"})
			}(c)
		}
	}()

	// Peer 2: always succeeds for tenant-hot and counts hits.
	var peer2Hits atomic.Int64
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen peer2: %v", err)
	}
	defer func() { _ = ln2.Close() }()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			peer2Hits.Add(1)
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				var req PeerForwardRequest
				if err := readMeshJSON(conn, &req); err != nil {
					return
				}
				_ = writeMeshJSON(conn, PeerForwardResponse{OK: true})
				time.Sleep(20 * time.Millisecond)
			}(c)
		}
	}()

	metrics := NewMetrics()
	mesh := NewMeshPeer("node-1", "mesh-sec", []string{ln1.Addr().String(), ln2.Addr().String()}, nil, metrics, nil)

	// Run 6 consecutive forwards for "tenant-hot":
	// Call #1 probes peer1 (miss) -> peer2 (hit + caches route).
	// Calls #2..#6 must go straight to peer2 without touching peer1!
	for i := 0; i < 6; i++ {
		conn, err := mesh.ForwardStream(context.Background(), "tenant-hot", "pg", "tcp", StreamMeta{CallerID: "c"})
		if err != nil {
			t.Fatalf("ForwardStream #%d failed: %v", i, err)
		}
		_ = conn.Close()
	}

	if got := peer1Probes.Load(); got != 1 {
		t.Fatalf("expected peer1 to be probed only once before sticky cache kicked in, got %d", got)
	}
	if got := peer2Hits.Load(); got != 6 {
		t.Fatalf("expected peer2 to handle all 6 forwards, got %d", got)
	}
}
