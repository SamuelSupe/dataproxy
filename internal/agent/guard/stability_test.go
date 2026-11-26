package guard

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRedisProxy_BackendDisconnectUnblocksIdleClient(t *testing.T) {
	cliEnd, proxyCli := net.Pipe()
	srvEnd, proxySrv := net.Pipe()
	defer func() {
		_ = cliEnd.Close()
		_ = proxyCli.Close()
		_ = srvEnd.Close()
		_ = proxySrv.Close()
	}()

	proxy := NewRedisProxy(RedisGuardConfig{ReadOnly: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = proxy.Proxy(proxyCli, proxySrv, nil)
	}()

	// Backend Redis suddenly closes connection while central client sits idle.
	_ = srvEnd.Close()

	select {
	case <-done:
		// Success: client loop unblocked promptly!
	case <-time.After(1 * time.Second):
		t.Fatal("RedisProxy.Proxy hung after backend server closed connection while client was idle")
	}
}

func TestMongoProxy_BackendDisconnectUnblocksIdleClient(t *testing.T) {
	cliEnd, proxyCli := net.Pipe()
	srvEnd, proxySrv := net.Pipe()
	defer func() {
		_ = cliEnd.Close()
		_ = proxyCli.Close()
		_ = srvEnd.Close()
		_ = proxySrv.Close()
	}()

	proxy := NewMongoProxy(MongoGuardConfig{ReadOnly: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = proxy.Proxy(proxyCli, proxySrv, nil)
	}()

	// Backend MongoDB suddenly restarts / closes while central client sits idle.
	_ = srvEnd.Close()

	select {
	case <-done:
		// Success!
	case <-time.After(1 * time.Second):
		t.Fatal("MongoProxy.Proxy hung after backend server closed connection while client was idle")
	}
}

func TestRedisRESPReader_RejectsOversizedLineAndCommand(t *testing.T) {
	// 1. Unterminated / oversized inline line (> 64 KiB) must be rejected without OOM.
	longLine := bytes.Repeat([]byte("A"), maxRESPLineBytes+1024)
	longLine = append(longLine, '\n')
	var rr respCmdReader
	if _, _, err := rr.read(bufio.NewReader(bytes.NewReader(longLine))); err == nil {
		t.Fatal("expected error for oversized inline RESP line > 64KiB")
	}

	// 2. Oversized array whose cumulative size exceeds 64 MiB must be rejected before allocating.
	// Send *2\r\n$33554433\r\n... -> second element would exceed 64 MiB, or single element > 64 MiB.
	hugeHeader := "*1\r\n$67108865\r\n"
	if _, _, err := rr.read(bufio.NewReader(strings.NewReader(hugeHeader))); err == nil {
		t.Fatal("expected error for oversized RESP bulk string > 64MiB")
	}
}

func TestHTTPMethodGuard_BlockedLargeBodyDoesNotStall(t *testing.T) {
	cliEnd, proxyCli := net.Pipe()
	srvEnd, proxySrv := net.Pipe()
	defer func() {
		_ = cliEnd.Close()
		_ = proxyCli.Close()
		_ = srvEnd.Close()
		_ = proxySrv.Close()
	}()

	g := NewHTTPMethodGuard([]string{"GET"}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.Proxy(proxyCli, proxySrv, nil)
	}()

	// Send a blocked POST declaring a 10 MiB body, streaming only 128 KiB and then pausing.
	// Guard MUST NOT wait for all 10 MiB; it must immediately respond 403 + Connection: close!
	go func() {
		_, _ = io.WriteString(cliEnd, "POST /upload HTTP/1.1\r\nHost: internal\r\nContent-Length: 10485760\r\n\r\n")
		_, _ = cliEnd.Write(bytes.Repeat([]byte("X"), 128*1024))
	}()

	_ = cliEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBytes, err := io.ReadAll(cliEnd)
	if err != nil {
		t.Fatalf("read 403 response failed: %v", err)
	}
	respText := string(respBytes)
	if !strings.Contains(respText, "403 Forbidden") || !strings.Contains(respText, "Connection: close") {
		t.Fatalf("expected 403 Forbidden with Connection: close, got:\n%s", respText)
	}

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("HTTPMethodGuard.Proxy did not exit promptly after closing oversized blocked POST")
	}
}

func TestSCRAM_RejectsExcessiveIterations(t *testing.T) {
	sc, err := newSCRAMSHA256Client("reader", "secret")
	if err != nil {
		t.Fatal(err)
	}
	maliciousChallenge := "r=" + sc.clientNonce + "srvnonce,s=c2FsdA==,i=50000000"
	start := time.Now()
	if _, err := sc.ProcessServerFirst(maliciousChallenge); err == nil {
		t.Fatal("expected SCRAM ProcessServerFirst to reject excessive iteration count")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("SCRAM rejection took too long: %v", time.Since(start))
	}
}

func TestMySQLHandshakeRewrite_LenEncOverflowDoesNotPanic(t *testing.T) {
	// Craft a malicious HandshakeResponse41 with capClientPluginAuthLenencClientData set
	// and a 0xfe lenenc auth length of 0xffffffffffffff00 (negative when cast to signed int).
	pkt := make([]byte, 32+2+9+8)
	// caps with capClientPluginAuthLenencClientData (0x00200000) | capClientConnectWithDB (0x00000008)
	pkt[0] = 0x08
	pkt[2] = 0x20
	pkt[32] = 'u'
	pkt[33] = 0x00 // username NUL
	pkt[34] = 0xfe // 8-byte lenenc marker
	pkt[35] = 0x00
	pkt[36] = 0xff
	pkt[37] = 0xff
	pkt[38] = 0xff
	pkt[39] = 0xff
	pkt[40] = 0xff
	pkt[41] = 0xff
	pkt[42] = 0xff

	if _, err := rewriteHandshakeResponse41(pkt, "real", "pass", []byte("12345678901234567890"), "mysql_native_password", true); err == nil {
		t.Fatal("expected error for malformed overflowing lenenc auth response")
	}
}
