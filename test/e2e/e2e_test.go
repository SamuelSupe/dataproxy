package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/auth"
	"dataproxy/internal/hub"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

type testCertBundle struct {
	CAFile          string
	ServerCertFile  string
	ServerKeyFile   string
	TenantBCertFile string
	TenantBKeyFile  string
}

func generateTestCerts(t *testing.T) testCertBundle {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dataproxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	writeCertAndKey := func(name string, tmpl *x509.Certificate) (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("gen key %s: %v", name, err)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create cert %s: %v", name, err)
		}
		certPath := filepath.Join(dir, name+".crt")
		keyPath := filepath.Join(dir, name+".key")
		_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
		keyDER, _ := x509.MarshalECPrivateKey(key)
		_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
		return certPath, keyPath
	}

	caPath := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600)

	srvCert, srvKey := writeCertAndKey("hub", &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	spiffeURI, _ := url.Parse("spiffe://dataproxy/tenant/tenant-b")
	cliCert, cliKey := writeCertAndKey("tenant-b", &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "tenant-b"},
		URIs:         []*url.URL{spiffeURI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	return testCertBundle{
		CAFile:          caPath,
		ServerCertFile:  srvCert,
		ServerKeyFile:   srvKey,
		TenantBCertFile: cliCert,
		TenantBKeyFile:  cliKey,
	}
}

// startMockMySQLServer simulates a MySQL v10 Server-First TCP server:
// 1. Immediately pushes a MySQL Initial Handshake Packet upon TCP accept (before client speaks).
// 2. Reads a length-prefixed client packet (auth / query) and replies with a MySQL packet containing tag + payload.
func startMockMySQLServer(t *testing.T, serverTag string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock mysql: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Emit Server-First MySQL v10 Initial Handshake Packet immediately!
				greetingPayload := append([]byte{0x0a}, []byte("8.0.36-"+serverTag+"\x00\x01\x02\x03\x04")...)
				if err := writeMySQLPacket(c, 0, greetingPayload); err != nil {
					return
				}

				// Handle client request packets (e.g. login / COM_QUERY)
				for {
					seq, reqPayload, err := readMySQLPacket(c)
					if err != nil {
						return
					}
					reply := append([]byte("OK:"+serverTag+":"), reqPayload...)
					if err := writeMySQLPacket(c, seq+1, reply); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	var hdr [4]byte
	n := len(payload)
	hdr[0] = byte(n)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n >> 16)
	hdr[3] = seq
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMySQLPacket(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

func TestEndToEndMultiTenantDataproxy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	// Start tenant internal backend services.
	mysqlTenantA := startMockMySQLServer(t, "TENANT-A-ORDERS")
	mysqlTenantB := startMockMySQLServer(t, "TENANT-B-LEDGER")

	erpTenantA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify central dataproxy secrets were stripped before reaching tenant!
		if r.Header.Get(hub.HeaderAuth) != "" || r.Header.Get(hub.HeaderTenant) != "" || r.Header.Get(hub.HeaderService) != "" {
			http.Error(w, "leaked dataproxy headers", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Backend-Tenant", "tenant-a")
		w.Header().Set("X-Echo-Tenant-Auth", r.Header.Get("Authorization"))
		_, _ = fmt.Fprintf(w, "erp-a:%s:%s", r.Method, r.URL.Path)
	}))
	defer erpTenantA.Close()
	erpAddrA := strings.TrimPrefix(erpTenantA.URL, "http://")

	// Start Central Hub with WSS TLS + raw mTLS TLS + SOCKS5/CONNECT + HTTP + Admin API.
	hubCfg := &hub.Config{
		TunnelWSSAddr:       "127.0.0.1:0",
		TunnelWSSPath:       "/tunnel/v1/connect",
		TunnelTLSAddr:       "127.0.0.1:0",
		ProxyAddr:           "127.0.0.1:0",
		HTTPAddr:            "127.0.0.1:0",
		AdminAddr:           "127.0.0.1:0",
		AdminToken:          "admin-secret-token",
		VirtualDomainSuffix: "dataproxy.internal",
		TunnelTLS: transport.TLSOptions{
			CertFile:          certs.ServerCertFile,
			KeyFile:           certs.ServerKeyFile,
			ClientCAFile:      certs.CAFile,
			RequireClientCert: false, // tenant-a uses token over WSS; tenant-b enforces require_mtls per-tenant!
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-a", TokenHash: "token-a", RequireTLS: false},
			{TenantID: "tenant-b", TokenHash: "token-b", RequireTLS: true},
		},
		Callers: []auth.CallerPolicy{
			{
				CallerID:        "worker-a",
				Secret:          "pass-a",
				AllowedTenants:  []string{"tenant-a"},
				AllowedServices: []string{"mysql-db", "internal-erp"},
			},
			{
				CallerID:       "platform-all",
				Secret:         "pass-all",
				AllowedTenants: []string{"*"},
			},
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

	// Create a static TCP binding for tenant-a's mysql-db.
	mysqlBinding, err := srv.PortMapper().Add(hub.TCPBindingSpec{
		ID:           "bind-mysql-a",
		ListenAddr:   "127.0.0.1:0",
		TenantID:     "tenant-a",
		ServiceName:  "mysql-db",
		AllowedCIDRs: []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("add tcp binding: %v", err)
	}

	// Start Tenant A Agent Replica #1 & Replica #2 over WSS + TLS.
	startAgent := func(ctx context.Context, cfg *agent.Config) *agent.Client {
		cli, err := agent.NewClient(cfg, logger)
		if err != nil {
			t.Fatalf("NewClient(%s/%s): %v", cfg.TenantID, cfg.AgentID, err)
		}
		go func() { _ = cli.Run(ctx) }()
		select {
		case <-cli.Ready():
		case <-time.After(5 * time.Second):
			t.Fatalf("agent %s/%s failed to register in time", cfg.TenantID, cfg.AgentID)
		}
		return cli
	}

	ctxA1, cancelA1 := context.WithCancel(context.Background())
	defer cancelA1()
	agentA1 := startAgent(ctxA1, &agent.Config{
		TenantID: "tenant-a",
		AgentID:  "tenant-a-replica-1",
		Token:    "token-a",
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			TLS: transport.TLSOptions{
				CAFile:     certs.CAFile,
				ServerName: "localhost",
			},
		},
		Services: []agent.ServiceConfig{
			{Name: "mysql-db", Protocol: "tcp", TargetAddr: mysqlTenantA, MaxConns: 16},
			{Name: "internal-erp", Protocol: "http", TargetAddr: erpAddrA, MaxConns: 16},
		},
	})

	ctxA2, cancelA2 := context.WithCancel(context.Background())
	defer cancelA2()
	_ = startAgent(ctxA2, &agent.Config{
		TenantID: "tenant-a",
		AgentID:  "tenant-a-replica-2",
		Token:    "token-a",
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			TLS: transport.TLSOptions{
				CAFile:     certs.CAFile,
				ServerName: "localhost",
			},
		},
		Services: []agent.ServiceConfig{
			{Name: "mysql-db", Protocol: "tcp", TargetAddr: mysqlTenantA, MaxConns: 16},
			{Name: "internal-erp", Protocol: "http", TargetAddr: erpAddrA, MaxConns: 16},
		},
	})

	// Start Tenant B Agent over raw mTLS TCP (verifying mTLS cert + raw TLS transport!).
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	_ = startAgent(ctxB, &agent.Config{
		TenantID: "tenant-b",
		AgentID:  "tenant-b-mtls-1",
		Token:    "token-b",
		Server: agent.ServerConfig{
			Mode: "tls",
			URL:  srv.RawTLSAddr(),
			TLS: transport.TLSOptions{
				CAFile:     certs.CAFile,
				CertFile:   certs.TenantBCertFile,
				KeyFile:    certs.TenantBKeyFile,
				ServerName: "localhost",
			},
		},
		Services: []agent.ServiceConfig{
			{Name: "mysql-db", Protocol: "tcp", TargetAddr: mysqlTenantB, MaxConns: 16},
		},
	})

	// 1. Verify MySQL Server-First Greeting + Large Query Passthrough via Dedicated TCP Port Mapping.
	t.Run("MySQL_ServerFirst_TCPPortMapping", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", mysqlBinding.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial mysql binding: %v", err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Client stays SILENT first and waits for MySQL Server-First Greeting!
		seq, greeting, err := readMySQLPacket(conn)
		if err != nil {
			t.Fatalf("read mysql greeting: %v", err)
		}
		if seq != 0 || greeting[0] != 0x0a || !bytes.Contains(greeting, []byte("TENANT-A-ORDERS")) {
			t.Fatalf("unexpected mysql greeting: seq=%d payload=%q", seq, greeting)
		}

		// Send a large 64KiB query payload to verify multi-frame streaming passthrough.
		bigQuery := bytes.Repeat([]byte("SELECT * FROM orders;"), 3000)
		if err := writeMySQLPacket(conn, 1, bigQuery); err != nil {
			t.Fatalf("write query: %v", err)
		}
		replySeq, replyPayload, err := readMySQLPacket(conn)
		if err != nil {
			t.Fatalf("read query reply: %v", err)
		}
		wantPrefix := []byte("OK:TENANT-A-ORDERS:")
		if replySeq != 2 || !bytes.HasPrefix(replyPayload, wantPrefix) || !bytes.Equal(replyPayload[len(wantPrefix):], bigQuery) {
			t.Fatalf("query reply mismatch: seq=%d len=%d", replySeq, len(replyPayload))
		}
	})

	// 2. Verify Unified Single-Port SOCKS5 + HTTP CONNECT Virtual Domain Routing & Cross-Tenant ACL.
	t.Run("SOCKS5_And_HTTPConnect_MultiTenant_Isolation", func(t *testing.T) {
		// 2a. worker-a -> tenant-a via SOCKS5 succeeds and gets TENANT-A-ORDERS greeting.
		s5Conn, err := dialSOCKS5(srv.ProxyAddr(), "worker-a", "pass-a", "mysql-db.tenant-a.dataproxy.internal", 3306)
		if err != nil {
			t.Fatalf("socks5 tenant-a failed: %v", err)
		}
		defer func() { _ = s5Conn.Close() }()
		_ = s5Conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, greetingA, err := readMySQLPacket(s5Conn)
		if err != nil || !bytes.Contains(greetingA, []byte("TENANT-A-ORDERS")) {
			t.Fatalf("socks5 tenant-a greeting mismatch: err=%v payload=%q", err, greetingA)
		}

		// 2b. worker-a -> tenant-b via SOCKS5 MUST BE DENIED by Caller ACL!
		if deniedConn, err := dialSOCKS5(srv.ProxyAddr(), "worker-a", "pass-a", "mysql-db.tenant-b.dataproxy.internal", 3306); err == nil {
			_ = deniedConn.Close()
			t.Fatalf("expected worker-a cross-tenant access to tenant-b to be denied")
		}

		// 2c. platform-all -> tenant-b (mTLS tunnel!) via HTTP CONNECT succeeds and gets TENANT-B-LEDGER!
		hcConn, err := dialHTTPConnect(srv.ProxyAddr(), "platform-all", "pass-all", "mysql-db.tenant-b.dataproxy.internal:3306")
		if err != nil {
			t.Fatalf("http connect tenant-b failed: %v", err)
		}
		defer func() { _ = hcConn.Close() }()
		_ = hcConn.SetDeadline(time.Now().Add(5 * time.Second))
		_, greetingB, err := readMySQLPacket(hcConn)
		if err != nil || !bytes.Contains(greetingB, []byte("TENANT-B-LEDGER")) {
			t.Fatalf("http connect tenant-b greeting mismatch: err=%v payload=%q", err, greetingB)
		}
	})

	// 3. Verify Standard HTTP Reverse Proxy (Host Routing, Header Routing, Secret Stripping, TCP Protection).
	t.Run("HTTP_ReverseProxy_Routing_And_Security", func(t *testing.T) {
		httpClient := &http.Client{Timeout: 5 * time.Second}

		// 3a. Host virtual domain routing + preserve tenant's own Authorization header.
		req1, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/v1/items", nil)
		req1.Host = "internal-erp.tenant-a.dataproxy.internal"
		req1.Header.Set(hub.HeaderAuth, "Bearer worker-a:pass-a")
		req1.Header.Set("Authorization", "Bearer tenant-internal-jwt")
		resp1, err := httpClient.Do(req1)
		if err != nil {
			t.Fatalf("http host routing failed: %v", err)
		}
		body1, _ := io.ReadAll(resp1.Body)
		_ = resp1.Body.Close()
		if resp1.StatusCode != http.StatusOK || string(body1) != "erp-a:GET:/v1/items" {
			t.Fatalf("unexpected http host response: status=%d body=%q", resp1.StatusCode, string(body1))
		}
		if resp1.Header.Get("X-Echo-Tenant-Auth") != "Bearer tenant-internal-jwt" {
			t.Fatalf("tenant Authorization header was not preserved: got %q", resp1.Header.Get("X-Echo-Tenant-Auth"))
		}

		// 3b. Explicit header routing.
		req2, _ := http.NewRequest("POST", "http://"+srv.HTTPAddr()+"/v1/sync", nil)
		req2.Header.Set(hub.HeaderTenant, "tenant-a")
		req2.Header.Set(hub.HeaderService, "internal-erp")
		req2.Header.Set(hub.HeaderAuth, "Bearer pass-all")
		resp2, err := httpClient.Do(req2)
		if err != nil {
			t.Fatalf("http header routing failed: %v", err)
		}
		body2, _ := io.ReadAll(resp2.Body)
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK || string(body2) != "erp-a:POST:/v1/sync" {
			t.Fatalf("unexpected http header response: status=%d body=%q", resp2.StatusCode, string(body2))
		}

		// 3c. Attempting to hit a TCP-only MySQL service via HTTP Ingress must be rejected!
		req3, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
		req3.Host = "mysql-db.tenant-a.dataproxy.internal"
		req3.Header.Set(hub.HeaderAuth, "Bearer pass-all")
		resp3, err := httpClient.Do(req3)
		if err != nil {
			t.Fatalf("http to tcp service request error: %v", err)
		}
		_ = resp3.Body.Close()
		if resp3.StatusCode == http.StatusOK {
			t.Fatalf("expected non-200 when hitting tcp-only mysql service via HTTP ingress")
		}
	})

	// 4. Verify Agent Zero-Trust Local Whitelist Defense-In-Depth (even if Hub bypasses announcement check).
	t.Run("Agent_ZeroTrust_LocalWhitelist_Rejection", func(t *testing.T) {
		beforeDenied := agentA1.Whitelist().DeniedCount()

		// Simulate compromised/misconfigured Hub requesting an unlisted internal service.
		conn, err := srv.Registry().OpenTenantStreamUnchecked(context.Background(), "tenant-a", "secret-redis", protocol.ProtocolTCP, "rogue-hub")
		if err == nil {
			_ = conn.Close()
			t.Fatalf("expected agent to reject unlisted service")
		}
		var rejErr *hub.StreamRejectError
		if !errors.As(err, &rejErr) || rejErr.Code != protocol.CodeForbiddenService {
			t.Fatalf("expected ERR_FORBIDDEN_SERVICE, got %v", err)
		}

		// Also verify protocol mismatch directly at agent side (sending http to tcp-only mysql-db).
		conn2, err := srv.Registry().OpenTenantStreamUnchecked(context.Background(), "tenant-a", "mysql-db", protocol.ProtocolHTTP, "rogue-hub")
		if err == nil {
			_ = conn2.Close()
			t.Fatalf("expected agent to reject protocol mismatch")
		}
		if !errors.As(err, &rejErr) || rejErr.Code != protocol.CodeProtocolMismatch {
			t.Fatalf("expected ERR_PROTOCOL_MISMATCH, got %v", err)
		}

		// At least one of the two replicas recorded the denials (both share the registry pool).
		if srv.Registry().RejectedStreams() < 2 {
			t.Fatalf("expected hub rejected_streams >= 2, got %d (a1 denied before=%d)", srv.Registry().RejectedStreams(), beforeDenied)
		}
	})

	// 5. Verify Dynamic Admin API Binding + HA Multi-Replica Graceful Failover.
	t.Run("AdminAPI_DynamicBinding_And_HAFailover", func(t *testing.T) {
		httpClient := &http.Client{Timeout: 5 * time.Second}

		// Dynamically create an ephemeral TCP binding via Admin API.
		body := strings.NewReader(`{"listen_addr":"127.0.0.1:0","tenant_id":"tenant-a","service_name":"mysql-db","ttl_seconds":60}`)
		req, _ := http.NewRequest("POST", "http://"+srv.AdminAddr()+"/api/v1/bindings/tcp", body)
		req.Header.Set("Authorization", "Bearer admin-secret-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("admin create binding: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
		}
		var dynBind hub.TCPBindingInfo
		if err := json.NewDecoder(resp.Body).Decode(&dynBind); err != nil {
			t.Fatalf("decode binding info: %v", err)
		}

		// Shut down Replica #1 gracefully; Replica #2 must seamlessly handle new connections!
		cancelA1()
		time.Sleep(150 * time.Millisecond)

		for i := 0; i < 3; i++ {
			c, err := net.DialTimeout("tcp", dynBind.ListenAddr, 3*time.Second)
			if err != nil {
				t.Fatalf("dial dynamic binding after failover (iter %d): %v", i, err)
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, g, err := readMySQLPacket(c)
			_ = c.Close()
			if err != nil || !bytes.Contains(g, []byte("TENANT-A-ORDERS")) {
				t.Fatalf("failover iter %d failed: err=%v greeting=%q", i, err, g)
			}
		}

		// Verify /api/v1/tenants and /metrics endpoints.
		tReq, _ := http.NewRequest("GET", "http://"+srv.AdminAddr()+"/api/v1/tenants", nil)
		tReq.Header.Set("Authorization", "Bearer admin-secret-token")
		tResp, err := httpClient.Do(tReq)
		if err != nil || tResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/v1/tenants failed: err=%v resp=%v", err, tResp)
		}
		_ = tResp.Body.Close()

		mResp, err := httpClient.Get("http://" + srv.AdminAddr() + "/metrics")
		if err != nil || mResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /metrics failed: err=%v", err)
		}
		mBody, _ := io.ReadAll(mResp.Body)
		_ = mResp.Body.Close()
		if !strings.Contains(string(mBody), "dataproxy_online_tenants 2") {
			t.Fatalf("expected 2 online tenants in metrics, got:\n%s", string(mBody))
		}
	})
}

func dialSOCKS5(proxyAddr, user, pass, targetDomain string, targetPort uint16) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: VER=5, NMETHODS=1, METHOD=0x02 (Username/Password)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var methodSel [2]byte
	if _, err := io.ReadFull(conn, methodSel[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if methodSel[1] != 0x02 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 server rejected user/pass auth: 0x%02x", methodSel[1])
	}

	// RFC 1929 Username/Password subnegotiation
	authBuf := bytes.NewBuffer([]byte{0x01, byte(len(user))})
	authBuf.WriteString(user)
	authBuf.WriteByte(byte(len(pass)))
	authBuf.WriteString(pass)
	if _, err := conn.Write(authBuf.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(conn, authResp[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if authResp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth failed: 0x%02x", authResp[1])
	}

	// CONNECT with ATYP=0x03 (Domain Name)
	req := bytes.NewBuffer([]byte{0x05, 0x01, 0x00, 0x03, byte(len(targetDomain))})
	req.WriteString(targetDomain)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], targetPort)
	req.Write(portBytes[:])
	if _, err := conn.Write(req.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var rep [10]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if rep[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect rejected: rep=0x%02x", rep[1])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func dialHTTPConnect(proxyAddr, user, pass, targetHostPort string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		targetHostPort, targetHostPort, cred)
	if _, err := io.WriteString(conn, reqStr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("http connect failed: status=%d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	return &readerConn{Conn: conn, r: br}, nil
}

type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (rc *readerConn) Read(p []byte) (int, error) {
	return rc.r.Read(p)
}
