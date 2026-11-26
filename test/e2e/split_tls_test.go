package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/agent/guard"
	"dataproxy/internal/auth"
	"dataproxy/internal/hub"
	"dataproxy/internal/transport"
)

// TestSplitTLS_AllProtocols_ForceSSL_CredInjection_ReadOnly_Doctor verifies tenant-side Split-TLS
// across all 5 service types (PostgreSQL force_ssl, MySQL require_secure_transport=ON,
// Redis TLS, MongoDB TLS, and Internal HTTPS) while preserving L7 read-only enforcement,
// local credential injection, doctor preflight checks, and sanitized health telemetry.
func TestSplitTLS_AllProtocols_ForceSSL_CredInjection_ReadOnly_Doctor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	srvCert, err := tls.LoadX509KeyPair(certs.ServerCertFile, certs.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	backendTLSCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
	}

	// 1. Mock PostgreSQL server enforcing rds.force_ssl=1 (rejects plaintext StartupMessage!).
	var pgTLSUsed atomic.Int32
	pgLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock pg: %v", err)
	}
	defer func() { _ = pgLn.Close() }()
	go serveForceSSLPostgres(pgLn, backendTLSCfg, "rds_pg_reader", "RDSPGSecret!99", &pgTLSUsed)

	// 2. Mock MySQL 8.4 server enforcing require_secure_transport=ON + caching_sha2_password over TLS.
	var mysqlTLSUsed atomic.Int32
	mysqlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock mysql: %v", err)
	}
	defer func() { _ = mysqlLn.Close() }()
	go serveForceSSLMySQL(mysqlLn, backendTLSCfg, "rds_mysql_reader", "RDSMySQLSecret!88", &mysqlTLSUsed)

	// 3. Mock TLS-only Redis server requiring AUTH.
	var redisTLSUsed atomic.Int32
	redisLn, err := tls.Listen("tcp", "127.0.0.1:0", backendTLSCfg)
	if err != nil {
		t.Fatalf("listen mock redis tls: %v", err)
	}
	defer func() { _ = redisLn.Close() }()
	go serveTLSRedis(redisLn, "RDSRedisSecret!77", &redisTLSUsed)

	// 4. Mock TLS-only MongoDB server answering OP_MSG {hello:1} and {find:...}.
	var mongoTLSUsed atomic.Int32
	mongoLn, err := tls.Listen("tcp", "127.0.0.1:0", backendTLSCfg)
	if err != nil {
		t.Fatalf("listen mock mongo tls: %v", err)
	}
	defer func() { _ = mongoLn.Close() }()
	go serveTLSMongo(mongoLn, &mongoTLSUsed)

	// 5. Internal HTTPS ERP service requiring locally injected Bearer token.
	httpsERP := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusUpgradeRequired)
			return
		}
		if r.Header.Get("Authorization") != "Bearer IntranetHTTPS!Token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "https-erp-ok")
	}))
	httpsERP.TLS = backendTLSCfg
	httpsERP.StartTLS()
	defer httpsERP.Close()
	httpsAddr := strings.TrimPrefix(httpsERP.URL, "https://")

	// Start Hub.
	srv, err := hub.NewServer(&hub.Config{
		TunnelWSSAddr:    "127.0.0.1:0",
		HTTPAddr:         "127.0.0.1:0",
		AdminAddr:        "127.0.0.1:0",
		TicketSigningKey: "split-tls-ticket-key",
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-rds", TokenHash: "tok-rds"},
		},
	}, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("hub Start: %v", err)
	}
	defer srv.Close()

	// Allocate TCP bindings on Hub for PG, MySQL, Redis, Mongo.
	bindPG, err := srv.PortMapper().Add(hub.TCPBindingSpec{TenantID: "tenant-rds", ServiceName: "pg-rds"})
	if err != nil {
		t.Fatalf("bind pg: %v", err)
	}
	bindMySQL, err := srv.PortMapper().Add(hub.TCPBindingSpec{TenantID: "tenant-rds", ServiceName: "mysql-rds"})
	if err != nil {
		t.Fatalf("bind mysql: %v", err)
	}
	bindRedis, err := srv.PortMapper().Add(hub.TCPBindingSpec{TenantID: "tenant-rds", ServiceName: "redis-tls"})
	if err != nil {
		t.Fatalf("bind redis: %v", err)
	}
	bindMongo, err := srv.PortMapper().Add(hub.TCPBindingSpec{TenantID: "tenant-rds", ServiceName: "mongo-tls"})
	if err != nil {
		t.Fatalf("bind mongo: %v", err)
	}

	targetTLS := &agent.TargetTLSConfig{
		Enabled:    true,
		CAFile:     certs.CAFile,
		ServerName: "localhost",
	}

	t.Setenv("DPX_SPLIT_ERP_TOKEN", "IntranetHTTPS!Token")

	agentCfg := &agent.Config{
		TenantID: "tenant-rds",
		AgentID:  "rds-agent-01",
		Token:    "tok-rds",
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			TLS:  transport.TLSOptions{CAFile: certs.CAFile, ServerName: "localhost"},
		},
		Services: []agent.ServiceConfig{
			{
				Name:       "pg-rds",
				Protocol:   "tcp",
				TargetAddr: pgLn.Addr().String(),
				TargetTLS:  targetTLS,
				Guard: &agent.ProtocolGuardConfig{
					Type:     "postgres",
					ReadOnly: true,
					CredentialInjection: &agent.CredentialInjectionConfig{
						Enabled:  true,
						Username: "rds_pg_reader",
						Password: "RDSPGSecret!99",
					},
				},
			},
			{
				Name:       "mysql-rds",
				Protocol:   "tcp",
				TargetAddr: mysqlLn.Addr().String(),
				TargetTLS:  targetTLS,
				Guard: &agent.ProtocolGuardConfig{
					Type:     "mysql",
					ReadOnly: true,
					CredentialInjection: &agent.CredentialInjectionConfig{
						Enabled:  true,
						Username: "rds_mysql_reader",
						Password: "RDSMySQLSecret!88",
					},
				},
			},
			{
				Name:       "redis-tls",
				Protocol:   "tcp",
				TargetAddr: redisLn.Addr().String(),
				TargetTLS:  targetTLS,
				Guard: &agent.ProtocolGuardConfig{
					Type:     "redis",
					ReadOnly: true,
					CredentialInjection: &agent.CredentialInjectionConfig{
						Enabled:  true,
						Password: "RDSRedisSecret!77",
					},
				},
			},
			{
				Name:       "mongo-tls",
				Protocol:   "tcp",
				TargetAddr: mongoLn.Addr().String(),
				TargetTLS:  targetTLS,
				Guard: &agent.ProtocolGuardConfig{
					Type:     "mongodb",
					ReadOnly: true,
				},
			},
			{
				Name:               "erp-https",
				Protocol:           "http",
				TargetAddr:         httpsAddr,
				TargetTLS:          targetTLS,
				AllowedHTTPMethods: []string{"GET", "HEAD"},
				InjectHeaders: map[string]string{
					"Authorization": "Bearer env:DPX_SPLIT_ERP_TOKEN",
				},
			},
		},
	}

	// Verify RunDoctor passes ALL Split-TLS checks with real CA verification!
	docReport := agent.RunDoctor(context.Background(), agentCfg)
	if !docReport.AllPassed() {
		var buf bytes.Buffer
		docReport.Format(&buf)
		t.Fatalf("expected Split-TLS doctor report to pass all checks:\n%s", buf.String())
	}

	// Verify strict CA rejection (wrong ServerName MUST fail TLS probe!).
	badTLS := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "wrong.example.com"}
	if _, err := guard.ProbePostgresTLS(pgLn.Addr().String(), 2*time.Second, badTLS); err == nil {
		t.Fatalf("expected ProbePostgresTLS to fail with untrusted cert/wrong ServerName")
	}
	if _, err := guard.ProbeMySQLGreetingTLS(mysqlLn.Addr().String(), 2*time.Second, badTLS); err == nil {
		t.Fatalf("expected ProbeMySQLGreetingTLS to fail with untrusted cert/wrong ServerName")
	}

	cli, err := agent.NewClient(agentCfg, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli.Run(ctx) }()

	waitUntil(t, 5*time.Second, func() bool {
		return len(srv.Registry().Snapshot()) == 1
	}, "tenant-rds agent online")

	// ---- A. Verify PostgreSQL Split-TLS + Cred Injection + Read-Only ----
	t.Run("Postgres_SplitTLS", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", bindPG.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial pg binding: %v", err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))

		// Central client sends plaintext StartupMessage with dummy placeholder user (zero real creds!).
		writeTestPGStartup(t, c, "central_placeholder")
		mType, payload := readTestPGMsg(t, c)
		if mType != 'R' || len(payload) < 4 || binary.BigEndian.Uint32(payload[:4]) != 0 {
			t.Fatalf("expected PG AuthOk, got type=%q payload=%x", mType, payload)
		}
		// Read initial ReadyForQuery ('Z').
		mType, _ = readTestPGMsg(t, c)
		if mType != 'Z' {
			t.Fatalf("expected ReadyForQuery 'Z', got %q", mType)
		}

		// Allowed SELECT must reach TLS-enforced PG backend!
		writeTestPGMsg(t, c, 'Q', append([]byte("SELECT 1"), 0))
		mType, payload = readTestPGMsg(t, c)
		if mType != 'C' || !strings.Contains(string(payload), "SELECT 1") {
			t.Fatalf("expected SELECT 1 command complete, got %q %q", mType, string(payload))
		}
		readTestPGMsg(t, c) // 'Z'

		// Write DROP TABLE must be blocked locally by Agent with SQLSTATE 25006!
		writeTestPGMsg(t, c, 'Q', append([]byte("DROP TABLE orders"), 0))
		mType, payload = readTestPGMsg(t, c)
		if mType != 'E' || !bytes.Contains(payload, []byte("25006")) {
			t.Fatalf("expected PG read-only block ErrorResponse (25006), got %q %q", mType, string(payload))
		}
		readTestPGMsg(t, c) // 'Z'

		if pgTLSUsed.Load() < 1 {
			t.Fatalf("expected mock PG server to observe TLS-upgraded connection")
		}
	})

	// ---- B. Verify MySQL Split-TLS + caching_sha2_password TLS Auth + Read-Only ----
	t.Run("MySQL_SplitTLS", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", bindMySQL.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial mysql binding: %v", err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))

		// Read greeting (seq=0) forwarded by agent (CLIENT_SSL cleared on Hub leg!).
		seq, greeting := readTestMySQLPkt(t, c)
		if seq != 0 || len(greeting) < 10 || greeting[0] != 0x0a {
			t.Fatalf("unexpected mysql greeting seq=%d len=%d", seq, len(greeting))
		}
		// Central client sends plaintext HandshakeResponse41 (seq=1) with dummy user.
		writeTestMySQLPkt(t, c, 1, buildDummyMySQLHandshakeResp("placeholder_user"))
		// Agent upgrades upstream to TLS, sends HandshakeResponse41(seq=2) + cleartext password over TLS,
		// and aligns OK_Packet back to seq=2 for central client!
		seq, authResp := readTestMySQLPkt(t, c)
		if seq != 2 || len(authResp) == 0 || authResp[0] != 0x00 {
			t.Fatalf("expected aligned MySQL OK_Packet (seq=2), got seq=%d payload=%x", seq, authResp)
		}

		// Allowed SELECT reaches TLS-enforced MySQL backend!
		writeTestMySQLPkt(t, c, 0, append([]byte{0x03}, []byte("SELECT 1")...))
		_, qResp := readTestMySQLPkt(t, c)
		if len(qResp) == 0 || qResp[0] != 0x00 {
			t.Fatalf("expected OK for SELECT 1, got %x", qResp)
		}

		// Write DELETE blocked locally by Agent with ERR 1290!
		writeTestMySQLPkt(t, c, 0, append([]byte{0x03}, []byte("DELETE FROM orders")...))
		_, errResp := readTestMySQLPkt(t, c)
		if len(errResp) < 3 || errResp[0] != 0xff || binary.LittleEndian.Uint16(errResp[1:3]) != 1290 {
			t.Fatalf("expected MySQL ERR 1290 read-only block, got %x", errResp)
		}
		if mysqlTLSUsed.Load() < 1 {
			t.Fatalf("expected mock MySQL server to observe SSLRequest + TLS handshake")
		}
	})

	// ---- C. Verify Redis Direct TLS + Proactive AUTH + Read-Only ----
	t.Run("Redis_DirectTLS", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", bindRedis.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial redis binding: %v", err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)

		// Central sends GET without AUTH (Agent proactively authenticated over TLS!).
		_, _ = io.WriteString(c, "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n")
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "+tls-redis-val" {
			t.Fatalf("expected +tls-redis-val, got %q err=%v", line, err)
		}

		// Write SET blocked locally!
		_, _ = io.WriteString(c, "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")
		line, err = br.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "-ERR dataproxy-agent:") {
			t.Fatalf("expected local read-only block on Redis SET, got %q err=%v", line, err)
		}
		if redisTLSUsed.Load() < 1 {
			t.Fatalf("expected mock TLS Redis to observe connection")
		}
	})

	// ---- D. Verify MongoDB Direct TLS + OP_MSG Read-Only ----
	t.Run("MongoDB_DirectTLS", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", bindMongo.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial mongo binding: %v", err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))

		// Send read-only OP_MSG {find: "orders", $db: "shop"}.
		writeTestMongoOpMsg(t, c, 10, buildSimpleBSON("find", "orders", "shop"))
		body := readTestMongoOpMsgBody(t, c)
		if !bytes.Contains(body, []byte("mongo-tls-ok")) {
			t.Fatalf("expected mongo-tls-ok in reply, got %x", body)
		}

		// Send write OP_MSG {insert: "orders", $db: "shop"} -> blocked locally!
		writeTestMongoOpMsg(t, c, 11, buildSimpleBSON("insert", "orders", "shop"))
		body = readTestMongoOpMsgBody(t, c)
		if !bytes.Contains(body, []byte("dataproxy-agent:")) {
			t.Fatalf("expected local read-only block on Mongo insert, got %q", string(body))
		}
		if mongoTLSUsed.Load() < 1 {
			t.Fatalf("expected mock TLS MongoDB to observe connection")
		}
	})

	// ---- E. Verify Internal HTTPS Backend + Read-Only HTTP + Header Injection ----
	t.Run("Internal_HTTPS_SplitTLS", func(t *testing.T) {
		tk, err := srv.Tickets().Issue("tenant-rds", "erp-https", time.Minute, nil)
		if err != nil {
			t.Fatalf("issue ticket: %v", err)
		}
		httpCli := &http.Client{Timeout: 5 * time.Second}

		// Allowed GET -> reaches HTTPS backend with injected Bearer token!
		reqGet, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/orders", nil)
		reqGet.Header.Set(hub.HeaderTicket, tk.JWT)
		resp, err := httpCli.Do(reqGet)
		if err != nil {
			t.Fatalf("GET erp-https failed: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(b) != "https-erp-ok" {
			t.Fatalf("unexpected HTTPS backend response: status=%d body=%q", resp.StatusCode, string(b))
		}

		// Disallowed POST -> blocked locally with 403 Forbidden!
		reqPost, _ := http.NewRequest("POST", "http://"+srv.HTTPAddr()+"/orders", strings.NewReader(`{}`))
		reqPost.Header.Set(hub.HeaderTicket, tk.JWT)
		resp2, err := httpCli.Do(reqPost)
		if err != nil {
			t.Fatalf("POST erp-https failed: %v", err)
		}
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden on POST to read-only HTTPS service, got %d", resp2.StatusCode)
		}
	})
}

// ---------- Mock TLS-Enforcing Servers ----------

func serveForceSSLPostgres(ln net.Listener, tlsCfg *tls.Config, wantUser, wantPass string, tlsCount *atomic.Int32) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			// Require 8-byte SSLRequest first! Reject plaintext StartupMessage (force_ssl=1).
			var hdr [8]byte
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return
			}
			if binary.BigEndian.Uint32(hdr[0:4]) != 8 || binary.BigEndian.Uint32(hdr[4:8]) != 80877103 {
				return
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return
			}
			tc := tls.Server(conn, tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			tlsCount.Add(1)

			// Now read StartupMessage over TLS.
			var lenBuf [4]byte
			if _, err := io.ReadFull(tc, lenBuf[:]); err != nil {
				return
			}
			mLen := binary.BigEndian.Uint32(lenBuf[:])
			if mLen < 8 || mLen > 64*1024 {
				return
			}
			body := make([]byte, mLen-4)
			if _, err := io.ReadFull(tc, body); err != nil {
				return
			}
			if !bytes.Contains(body, []byte("user\x00"+wantUser+"\x00")) {
				return
			}

			// Ask for CleartextPassword ('R', 3) and verify injected password.
			_ = writeMockPGMsg(tc, 'R', []byte{0, 0, 0, 3})
			mType, passPayload, err := readMockPGMsg(tc)
			if err != nil || mType != 'p' || string(bytes.TrimRight(passPayload, "\x00")) != wantPass {
				return
			}
			_ = writeMockPGMsg(tc, 'R', []byte{0, 0, 0, 0}) // AuthOk
			_ = writeMockPGMsg(tc, 'Z', []byte{'I'})       // ReadyForQuery

			for {
				qType, _, err := readMockPGMsg(tc)
				if err != nil {
					return
				}
				if qType == 'Q' {
					_ = writeMockPGMsg(tc, 'C', append([]byte("SELECT 1"), 0))
					_ = writeMockPGMsg(tc, 'Z', []byte{'I'})
				}
			}
		}(c)
	}
}

func serveForceSSLMySQL(ln net.Listener, tlsCfg *tls.Config, wantUser, wantPass string, tlsCount *atomic.Int32) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			// Send Initial Handshake Packet (seq=0) advertising CLIENT_SSL + caching_sha2_password.
			var g bytes.Buffer
			g.WriteByte(0x0a)
			g.WriteString("8.4.13-rds-tls")
			g.WriteByte(0x00)
			g.Write([]byte{1, 0, 0, 0})         // conn id
			g.Write([]byte("12345678"))         // salt part 1
			g.WriteByte(0x00)                   // filler
			g.Write([]byte{0xff, 0xff})         // capLow (includes CLIENT_SSL=0x0800!)
			g.WriteByte(0xff)                   // charset utf8mb4
			g.Write([]byte{0x02, 0x00})         // status flags
			g.Write([]byte{0xff, 0x81})         // capHigh (includes CLIENT_PLUGIN_AUTH)
			g.WriteByte(21)                     // auth plugin data len
			g.Write(make([]byte, 10))           // reserved
			g.Write([]byte("abcdefghijkl\x00")) // salt part 2
			g.WriteString("caching_sha2_password\x00")
			if err := writeMockMySQLPkt(conn, 0, g.Bytes()); err != nil {
				return
			}

			// Enforce require_secure_transport=ON: seq=1 MUST be 32-byte SSLRequest with CLIENT_SSL!
			seq, pkt, err := readMockMySQLPkt(conn)
			if err != nil || seq != 1 || len(pkt) != 32 {
				return
			}
			caps := binary.LittleEndian.Uint32(pkt[0:4])
			if (caps & 0x0800) == 0 {
				return
			}

			tc := tls.Server(conn, tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			tlsCount.Add(1)

			// Read HandshakeResponse41 (seq=2) over TLS and verify CLIENT_SSL + injected username!
			seq, hsResp, err := readMockMySQLPkt(tc)
			if err != nil || seq != 2 || len(hsResp) < 33 {
				return
			}
			if (binary.LittleEndian.Uint32(hsResp[0:4]) & 0x0800) == 0 {
				return
			}
			if !bytes.HasPrefix(hsResp[32:], []byte(wantUser+"\x00")) {
				return
			}

			// Trigger caching_sha2_password full auth (0x01 0x04) over TLS -> expect NUL-terminated cleartext password!
			if err := writeMockMySQLPkt(tc, 3, []byte{0x01, 0x04}); err != nil {
				return
			}
			seq, pwPkt, err := readMockMySQLPkt(tc)
			if err != nil || seq != 4 || string(bytes.TrimRight(pwPkt, "\x00")) != wantPass {
				return
			}
			// Send OK_Packet at seq=5 (agent must align back to seq=2 for central client!).
			if err := writeMockMySQLPkt(tc, 5, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
				return
			}

			for {
				qSeq, qPkt, err := readMockMySQLPkt(tc)
				if err != nil {
					return
				}
				if len(qPkt) > 0 && qPkt[0] == 0x03 {
					_ = writeMockMySQLPkt(tc, qSeq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
				}
			}
		}(c)
	}
}

func serveTLSRedis(ln net.Listener, wantPass string, tlsCount *atomic.Int32) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			if tc, ok := conn.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					return
				}
			}
			tlsCount.Add(1)
			br := bufio.NewReader(conn)
			authed := false
			for {
				args, err := readMockRESP(br)
				if err != nil || len(args) == 0 {
					return
				}
				cmd := strings.ToUpper(args[0])
				switch cmd {
				case "PING":
					if !authed {
						_, _ = io.WriteString(conn, "-NOAUTH Authentication required.\r\n")
					} else {
						_, _ = io.WriteString(conn, "+PONG\r\n")
					}
				case "AUTH":
					if len(args) >= 2 && args[len(args)-1] == wantPass {
						authed = true
						_, _ = io.WriteString(conn, "+OK\r\n")
					} else {
						_, _ = io.WriteString(conn, "-WRONGPASS invalid password\r\n")
					}
				case "GET":
					if !authed {
						_, _ = io.WriteString(conn, "-NOAUTH Authentication required.\r\n")
					} else {
						_, _ = io.WriteString(conn, "+tls-redis-val\r\n")
					}
				default:
					_, _ = io.WriteString(conn, "+OK\r\n")
				}
			}
		}(c)
	}
}

func serveTLSMongo(ln net.Listener, tlsCount *atomic.Int32) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			if tc, ok := conn.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					return
				}
			}
			tlsCount.Add(1)
			for {
				var hdr [16]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				msgLen := binary.LittleEndian.Uint32(hdr[0:4])
				reqID := binary.LittleEndian.Uint32(hdr[4:8])
				if msgLen < 16 || msgLen > 1024*1024 {
					return
				}
				body := make([]byte, msgLen-16)
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				// Reply with valid OP_MSG BSON containing isWritablePrimary=true, maxWireVersion=25, note="mongo-tls-ok".
				replyDoc := buildMockMongoReplyDoc()
				var out bytes.Buffer
				var rh [16]byte
				binary.LittleEndian.PutUint32(rh[0:4], uint32(16+4+1+len(replyDoc)))
				binary.LittleEndian.PutUint32(rh[4:8], reqID+1000)
				binary.LittleEndian.PutUint32(rh[8:12], reqID)
				binary.LittleEndian.PutUint32(rh[12:16], 2013)
				out.Write(rh[:])
				out.Write([]byte{0, 0, 0, 0}) // flagBits
				out.WriteByte(0)              // section kind 0
				out.Write(replyDoc)
				if _, err := conn.Write(out.Bytes()); err != nil {
					return
				}
			}
		}(c)
	}
}

// ---------- Wire Helpers for Tests ----------

func writeMockPGMsg(w io.Writer, msgType byte, payload []byte) error {
	var h [5]byte
	h[0] = msgType
	binary.BigEndian.PutUint32(h[1:5], uint32(len(payload)+4))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMockPGMsg(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:5])
	if n < 4 || n > 1024*1024 {
		return 0, nil, fmt.Errorf("bad pg msg len %d", n)
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return h[0], buf, nil
}

func writeTestPGStartup(t *testing.T, w io.Writer, user string) {
	t.Helper()
	var body bytes.Buffer
	var proto [4]byte
	binary.BigEndian.PutUint32(proto[:], 196608)
	body.Write(proto[:])
	body.WriteString("user\x00" + user + "\x00database\x00test\x00\x00")
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(body.Len()+4))
	_, _ = w.Write(l[:])
	_, _ = w.Write(body.Bytes())
}

func writeTestPGMsg(t *testing.T, w io.Writer, msgType byte, payload []byte) {
	t.Helper()
	if err := writeMockPGMsg(w, msgType, payload); err != nil {
		t.Fatalf("write pg msg: %v", err)
	}
}

func readTestPGMsg(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	mt, p, err := readMockPGMsg(r)
	if err != nil {
		t.Fatalf("read pg msg: %v", err)
	}
	return mt, p
}

func writeMockMySQLPkt(w io.Writer, seq byte, payload []byte) error {
	var h [4]byte
	n := len(payload)
	h[0], h[1], h[2], h[3] = byte(n), byte(n>>8), byte(n>>16), seq
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMockMySQLPkt(r io.Reader) (byte, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return h[3], buf, nil
}

func writeTestMySQLPkt(t *testing.T, w io.Writer, seq byte, payload []byte) {
	t.Helper()
	if err := writeMockMySQLPkt(w, seq, payload); err != nil {
		t.Fatalf("write mysql pkt: %v", err)
	}
}

func readTestMySQLPkt(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	seq, p, err := readMockMySQLPkt(r)
	if err != nil {
		t.Fatalf("read mysql pkt: %v", err)
	}
	return seq, p
}

func buildDummyMySQLHandshakeResp(user string) []byte {
	var b bytes.Buffer
	var caps [4]byte
	binary.LittleEndian.PutUint32(caps[:], 0x00088201) // Protocol41 | LongPassword | SecureConn | PluginAuth
	b.Write(caps[:])
	b.Write([]byte{0, 0, 0, 1}) // maxPacket
	b.WriteByte(0xff)           // utf8mb4
	b.Write(make([]byte, 23))   // reserved
	b.WriteString(user)
	b.WriteByte(0x00)
	b.WriteByte(0x00) // empty auth resp
	b.WriteString("caching_sha2_password\x00")
	return b.Bytes()
}

func readMockRESP(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil
	}
	var count int
	_, _ = fmt.Sscanf(line[1:], "%d", &count)
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if _, err := br.ReadString('\n'); err != nil {
			return nil, err
		}
		val, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args = append(args, strings.TrimRight(val, "\r\n"))
	}
	return args, nil
}

func buildSimpleBSON(cmd, val, db string) []byte {
	var body bytes.Buffer
	appendBSONStr := func(k, v string) {
		body.WriteByte(0x02)
		body.WriteString(k)
		body.WriteByte(0x00)
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(v)+1))
		body.Write(l[:])
		body.WriteString(v)
		body.WriteByte(0x00)
	}
	appendBSONStr(cmd, val)
	appendBSONStr("$db", db)
	body.WriteByte(0x00)
	var total [4]byte
	binary.LittleEndian.PutUint32(total[:], uint32(body.Len()+4))
	return append(total[:], body.Bytes()...)
}

func buildMockMongoReplyDoc() []byte {
	var body bytes.Buffer
	// isWritablePrimary: true (0x08)
	body.WriteByte(0x08)
	body.WriteString("isWritablePrimary\x00")
	body.WriteByte(1)
	// maxWireVersion: 25 (0x10)
	body.WriteByte(0x10)
	body.WriteString("maxWireVersion\x00")
	var wv [4]byte
	binary.LittleEndian.PutUint32(wv[:], 25)
	body.Write(wv[:])
	// note: "mongo-tls-ok" (0x02)
	body.WriteByte(0x02)
	body.WriteString("note\x00")
	var sl [4]byte
	binary.LittleEndian.PutUint32(sl[:], uint32(len("mongo-tls-ok")+1))
	body.Write(sl[:])
	body.WriteString("mongo-tls-ok\x00")
	// ok: 1 (0x10)
	body.WriteByte(0x10)
	body.WriteString("ok\x00")
	body.Write([]byte{1, 0, 0, 0})
	body.WriteByte(0x00)
	var total [4]byte
	binary.LittleEndian.PutUint32(total[:], uint32(body.Len()+4))
	return append(total[:], body.Bytes()...)
}

func writeTestMongoOpMsg(t *testing.T, w io.Writer, reqID uint32, doc []byte) {
	t.Helper()
	var buf bytes.Buffer
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:4], uint32(16+4+1+len(doc)))
	binary.LittleEndian.PutUint32(h[4:8], reqID)
	binary.LittleEndian.PutUint32(h[12:16], 2013)
	buf.Write(h[:])
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteByte(0)
	buf.Write(doc)
	if _, err := w.Write(buf.Bytes()); err != nil {
		t.Fatalf("write mongo op_msg: %v", err)
	}
}

func readTestMongoOpMsgBody(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var h [16]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatalf("read mongo header: %v", err)
	}
	msgLen := binary.LittleEndian.Uint32(h[0:4])
	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read mongo body: %v", err)
	}
	return body
}
