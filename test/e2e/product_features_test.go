package e2e

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// startAuthMySQLServer runs a spec-compliant MySQL v10 server that:
// 1. Sends a full Initial Handshake Packet (with 20-byte salt, CLIENT_SSL, mysql_native_password).
// 2. Cryptographically validates username + mysql_native_password SHA1 scramble.
// 3. Records every received COM_QUERY so tests can assert zero mutating queries reached MySQL.
func startAuthMySQLServer(t *testing.T, serverTag, expectUser, expectPass string) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen auth mysql: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var receivedQueries []string
	salt := []byte("1234567890abcdefghij") // 20 bytes deterministic salt for test

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				// Build full MySQL v10 Initial Handshake Packet
				var hs bytes.Buffer
				hs.WriteByte(0x0a)
				hs.WriteString("8.0.36-" + serverTag)
				hs.WriteByte(0x00)
				hs.Write([]byte{0x01, 0x00, 0x00, 0x00}) // conn id
				hs.Write(salt[:8])                       // auth plugin data part 1 (8B)
				hs.WriteByte(0x00)                       // filler
				// capLow: LONG_PASSWORD | PROTOCOL_41 | SSL (0x0800) | SECURE_CONNECTION (0x8000)
				binary.Write(&hs, binary.LittleEndian, uint16(0x8a01))
				hs.WriteByte(0x21) // utf8_general_ci
				binary.Write(&hs, binary.LittleEndian, uint16(0x0002))
				// capHigh: PLUGIN_AUTH (0x0008 -> 0x00080000)
				binary.Write(&hs, binary.LittleEndian, uint16(0x0008))
				hs.WriteByte(21)             // auth_plugin_data_len
				hs.Write(make([]byte, 10))   // reserved
				hs.Write(salt[8:20])         // auth plugin data part 2 (12B)
				hs.WriteByte(0x00)           // terminator for part 2
				hs.WriteString("mysql_native_password")
				hs.WriteByte(0x00)

				if err := writeMySQLPacket(c, 0, hs.Bytes()); err != nil {
					return
				}

				// Read HandshakeResponse41 (seq=1)
				seq, resp, err := readMySQLPacket(c)
				if err != nil || len(resp) < 33 {
					return
				}
				userEnd := bytes.IndexByte(resp[32:], 0x00)
				if userEnd < 0 {
					return
				}
				gotUser := string(resp[32 : 32+userEnd])
				pos := 32 + userEnd + 1
				if pos >= len(resp) {
					return
				}
				authLen := int(resp[pos])
				pos++
				if pos+authLen > len(resp) {
					return
				}
				gotAuth := resp[pos : pos+authLen]

				// Compute expected mysql_native_password scramble
				wantAuth := mysqlNativeScramble(expectPass, salt)
				if gotUser != expectUser || !bytes.Equal(gotAuth, wantAuth) {
					// Send ERR 1045 Access Denied
					errPkt := append([]byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}, []byte("Access denied for user "+gotUser)...)
					_ = writeMySQLPacket(c, seq+1, errPkt)
					return
				}

				// Send OK_Packet (0x00)
				_ = writeMySQLPacket(c, seq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})

				// Command phase
				for {
					cSeq, payload, err := readMySQLPacket(c)
					if err != nil || len(payload) == 0 {
						return
					}
					switch payload[0] {
					case 0x01: // COM_QUIT
						return
					case 0x03: // COM_QUERY
						q := string(payload[1:])
						mu.Lock()
						receivedQueries = append(receivedQueries, q)
						mu.Unlock()
						reply := append([]byte("RESULT:"), []byte(q)...)
						if err := writeMySQLPacket(c, cSeq+1, reply); err != nil {
							return
						}
					default:
						_ = writeMySQLPacket(c, cSeq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
					}
				}
			}(conn)
		}
	}()

	getQueries := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), receivedQueries...)
	}
	return ln.Addr().String(), getQueries
}

func mysqlNativeScramble(password string, salt []byte) []byte {
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	sc := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s1[i] ^ sc[i]
	}
	return out
}

func buildPlaceholderHandshake41(user, pass string) []byte {
	var b bytes.Buffer
	// cap: LONG_PASSWORD | PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH
	binary.Write(&b, binary.LittleEndian, uint32(0x00088201))
	binary.Write(&b, binary.LittleEndian, uint32(16*1024*1024))
	b.WriteByte(0x21)
	b.Write(make([]byte, 23))
	b.WriteString(user)
	b.WriteByte(0x00)
	b.WriteByte(byte(len(pass)))
	b.WriteString(pass)
	b.WriteString("mysql_native_password")
	b.WriteByte(0x00)
	return b.Bytes()
}

func TestProductFeatures_CredInjection_ReadOnly_Bandwidth_Doctor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	// Store real tenant DB credentials strictly in local env + local Vault/Secret file!
	const realDBUser = "tenant_real_reader"
	const realDBPass = "VaultSecretPass!2026"
	t.Setenv("DPX_E2E_MYSQL_USER", realDBUser)
	passFile := filepath.Join(t.TempDir(), "vault_mysql_pass")
	if err := os.WriteFile(passFile, []byte(realDBPass+"\n"), 0600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	// Start tenant internal services.
	mysqlAddr, getReceivedSQL := startAuthMySQLServer(t, "PROD-GUARD", realDBUser, realDBPass)

	var httpMu sync.Mutex
	var receivedHTTPMethods []string
	erpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpMu.Lock()
		receivedHTTPMethods = append(receivedHTTPMethods, r.Method)
		httpMu.Unlock()
		if r.URL.Path == "/big" {
			// Return 160KB payload for bandwidth shaping test
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("A"), 160_000))
			return
		}
		_, _ = fmt.Fprintf(w, "ok:%s:%s", r.Method, r.URL.Path)
	}))
	defer erpSrv.Close()
	erpAddr := strings.TrimPrefix(erpSrv.URL, "http://")

	// Start Central Hub.
	hubCfg := &hub.Config{
		TunnelWSSAddr:       "127.0.0.1:0",
		TunnelWSSPath:       "/tunnel/v1/connect",
		HTTPAddr:            "127.0.0.1:0",
		VirtualDomainSuffix: "dataproxy.internal",
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-fin", TokenHash: "token-fin"},
		},
		Callers: []auth.CallerPolicy{
			{CallerID: "saas-bi", Secret: "bi-secret", AllowedTenants: []string{"tenant-fin"}},
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

	mysqlBind, err := srv.PortMapper().Add(hub.TCPBindingSpec{
		ID:          "fin-mysql",
		ListenAddr:  "127.0.0.1:0",
		TenantID:    "tenant-fin",
		ServiceName: "mysql-prod",
	})
	if err != nil {
		t.Fatalf("add tcp binding: %v", err)
	}

	// Configure Agent with ALL 4 product features enabled!
	agentCfg := &agent.Config{
		TenantID:     "tenant-fin",
		AgentID:      "fin-node-01",
		Token:        "token-fin",
		MaxBandwidth: "500KB/s", // Global cap
		Server: agent.ServerConfig{
			Mode: "wss",
			URL:  "wss://" + srv.WSSAddr() + "/tunnel/v1/connect",
			TLS: transport.TLSOptions{
				CAFile:     certs.CAFile,
				ServerName: "localhost",
			},
		},
		Services: []agent.ServiceConfig{
			{
				Name:         "mysql-prod",
				Protocol:     "tcp",
				TargetAddr:   mysqlAddr,
				MaxConns:     10,
				MaxBandwidth: "500KB/s",
				MySQL: &agent.MySQLServiceConfig{
					ReadOnly: true,
					CredentialInjection: &agent.MySQLCredentialInjection{
						Enabled:  true,
						Username: "env:DPX_E2E_MYSQL_USER",
						Password: "file:" + passFile,
					},
				},
			},
			{
				Name:               "erp-readonly",
				Protocol:           "http",
				TargetAddr:         erpAddr,
				MaxConns:           10,
				MaxBandwidth:       "200KB/s", // Tight per-service cap for bandwidth shaping verification
				AllowedHTTPMethods: []string{"GET", "HEAD"},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli, err := agent.NewClient(agentCfg, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	go func() { _ = cli.Run(ctx) }()
	select {
	case <-cli.Ready():
	case <-time.After(5 * time.Second):
		t.Fatalf("agent failed to register")
	}

	// Feature 1 & 2: MySQL Credential Injection (credentials never leave tenant) + Read-Only SQL Guard.
	t.Run("MySQL_CredentialInjection_And_ReadOnlyGuard", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", mysqlBind.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial mysql binding: %v", err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// 1. Receive Initial Handshake Packet and verify CLIENT_SSL bit (0x0800) was stripped by guard.
		seq, greeting, err := readMySQLPacket(conn)
		if err != nil || seq != 0 || !bytes.Contains(greeting, []byte("PROD-GUARD")) {
			t.Fatalf("unexpected greeting: err=%v seq=%d data=%q", err, seq, greeting)
		}

		// 2. Central client sends DUMMY placeholder user/password (never knows real DB password!).
		dummyHS := buildPlaceholderHandshake41("central_dummy_user", "completely_wrong_password")
		if err := writeMySQLPacket(conn, 1, dummyHS); err != nil {
			t.Fatalf("write handshake response: %v", err)
		}
		_, authRes, err := readMySQLPacket(conn)
		if err != nil {
			t.Fatalf("read auth result: %v", err)
		}
		if len(authRes) == 0 || authRes[0] != 0x00 {
			t.Fatalf("expected OK_Packet (0x00) after local credential injection, got 0x%x (%q)", authRes[0], string(authRes))
		}

		// 3. Allowed SELECT succeeds.
		if err := writeMySQLPacket(conn, 0, append([]byte{0x03}, []byte("SELECT id FROM orders LIMIT 5")...)); err != nil {
			t.Fatalf("write SELECT: %v", err)
		}
		_, selResp, err := readMySQLPacket(conn)
		if err != nil || string(selResp) != "RESULT:SELECT id FROM orders LIMIT 5" {
			t.Fatalf("SELECT failed: err=%v resp=%q", err, string(selResp))
		}

		// 4. Dangerous write / injection queries MUST be blocked locally with MySQL ERR 1290!
		blockedQueries := []string{
			"DELETE FROM orders WHERE id = 1",
			"DROP TABLE users",
			"SELECT 1; DROP TABLE users",
			"SELECT * FROM orders INTO OUTFILE '/tmp/leak.csv'",
			"/*!50000 UPDATE orders SET total=0 */",
		}
		for _, badSQL := range blockedQueries {
			if err := writeMySQLPacket(conn, 0, append([]byte{0x03}, []byte(badSQL)...)); err != nil {
				t.Fatalf("write blocked SQL %q: %v", badSQL, err)
			}
			_, errResp, err := readMySQLPacket(conn)
			if err != nil {
				t.Fatalf("read ERR packet for %q: %v", badSQL, err)
			}
			if len(errResp) < 9 || errResp[0] != 0xff {
				t.Fatalf("expected MySQL ERR_Packet (0xff) for %q, got %x", badSQL, errResp)
			}
			errCode := binary.LittleEndian.Uint16(errResp[1:3])
			if errCode != 1290 {
				t.Fatalf("expected MySQL error code 1290 for %q, got %d", badSQL, errCode)
			}
		}

		// 5. Connection must remain healthy for subsequent SHOW TABLES!
		if err := writeMySQLPacket(conn, 0, append([]byte{0x03}, []byte("SHOW TABLES")...)); err != nil {
			t.Fatalf("write SHOW TABLES: %v", err)
		}
		_, showResp, err := readMySQLPacket(conn)
		if err != nil || string(showResp) != "RESULT:SHOW TABLES" {
			t.Fatalf("SHOW TABLES after blocked write failed: err=%v resp=%q", err, string(showResp))
		}

		// 6. Prove ZERO mutating queries ever reached the tenant MySQL backend!
		got := getReceivedSQL()
		if len(got) != 2 || got[0] != "SELECT id FROM orders LIMIT 5" || got[1] != "SHOW TABLES" {
			t.Fatalf("backend MySQL should have received ONLY 2 read queries, got: %#v", got)
		}
		mysqlBlocked, _ := cli.Whitelist().BlockedProtocolOps()
		if mysqlBlocked != int64(len(blockedQueries)) {
			t.Fatalf("expected %d blocked mysql queries, got %d", len(blockedQueries), mysqlBlocked)
		}
	})

	// Feature 3: HTTP Method Read-Only Guard.
	t.Run("HTTP_Method_ReadOnlyGuard", func(t *testing.T) {
		httpCli := &http.Client{Timeout: 5 * time.Second}

		// GET allowed -> 200 OK
		reqGet, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/v1/orders", nil)
		reqGet.Host = "erp-readonly.tenant-fin.dataproxy.internal"
		reqGet.Header.Set(hub.HeaderAuth, "Bearer saas-bi:bi-secret")
		respGet, err := httpCli.Do(reqGet)
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		bodyGet, _ := io.ReadAll(respGet.Body)
		_ = respGet.Body.Close()
		if respGet.StatusCode != http.StatusOK || string(bodyGet) != "ok:GET:/v1/orders" {
			t.Fatalf("unexpected GET response: status=%d body=%q", respGet.StatusCode, string(bodyGet))
		}

		// POST & DELETE blocked locally in tenant Agent -> 403 Forbidden
		for _, method := range []string{"POST", "DELETE"} {
			reqMut, _ := http.NewRequest(method, "http://"+srv.HTTPAddr()+"/v1/orders", strings.NewReader(`{"amount":0}`))
			reqMut.Host = "erp-readonly.tenant-fin.dataproxy.internal"
			reqMut.Header.Set(hub.HeaderAuth, "Bearer saas-bi:bi-secret")
			respMut, err := httpCli.Do(reqMut)
			if err != nil {
				t.Fatalf("%s request error: %v", method, err)
			}
			bodyMut, _ := io.ReadAll(respMut.Body)
			_ = respMut.Body.Close()
			if respMut.StatusCode != http.StatusForbidden || !strings.Contains(string(bodyMut), "blocked by tenant read-only policy") {
				t.Fatalf("expected 403 read-only block for %s, got status=%d body=%q", method, respMut.StatusCode, string(bodyMut))
			}
		}

		// Verify backend ERP never received POST or DELETE!
		httpMu.Lock()
		for _, m := range receivedHTTPMethods {
			if m == "POST" || m == "DELETE" {
				t.Fatalf("backend ERP received forbidden HTTP method %q!", m)
			}
		}
		httpMu.Unlock()
	})

	// Feature 4: Bandwidth Shaping Verification (160KB through 200KB/s limiter).
	t.Run("Bandwidth_Shaping_Enforcement", func(t *testing.T) {
		httpCli := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/big", nil)
		req.Host = "erp-readonly.tenant-fin.dataproxy.internal"
		req.Header.Set(hub.HeaderAuth, "Bearer saas-bi:bi-secret")

		start := time.Now()
		resp, err := httpCli.Do(req)
		if err != nil {
			t.Fatalf("GET /big failed: %v", err)
		}
		payload, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		elapsed := time.Since(start)

		if err != nil || len(payload) != 160_000 {
			t.Fatalf("unexpected /big payload: err=%v len=%d", err, len(payload))
		}
		// 200KB/s with 50KB burst -> 160KB requires at least (160-50)/200 = 0.55s; allow small jitter margin >= 350ms.
		if elapsed < 350*time.Millisecond {
			t.Fatalf("expected bandwidth shaping delay >= 350ms for 160KB @ 200KB/s, got %v", elapsed)
		}
	})

	// Feature 5: dataproxy-agent doctor Full-Chain Diagnostics.
	t.Run("Doctor_Preflight_Diagnostics", func(t *testing.T) {
		report := agent.RunDoctor(context.Background(), agentCfg)
		var out bytes.Buffer
		report.Format(&out)
		text := out.String()

		if !report.AllPassed() {
			t.Fatalf("expected doctor all passed, got:\n%s", text)
		}
		for _, expected := range []string{
			"MySQL v10 首包识别成功",
			"8.0.36-PROD-GUARD",
			"本地只读拦截=开启",
			"本地凭据代填=开启",
			"成功接入",
			"HTTP 目标存活",
		} {
			if !strings.Contains(text, expected) {
				t.Fatalf("doctor report missing %q:\n%s", expected, text)
			}
		}

		// Verify TLS untrusted CA diagnostic produces actionable Chinese MITM proxy advice.
		badCfg := *agentCfg
		badCfg.Server.TLS.CAFile = "" // omit custom test CA -> triggers x509 unknown authority
		badReport := agent.RunDoctor(context.Background(), &badCfg)
		var badOut bytes.Buffer
		badReport.Format(&badOut)
		if badReport.AllPassed() || !strings.Contains(badOut.String(), "HTTPS 中间人解密代理") {
			t.Fatalf("expected TLS MITM remediation advice on untrusted CA, got:\n%s", badOut.String())
		}
	})
}
