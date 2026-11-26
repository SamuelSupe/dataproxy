package guard

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMSSQL_IsReadOnlyTSQL(t *testing.T) {
	allowed := []string{
		"SELECT TOP 10 id, name FROM dbo.orders WHERE status = 'PAID'",
		"WITH cte AS (SELECT id FROM dbo.orders) SELECT * FROM cte",
		"SET NOCOUNT ON",
		"SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED",
		"USE erp_prod",
	}
	for _, q := range allowed {
		if ok, reason := IsReadOnlyTSQL(q); !ok {
			t.Errorf("expected T-SQL allowed: %q, got blocked: %s", q, reason)
		}
	}

	blocked := []string{
		"INSERT INTO dbo.orders VALUES (1)",
		"UPDATE dbo.orders SET status = 'X'",
		"DELETE FROM dbo.orders",
		"DROP TABLE dbo.orders",
		"SELECT * INTO dbo.backup_orders FROM dbo.orders",
		"SELECT * FROM dbo.orders WITH (UPDLOCK)",
		"EXEC xp_cmdshell 'whoami'",
		"SELECT 1; DELETE FROM dbo.orders",
	}
	for _, q := range blocked {
		if ok, _ := IsReadOnlyTSQL(q); ok {
			t.Errorf("expected T-SQL blocked: %q", q)
		}
	}
}

func TestMSSQLProxy_TDS_Login7Inject_SQLBatch_RPC_And_Probe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var mu sync.Mutex
	var gotUser, gotPass string
	var gotBatches []string

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				for {
					pType, payload, _, err := readTDSMessage(conn)
					if err != nil {
						return
					}
					switch pType {
					case tdsPacketPreLogin:
						resp := buildTDSPreLogin(tdsEncryptNotSup)
						// Put version 16.0.4100 in PRELOGIN response
						resp[11] = 16
						resp[12] = 0
						binary.BigEndian.PutUint16(resp[13:15], 4100)
						_ = writeTDSPackets(conn, tdsPacketTabularResult, resp)
					case tdsPacketLogin7:
						uOff := int(binary.LittleEndian.Uint16(payload[40:42]))
						uLen := int(binary.LittleEndian.Uint16(payload[42:44])) * 2
						pOff := int(binary.LittleEndian.Uint16(payload[44:46]))
						pLen := int(binary.LittleEndian.Uint16(payload[46:48])) * 2
						mu.Lock()
						gotUser = decodeUTF16LE(payload[uOff : uOff+uLen])
						encPass := payload[pOff : pOff+pLen]
						decPass := make([]byte, len(encPass))
						for i, b := range encPass {
							x := b ^ 0xA5
							decPass[i] = (x << 4) | (x >> 4)
						}
						gotPass = decodeUTF16LE(decPass)
						mu.Unlock()
						_ = writeTDSPackets(conn, tdsPacketTabularResult, []byte{0xAD, 0x00, 0x00})
					case tdsPacketSQLBatch:
						mu.Lock()
						gotBatches = append(gotBatches, extractTDSSQLBatchText(payload))
						mu.Unlock()
						_ = writeTDSPackets(conn, tdsPacketTabularResult, []byte{0xFD, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0})
					case tdsPacketRPCRequest:
						mu.Lock()
						gotBatches = append(gotBatches, "RPC_OK")
						mu.Unlock()
						_ = writeTDSPackets(conn, tdsPacketTabularResult, []byte{0xFD, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0})
					}
				}
			}(c)
		}
	}()

	// 1. Test ProbeMSSQL
	info, err := ProbeMSSQL(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeMSSQL failed: %v", err)
	}
	if info.ServerVersion != "16.0.4100" {
		t.Fatalf("expected MSSQL version 16.0.4100, got %q", info.ServerVersion)
	}

	// 2. Test MSSQLProxy with LOGIN7 injection + SQL_BATCH + RPC + BULK_LOAD
	srvConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cliEnd, proxyCli := net.Pipe()
	defer func() {
		_ = cliEnd.Close()
		_ = proxyCli.Close()
		_ = srvConn.Close()
	}()

	proxy := NewMSSQLProxy(MSSQLGuardConfig{
		ReadOnly:     true,
		InjectCreds:  true,
		UsernameSpec: "literal:real_mssql_reader",
		PasswordSpec: "literal:MssqlSecret!23",
	})
	var blockedActions []string
	var blockMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = proxy.Proxy(proxyCli, srvConn, func(action, _ string) {
			blockMu.Lock()
			blockedActions = append(blockedActions, action)
			blockMu.Unlock()
		})
	}()

	// Send PRELOGIN
	if err := writeTDSPackets(cliEnd, tdsPacketPreLogin, buildTDSPreLogin(tdsEncryptOff)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readTDSMessage(cliEnd); err != nil {
		t.Fatal(err)
	}

	// Send dummy LOGIN7 (86 bytes minimal header)
	login7 := make([]byte, 94)
	binary.LittleEndian.PutUint32(login7[0:4], uint32(len(login7)))
	if err := writeTDSPackets(cliEnd, tdsPacketLogin7, login7); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readTDSMessage(cliEnd); err != nil {
		t.Fatal(err)
	}

	// Send allowed SQL_BATCH
	if err := writeTDSPackets(cliEnd, tdsPacketSQLBatch, encodeUTF16LE("SELECT TOP 5 * FROM orders")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readTDSMessage(cliEnd); err != nil {
		t.Fatal(err)
	}

	// Send blocked SQL_BATCH -> should return TDS ERROR token (0xAA) locally!
	if err := writeTDSPackets(cliEnd, tdsPacketSQLBatch, encodeUTF16LE("DELETE FROM orders")); err != nil {
		t.Fatal(err)
	}
	rType, rPayload, _, err := readTDSMessage(cliEnd)
	if err != nil || rType != tdsPacketTabularResult || len(rPayload) == 0 || rPayload[0] != 0xAA {
		t.Fatalf("expected TDS ERROR token 0xAA for blocked DELETE, got type=0x%02x payload=%x err=%v", rType, rPayload, err)
	}

	// Send allowed RPC sp_executesql with SELECT
	if err := writeTDSPackets(cliEnd, tdsPacketRPCRequest, buildTestTDSRPC(10, "SELECT 42")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readTDSMessage(cliEnd); err != nil {
		t.Fatal(err)
	}

	// Send blocked RPC sp_executesql with DROP TABLE
	if err := writeTDSPackets(cliEnd, tdsPacketRPCRequest, buildTestTDSRPC(10, "DROP TABLE orders")); err != nil {
		t.Fatal(err)
	}
	_, rPayload, _, err = readTDSMessage(cliEnd)
	if err != nil || len(rPayload) == 0 || rPayload[0] != 0xAA {
		t.Fatalf("expected TDS ERROR token 0xAA for blocked sp_executesql DROP, got %x err=%v", rPayload, err)
	}

	// Send blocked BULK_LOAD
	if err := writeTDSPackets(cliEnd, tdsPacketBulkLoad, []byte{0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	_, rPayload, _, err = readTDSMessage(cliEnd)
	if err != nil || len(rPayload) == 0 || rPayload[0] != 0xAA {
		t.Fatalf("expected TDS ERROR token 0xAA for blocked BULK_LOAD, got %x err=%v", rPayload, err)
	}

	_ = cliEnd.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if gotUser != "real_mssql_reader" || gotPass != "MssqlSecret!23" {
		t.Fatalf("LOGIN7 credential injection mismatch: user=%q pass=%q", gotUser, gotPass)
	}
	if len(gotBatches) != 2 {
		t.Fatalf("expected exactly 2 allowed queries forwarded to MSSQL, got %v", gotBatches)
	}
	if proxy.BlockedQueries() != 3 {
		t.Fatalf("expected 3 blocked MSSQL ops, got %d", proxy.BlockedQueries())
	}
}

func buildTestTDSRPC(procID uint16, sqlText string) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint16(0xFFFF))
	_ = binary.Write(&b, binary.LittleEndian, procID)
	_ = binary.Write(&b, binary.LittleEndian, uint16(0)) // option flags
	// First param: unnamed NVARCHAR containing sqlText
	b.WriteByte(0)    // name len = 0
	b.WriteByte(0)    // status flags
	b.WriteByte(0xE7) // NVARCHAR
	u16 := encodeUTF16LE(sqlText)
	_ = binary.Write(&b, binary.LittleEndian, uint16(4000)) // maxLen
	b.Write([]byte{0x09, 0x04, 0xD0, 0x00, 0x34})           // collation (5B)
	_ = binary.Write(&b, binary.LittleEndian, uint16(len(u16)))
	b.Write(u16)
	return b.Bytes()
}

func TestOracle_IsReadOnlyOracleSQL_And_Proxy(t *testing.T) {
	if ok, reason := IsReadOnlyOracleSQL("SELECT * FROM hr.employees WHERE rownum <= 10"); !ok {
		t.Fatalf("expected Oracle SELECT allowed, got: %s", reason)
	}
	for _, bad := range []string{
		"DELETE FROM hr.employees",
		"BEGIN UPDATE hr.employees SET sal=0; END;",
		"SELECT UTL_HTTP.REQUEST('http://evil') FROM dual",
		"SELECT * FROM hr.employees FOR UPDATE",
	} {
		if ok, _ := IsReadOnlyOracleSQL(bad); ok {
			t.Errorf("expected Oracle SQL blocked: %q", bad)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var mu sync.Mutex
	var forwarded []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				for {
					pType, payload, _, err := readTNSPacket(conn, false)
					if err != nil {
						return
					}
					if pType == tnsTypeConnect {
						// Reply with TNS ACCEPT v314
						acc := make([]byte, 16)
						binary.BigEndian.PutUint16(acc[0:2], 16)
						acc[4] = tnsTypeAccept
						binary.BigEndian.PutUint16(acc[8:10], 314)
						_, _ = conn.Write(acc)
					} else if pType == tnsTypeData {
						if stmt, ok := extractOracleTTCStatement(payload); ok {
							mu.Lock()
							forwarded = append(forwarded, stmt)
							mu.Unlock()
						}
						// Reply with simple TNS DATA OK
						ack := make([]byte, 12)
						binary.BigEndian.PutUint16(ack[0:2], 12)
						ack[4] = tnsTypeData
						_, _ = conn.Write(ack)
					}
				}
			}(c)
		}
	}()

	info, err := ProbeOracle(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeOracle failed: %v", err)
	}
	if info.TNSVersion != 314 || info.ReplyType != tnsTypeAccept {
		t.Fatalf("unexpected Oracle probe info: %+v", info)
	}

	srvConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cliEnd, proxyCli := net.Pipe()
	defer func() {
		_ = cliEnd.Close()
		_ = proxyCli.Close()
		_ = srvConn.Close()
	}()

	proxy := NewOracleProxy(OracleGuardConfig{ReadOnly: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = proxy.Proxy(proxyCli, srvConn, nil)
	}()

	// Send allowed SELECT over TNS DATA + TTC 0x03 0x5E
	makeTNSData := func(sql string) []byte {
		payload := append([]byte{0x00, 0x00, 0x03, 0x5E, 0x01}, []byte(sql)...)
		pkt := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(pkt[0:2], uint16(len(pkt)))
		pkt[4] = tnsTypeData
		copy(pkt[8:], payload)
		return pkt
	}

	_, _ = cliEnd.Write(makeTNSData("SELECT * FROM hr.employees"))
	if _, _, _, err := readTNSPacket(cliEnd, false); err != nil {
		t.Fatal(err)
	}

	// Send blocked DELETE -> should return ORA-01031 locally!
	_, _ = cliEnd.Write(makeTNSData("DELETE FROM hr.employees"))
	pType, errPayload, _, err := readTNSPacket(cliEnd, false)
	if err != nil || pType != tnsTypeData || !bytes.Contains(errPayload, []byte("ORA-01031")) {
		t.Fatalf("expected ORA-01031 in TNS DATA error reply, got type=%d payload=%q err=%v", pType, string(errPayload), err)
	}

	_ = cliEnd.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(forwarded) != 1 || forwarded[0] != "SELECT * FROM hr.employees" {
		t.Fatalf("expected only SELECT forwarded to Oracle, got %v", forwarded)
	}
	if proxy.BlockedQueries() != 1 {
		t.Fatalf("expected 1 blocked Oracle query, got %d", proxy.BlockedQueries())
	}
}

func TestClickHouse_HTTP_And_NativeTCP_Guard_And_Probe(t *testing.T) {
	// 1. SQL policy checks
	if ok, why := IsReadOnlyClickHouseSQL("SELECT count() FROM system.tables"); !ok {
		t.Fatalf("expected CH SELECT allowed, got %s", why)
	}
	for _, bad := range []string{
		"INSERT INTO events VALUES (1)",
		"ALTER TABLE events DELETE WHERE id = 1",
		"SYSTEM RELOAD DICTIONARIES",
		"SELECT * FROM url('http://169.254.169.254/latest/meta-data')",
		"SELECT * FROM file('/etc/passwd')",
	} {
		if ok, _ := IsReadOnlyClickHouseSQL(bad); ok {
			t.Errorf("expected ClickHouse SQL blocked: %q", bad)
		}
	}

	// 2. ClickHouse HTTP Interface test (8123)
	var gotUser, gotKey, gotReadOnly string
	var gotQueries []string
	var mu sync.Mutex
	chHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			_, _ = io.WriteString(w, "Ok.\n")
			return
		}
		mu.Lock()
		gotUser = r.Header.Get("X-ClickHouse-User")
		gotKey = r.Header.Get("X-ClickHouse-Key")
		gotReadOnly = r.URL.Query().Get("readonly")
		body, _ := io.ReadAll(r.Body)
		gotQueries = append(gotQueries, r.URL.Query().Get("query")+string(body))
		mu.Unlock()
		_, _ = io.WriteString(w, "42\n")
	}))
	defer chHTTP.Close()

	httpAddr := strings.TrimPrefix(chHTTP.URL, "http://")
	probeInfo, err := ProbeClickHouse(httpAddr, 2*time.Second)
	if err != nil || probeInfo.Interface != "http" {
		t.Fatalf("ProbeClickHouse HTTP failed: info=%+v err=%v", probeInfo, err)
	}

	srvConn, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	cliEnd, proxyCli := net.Pipe()
	proxy := NewClickHouseProxy(ClickHouseGuardConfig{
		ReadOnly:     true,
		InjectCreds:  true,
		UsernameSpec: "literal:ck_reader",
		PasswordSpec: "literal:ck_secret",
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = proxy.Proxy(proxyCli, srvConn, nil)
	}()

	cliBR := bufio.NewReader(cliEnd)
	// Allowed GET query
	_, _ = io.WriteString(cliEnd, "GET /?query=SELECT+1&user=fake&password=bad HTTP/1.1\r\nHost: ck\r\nAuthorization: Basic ZmFrZQ==\r\n\r\n")
	resp, err := http.ReadResponse(cliBR, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("expected 200 for allowed CH GET query, got resp=%v err=%v", resp, err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Blocked POST INSERT
	insertBody := "INSERT INTO events VALUES (1)"
	_, _ = io.WriteString(cliEnd, "POST / HTTP/1.1\r\nHost: ck\r\nContent-Length: 29\r\nConnection: close\r\n\r\n"+insertBody)
	resp2, err := http.ReadResponse(cliBR, nil)
	if err != nil || resp2.StatusCode != 403 {
		t.Fatalf("expected 403 for blocked CH POST INSERT, got resp=%v err=%v", resp2, err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if !strings.Contains(string(b2), "Code: 497") {
		t.Fatalf("expected ClickHouse Code: 497 error body, got %q", string(b2))
	}
	_ = cliEnd.Close()
	<-done

	mu.Lock()
	if gotUser != "ck_reader" || gotKey != "ck_secret" || gotReadOnly != "1" {
		t.Fatalf("CH HTTP injection/readonly mismatch: user=%q key=%q readonly=%q", gotUser, gotKey, gotReadOnly)
	}
	if len(gotQueries) != 1 {
		t.Fatalf("expected only 1 allowed CH HTTP query forwarded, got %v", gotQueries)
	}
	mu.Unlock()

	// 3. ClickHouse Native TCP Interface test (9000)
	nativeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nativeLn.Close() }()

	var nativeUser, nativePass string
	var nativeQueries []string
	go func() {
		for {
			c, err := nativeLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				pType, err := readUvarint(br)
				if err != nil || pType != chClientHello {
					return
				}
				_, _ = readCHString(br) // name
				_, _ = readUvarint(br)  // maj
				_, _ = readUvarint(br)  // min
				rev, _ := readUvarint(br)
				_, _ = readCHString(br) // db
				u, _ := readCHString(br)
				pw, _ := readCHString(br)
				mu.Lock()
				nativeUser, nativePass = u, pw
				mu.Unlock()

				// Reply with ServerHello
				var sh bytes.Buffer
				writeUvarint(&sh, chServerHello)
				writeCHString(&sh, "ClickHouse")
				writeUvarint(&sh, 24)
				writeUvarint(&sh, 8)
				writeUvarint(&sh, rev)
				_, _ = conn.Write(sh.Bytes())

				for {
					rec := &chPacketRecorder{r: br}
					code, err := readUvarint(rec)
					if err != nil {
						return
					}
					if code == chClientQuery {
						q, err := consumeCHClientQuery(rec, rev)
						if err != nil {
							return
						}
						mu.Lock()
						nativeQueries = append(nativeQueries, q)
						mu.Unlock()
						// Reply with ServerEndOfStream (code 5)
						var eos bytes.Buffer
						writeUvarint(&eos, 5)
						_, _ = conn.Write(eos.Bytes())
					}
				}
			}(c)
		}
	}()

	nInfo, err := ProbeClickHouse(nativeLn.Addr().String(), 2*time.Second)
	if err != nil || nInfo.Interface != "native" || !strings.Contains(nInfo.Detail, "ClickHouse 24.8") {
		t.Fatalf("ProbeClickHouse Native failed: info=%+v err=%v", nInfo, err)
	}

	nSrv, err := net.Dial("tcp", nativeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	nCli, nProxyCli := net.Pipe()
	nProxy := NewClickHouseProxy(ClickHouseGuardConfig{
		ReadOnly:     true,
		InjectCreds:  true,
		UsernameSpec: "literal:native_reader",
		PasswordSpec: "literal:native_pass",
	})
	nDone := make(chan struct{})
	go func() {
		defer close(nDone)
		_, _, _ = nProxy.Proxy(nProxyCli, nSrv, nil)
	}()

	nBR := bufio.NewReader(nCli)
	// Send ClientHello with placeholder creds (rev 54400)
	_, _ = nCli.Write(encodeCHClientHello("ch-client", 24, 1, 54400, "default", "placeholder", "wrong"))
	if pType, err := readUvarint(nBR); err != nil || pType != chServerHello {
		t.Fatalf("expected ServerHello, got %d err=%v", pType, err)
	}
	_, _ = readCHString(nBR)
	_, _ = readUvarint(nBR)
	_, _ = readUvarint(nBR)
	_, _ = readUvarint(nBR)

	buildNativeQuery := func(sql string) []byte {
		var b bytes.Buffer
		writeUvarint(&b, chClientQuery)
		writeCHString(&b, "qid-1")
		b.WriteByte(0)    // query_kind=0 (minimal ClientInfo)
		writeCHString(&b, "") // empty settings terminator
		writeUvarint(&b, 2)   // stage = complete
		writeUvarint(&b, 0)   // compression = none
		writeCHString(&b, sql)
		return b.Bytes()
	}

	// Allowed SELECT
	_, _ = nCli.Write(buildNativeQuery("SELECT 1"))
	if pType, err := readUvarint(nBR); err != nil || pType != 5 {
		t.Fatalf("expected EndOfStream (5) for allowed native SELECT, got %d err=%v", pType, err)
	}

	// Blocked DROP TABLE -> should return ServerException (2) locally!
	_, _ = nCli.Write(buildNativeQuery("DROP TABLE events"))
	if pType, err := readUvarint(nBR); err != nil || pType != chServerException {
		t.Fatalf("expected ServerException (2) for blocked native DROP, got %d err=%v", pType, err)
	}

	_ = nCli.Close()
	<-nDone

	mu.Lock()
	defer mu.Unlock()
	if nativeUser != "native_reader" || nativePass != "native_pass" {
		t.Fatalf("CH native credential injection mismatch: user=%q pass=%q", nativeUser, nativePass)
	}
	if len(nativeQueries) != 1 || nativeQueries[0] != "SELECT 1" {
		t.Fatalf("expected only SELECT 1 forwarded to native CH, got %v", nativeQueries)
	}
}

func BenchmarkIsReadOnlyTSQL_Select(b *testing.B) {
	q := "SELECT TOP 100 id, order_no, total_amount FROM dbo.orders WHERE tenant_id = 'acme' AND status = 'PAID' ORDER BY created_at DESC"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ok, _ := IsReadOnlyTSQL(q); !ok {
			b.Fatal("expected allowed")
		}
	}
}

func BenchmarkExtractTDSSQLBatchView_ASCII(b *testing.B) {
	payload := encodeUTF16LE("SELECT TOP 50 id, customer_name, amount FROM dbo.sales WHERE region = 'cn-east'")
	var scratch [512]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s, zero := extractTDSSQLBatchView(payload, scratch[:])
		if !zero || len(s) == 0 {
			b.Fatal("expected zero-alloc ASCII view")
		}
	}
}

func BenchmarkIsReadOnlyOracleSQL_Select(b *testing.B) {
	q := "SELECT emp_id, dept_name, salary FROM hr.employees WHERE department_id = 42 AND rownum <= 100"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ok, _ := IsReadOnlyOracleSQL(q); !ok {
			b.Fatal("expected allowed")
		}
	}
}

func BenchmarkExtractOracleTTCStatementBytes(b *testing.B) {
	payload := append([]byte{0x00, 0x00, 0x03, 0x5E, 0x01, 0x00, 0x00, 0x20}, []byte("SELECT emp_id, dept_name FROM hr.employees WHERE rownum <= 10")...)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		stmt, ok := extractOracleTTCStatementBytes(payload)
		if !ok || len(stmt) == 0 {
			b.Fatal("expected statement extracted")
		}
	}
}

func BenchmarkIsReadOnlyClickHouseSQL_Select(b *testing.B) {
	q := "SELECT toDate(ts) AS d, count(), sum(amount) FROM analytics.events WHERE tenant_id = 'acme' GROUP BY d ORDER BY d DESC LIMIT 30"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ok, _ := IsReadOnlyClickHouseSQL(q); !ok {
			b.Fatal("expected allowed")
		}
	}
}
