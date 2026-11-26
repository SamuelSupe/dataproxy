package guard

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/transport"
)

// ClickHouse Native TCP packet codes.
const (
	chClientHello  uint64 = 0
	chClientQuery  uint64 = 1
	chClientData   uint64 = 2
	chClientCancel uint64 = 3
	chClientPing   uint64 = 4

	chServerHello     uint64 = 0
	chServerException uint64 = 2

	maxCHHTTPBodyInspect = 16 * 1024 * 1024
)

// ClickHouseGuardConfig configures tenant-local ClickHouse read-only enforcement
// and credential injection, automatically supporting BOTH the ClickHouse HTTP(S)
// interface (8123/8443) and Native TCP interface (9000/9440).
type ClickHouseGuardConfig struct {
	ReadOnly     bool
	InjectCreds  bool
	UsernameSpec string
	PasswordSpec string
}

func (c ClickHouseGuardConfig) Enabled() bool {
	return c.ReadOnly || c.InjectCreds
}

// ClickHouseProbeInfo holds metadata returned by ProbeClickHouse / ProbeClickHouseTLS.
type ClickHouseProbeInfo struct {
	Interface string // "http" or "native"
	Detail    string
	Latency   time.Duration
}

// ProbeClickHouse checks ClickHouse reachability without credentials (HTTP /ping or Native Hello).
func ProbeClickHouse(addr string, timeout time.Duration) (*ClickHouseProbeInfo, error) {
	return ProbeClickHouseTLS(addr, timeout, nil)
}

// ProbeClickHouseTLS probes ClickHouse over HTTP(S) (/ping) first, falling back to
// ClickHouse Native TCP ClientHello/ServerHello when the target is a native port (9000/9440).
func ProbeClickHouseTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*ClickHouseProbeInfo, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	start := time.Now()

	// 1. Try ClickHouse HTTP(S) GET /ping first (returns "Ok.\n").
	scheme := "http"
	tr := &http.Transport{DisableKeepAlives: true}
	if tlsCfg != nil {
		scheme = "https"
		tr.TLSClientConfig = tlsCfg.Clone()
	}
	httpCli := &http.Client{Timeout: timeout, Transport: tr}
	resp, err := httpCli.Get(scheme + "://" + addr + "/ping")
	tr.CloseIdleConnections()
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		text := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusOK && strings.HasPrefix(text, "Ok") {
			return &ClickHouseProbeInfo{
				Interface: scheme,
				Detail:    "ping=" + text,
				Latency:   time.Since(start),
			}, nil
		}
	}

	// 2. Try ClickHouse Native TCP ClientHello (port 9000/9440).
	var conn net.Conn
	if tlsCfg != nil {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsCfg.Clone())
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello := encodeCHClientHello("dataproxy-agent", 24, 1, 54460, "default", "default", "")
	if _, err := conn.Write(hello); err != nil {
		return nil, fmt.Errorf("write clickhouse ClientHello: %w", err)
	}
	br := bufio.NewReader(conn)
	pktType, err := readUvarint(br)
	if err != nil {
		return nil, fmt.Errorf("read clickhouse ServerHello: %w", err)
	}
	switch pktType {
	case chServerHello:
		srvName, _ := readCHString(br)
		maj, _ := readUvarint(br)
		minV, _ := readUvarint(br)
		return &ClickHouseProbeInfo{
			Interface: "native",
			Detail:    fmt.Sprintf("%s %d.%d", srvName, maj, minV),
			Latency:   time.Since(start),
		}, nil
	case chServerException:
		// Even an auth exception proves a live ClickHouse Native TCP endpoint!
		return &ClickHouseProbeInfo{
			Interface: "native",
			Detail:    "native protocol ready (auth required)",
			Latency:   time.Since(start),
		}, nil
	default:
		return nil, fmt.Errorf("unexpected clickhouse native reply type %d", pktType)
	}
}

var chDangerousTableFuncs = []string{
	"FILE", "URL", "S3", "S3CLUSTER", "HDFS", "JDBC", "ODBC",
	"REMOTE", "REMOTESECURE", "MYSQL", "POSTGRESQL", "MONGODB", "REDIS", "INPUT",
}

// IsReadOnlyClickHouseSQL enforces strict read-only ClickHouse SQL rules.
func IsReadOnlyClickHouseSQL(sql string) (bool, string) {
	bufPtr := getSQLTokens()
	defer putSQLTokens(bufPtr)
	tokens := tokenizeSQLInto(sql, *bufPtr)
	*bufPtr = tokens
	if len(tokens) == 0 {
		return true, ""
	}

	afterFromOrJoin := false
	for i, tok := range tokens {
		if tok == ";" && i < len(tokens)-1 {
			return false, "multi-statement ClickHouse SQL is blocked in read-only mode"
		}
		if afterFromOrJoin {
			for _, fn := range chDangerousTableFuncs {
				if strings.EqualFold(tok, fn) {
					return false, "ClickHouse external table function " + fn + "() is blocked in read-only mode"
				}
			}
		}
		afterFromOrJoin = len(tok) == 4 && (strings.EqualFold(tok, "FROM") || strings.EqualFold(tok, "JOIN"))
	}
	if tokens[len(tokens)-1] == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	if len(tokens) == 0 {
		return true, ""
	}

	first := tokens[0]
	switch {
	case strings.EqualFold(first, "SELECT"),
		strings.EqualFold(first, "SHOW"),
		strings.EqualFold(first, "DESCRIBE"),
		strings.EqualFold(first, "DESC"),
		strings.EqualFold(first, "EXPLAIN"),
		strings.EqualFold(first, "EXISTS"),
		strings.EqualFold(first, "CHECK"):
		if reason := checkForbiddenSelectClauses(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "WITH"):
		for _, tok := range tokens[1:] {
			for _, kw := range mutatingCTEKeywords {
				if strings.EqualFold(tok, kw) {
					return false, "mutating ClickHouse CTE (" + kw + ") is blocked in read-only mode"
				}
			}
		}
		if reason := checkForbiddenSelectClauses(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	default:
		return false, "ClickHouse SQL command " + strings.ToUpper(first) + " is blocked by tenant read-only policy"
	}
}

// ClickHouseProxy intercepts ClickHouse traffic (auto-detecting HTTP(S) vs Native TCP)
// for tenant-local credential injection and strict read-only SQL enforcement.
type ClickHouseProxy struct {
	cfg            ClickHouseGuardConfig
	blockedQueries atomic.Int64
}

func NewClickHouseProxy(cfg ClickHouseGuardConfig) *ClickHouseProxy {
	return &ClickHouseProxy{cfg: cfg}
}

func (p *ClickHouseProxy) BlockedQueries() int64 {
	return p.blockedQueries.Load()
}

func (p *ClickHouseProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(sqlText, reason string),
) (bytesIn, bytesOut int64, err error) {
	if !p.cfg.ReadOnly && !p.cfg.InjectCreds {
		in2, out2 := transport.BidirectionalPipe(clientConn, serverConn)
		return in2, out2, nil
	}

	cliBR := transport.GetBufioReader(clientConn)
	defer transport.PutBufioReader(cliBR)

	_ = clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	peek, err := cliBR.Peek(3)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, 0, err
	}

	if looksLikeHTTPMethod(peek) {
		return p.proxyHTTP(cliBR, clientConn, serverConn, onBlocked)
	}
	return p.proxyNativeTCP(cliBR, clientConn, serverConn, onBlocked)
}

func looksLikeHTTPMethod(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	s := string(b[:3])
	return s == "GET" || s == "POS" || s == "HEA" || s == "PUT" || s == "DEL" || s == "OPT"
}

func (p *ClickHouseProxy) proxyHTTP(
	cliBR *bufio.Reader,
	clientConn, serverConn net.Conn,
	onBlocked func(sqlText, reason string),
) (bytesIn, bytesOut int64, err error) {
	upBR := transport.GetBufioReader(serverConn)
	defer transport.PutBufioReader(upBR)

	var realUser, realPass string
	if p.cfg.InjectCreds {
		realUser, err = ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			writeCHHTTPError(clientConn, http.StatusBadGateway, "dataproxy-agent: local clickhouse username error", true)
			return 0, 0, err
		}
		realPass, err = ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			writeCHHTTPError(clientConn, http.StatusBadGateway, "dataproxy-agent: local clickhouse password error", true)
			return 0, 0, err
		}
	}

	for {
		req, rerr := http.ReadRequest(cliBR)
		if rerr != nil {
			return bytesIn, bytesOut, nil
		}

		// Health ping endpoints (/ping, /replicas_status) are always read-only.
		isPing := req.Method == http.MethodGet && (req.URL.Path == "/ping" || req.URL.Path == "/replicas_status")

		var bodyBytes []byte
		if !isPing && req.Method == http.MethodPost {
			if req.ContentLength > maxCHHTTPBodyInspect {
				p.blockedQueries.Add(1)
				reason := "ClickHouse HTTP POST body exceeds 16MiB read-only inspection limit"
				if onBlocked != nil {
					onBlocked("POST(oversized)", reason)
				}
				writeCHHTTPError(clientConn, http.StatusForbidden, "Code: 497. DB::Exception: dataproxy-agent: "+reason+" (ACCESS_DENIED)", true)
				_ = clientConn.Close()
				return bytesIn, bytesOut, nil
			}
			var readErr error
			bodyBytes, readErr = io.ReadAll(io.LimitReader(req.Body, maxCHHTTPBodyInspect+1))
			_ = req.Body.Close()
			if readErr != nil {
				return bytesIn, bytesOut, nil
			}
			if len(bodyBytes) > maxCHHTTPBodyInspect {
				p.blockedQueries.Add(1)
				reason := "ClickHouse HTTP POST body exceeds 16MiB read-only inspection limit"
				if onBlocked != nil {
					onBlocked("POST(oversized)", reason)
				}
				writeCHHTTPError(clientConn, http.StatusForbidden, "Code: 497. DB::Exception: dataproxy-agent: "+reason+" (ACCESS_DENIED)", true)
				_ = clientConn.Close()
				return bytesIn, bytesOut, nil
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}

		if p.cfg.ReadOnly && !isPing {
			if req.Method != http.MethodGet && req.Method != http.MethodPost && req.Method != http.MethodHead {
				p.blockedQueries.Add(1)
				reason := fmt.Sprintf("ClickHouse HTTP method %s is blocked by tenant read-only policy", req.Method)
				if onBlocked != nil {
					onBlocked(req.Method, reason)
				}
				writeCHHTTPError(clientConn, http.StatusForbidden, "Code: 497. DB::Exception: dataproxy-agent: "+reason+" (ACCESS_DENIED)", true)
				_ = clientConn.Close()
				return bytesIn, bytesOut, nil
			}
			q := req.URL.Query()
			sqlText := strings.TrimSpace(q.Get("query"))
			if len(bodyBytes) > 0 {
				if sqlText != "" {
					sqlText += "\n" + string(bodyBytes)
				} else {
					sqlText = string(bodyBytes)
				}
			}
			if ok, reason := IsReadOnlyClickHouseSQL(sqlText); !ok {
				p.blockedQueries.Add(1)
				if onBlocked != nil {
					onBlocked(sqlText, reason)
				}
				writeCHHTTPError(clientConn, http.StatusForbidden, "Code: 497. DB::Exception: dataproxy-agent: "+reason+" (ACCESS_DENIED)", req.Close)
				if req.Close {
					_ = clientConn.Close()
					return bytesIn, bytesOut, nil
				}
				continue
			}
			// Defense-in-depth: also enforce ClickHouse native readonly=1 setting!
			q.Set("readonly", "1")
			req.URL.RawQuery = q.Encode()
		}

		if p.cfg.InjectCreds {
			q := req.URL.Query()
			q.Del("user")
			q.Del("password")
			req.URL.RawQuery = q.Encode()
			req.Header.Del("Authorization")
			req.Header.Set("X-ClickHouse-User", realUser)
			req.Header.Set("X-ClickHouse-Key", realPass)
		}

		inCounter := &countingWriter{w: serverConn}
		if err := req.Write(inCounter); err != nil {
			return bytesIn + inCounter.n, bytesOut, nil
		}
		bytesIn += inCounter.n

		resp, err := http.ReadResponse(upBR, req)
		if err != nil {
			return bytesIn, bytesOut, nil
		}
		outCounter := &countingWriter{w: clientConn}
		werr := resp.Write(outCounter)
		_ = resp.Body.Close()
		bytesOut += outCounter.n
		if werr != nil || req.Close || resp.Close {
			return bytesIn, bytesOut, nil
		}
	}
}

func writeCHHTTPError(w io.Writer, status int, body string, forceClose bool) {
	connHdr := "keep-alive"
	if forceClose {
		connHdr = "close"
	}
	statusText := http.StatusText(status)
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n%s\n",
		status, statusText, len(body)+1, connHdr, body,
	)
}

func (p *ClickHouseProxy) proxyNativeTCP(
	cliBR *bufio.Reader,
	clientConn, serverConn net.Conn,
	onBlocked func(sqlText, reason string),
) (bytesIn, bytesOut int64, err error) {
	var realUser, realPass string
	if p.cfg.InjectCreds {
		realUser, err = ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			_ = writeCHNativeException(clientConn, 497, "dataproxy-agent: local clickhouse username error")
			return 0, 0, err
		}
		realPass, err = ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			_ = writeCHNativeException(clientConn, 497, "dataproxy-agent: local clickhouse password error")
			return 0, 0, err
		}
	}

	// 1. Read & optionally rewrite ClientHello (0x00).
	_ = clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	pktType, err := readUvarint(cliBR)
	if err != nil || pktType != chClientHello {
		return 0, 0, fmt.Errorf("expected clickhouse ClientHello (0), got type=%d err=%v", pktType, err)
	}
	clientName, err := readCHString(cliBR)
	if err != nil {
		return 0, 0, err
	}
	majVer, err := readUvarint(cliBR)
	if err != nil {
		return 0, 0, err
	}
	minVer, err := readUvarint(cliBR)
	if err != nil {
		return 0, 0, err
	}
	protoRev, err := readUvarint(cliBR)
	if err != nil {
		return 0, 0, err
	}
	dbName, err := readCHString(cliBR)
	if err != nil {
		return 0, 0, err
	}
	user, err := readCHString(cliBR)
	if err != nil {
		return 0, 0, err
	}
	pass, err := readCHString(cliBR)
	if err != nil {
		return 0, 0, err
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	if p.cfg.InjectCreds {
		user = realUser
		pass = realPass
	}
	helloBytes := encodeCHClientHello(clientName, majVer, minVer, protoRev, dbName, user, pass)
	bytesIn += int64(len(helloBytes))
	if _, err := serverConn.Write(helloBytes); err != nil {
		return bytesIn, 0, err
	}

	if !p.cfg.ReadOnly {
		in2, out2 := transport.BidirectionalPipe(&peekedConn{Conn: clientConn, r: cliBR}, serverConn)
		return bytesIn + in2, out2, nil
	}

	// 2. Concurrent server -> client relay + ClientQuery inspection.
	var clientWriteMu sync.Mutex
	var serverCopyBytes atomic.Int64
	srvDone := make(chan struct{})
	go func() {
		defer func() {
			_ = clientConn.Close()
			close(srvDone)
		}()
		bufPtr := transport.GetCopyBuf()
		defer transport.PutCopyBuf(bufPtr)
		buf := *bufPtr
		for {
			n, rerr := serverConn.Read(buf)
			if n > 0 {
				clientWriteMu.Lock()
				_, werr := clientConn.Write(buf[:n])
				clientWriteMu.Unlock()
				serverCopyBytes.Add(int64(n))
				if werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Reuse one chPacketRecorder across native queries on this connection to avoid per-query buffer churn.
	rec := &chPacketRecorder{r: cliBR}
	for {
		if rec.buf.Cap() > 256*1024 {
			rec.buf = bytes.Buffer{}
		} else {
			rec.buf.Reset()
		}
		code, rerr := readUvarint(rec)
		if rerr != nil {
			break
		}
		switch code {
		case chClientPing, chClientCancel:
			// Single-varint packet; forward immediately.
		case chClientQuery:
			sqlText, parseErr := consumeCHClientQuery(rec, protoRev)
			if parseErr != nil {
				goto Done
			}
			if ok, reason := IsReadOnlyClickHouseSQL(sqlText); !ok {
				p.blockedQueries.Add(1)
				if onBlocked != nil {
					onBlocked(sqlText, reason)
				}
				clientWriteMu.Lock()
				werr := writeCHNativeException(clientConn, 497, "dataproxy-agent: "+reason)
				clientWriteMu.Unlock()
				if werr != nil {
					goto Done
				}
				continue
			}
		case chClientData:
			// ClientData (INSERT block) is strictly blocked in read-only mode!
			p.blockedQueries.Add(1)
			reason := "ClickHouse Native ClientData block is blocked in read-only mode"
			if onBlocked != nil {
				onBlocked("ClientData", reason)
			}
			clientWriteMu.Lock()
			_ = writeCHNativeException(clientConn, 497, "dataproxy-agent: "+reason)
			clientWriteMu.Unlock()
			goto Done
		default:
			goto Done
		}
		raw := rec.buf.Bytes()
		bytesIn += int64(len(raw))
		if _, err := serverConn.Write(raw); err != nil {
			break
		}
	}

Done:
	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

type chPacketRecorder struct {
	r   *bufio.Reader
	buf bytes.Buffer
}

func (c *chPacketRecorder) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.buf.WriteByte(b)
	}
	return b, err
}

func (c *chPacketRecorder) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

// consumeCHClientQuery parses a ClickHouse Native ClientQuery packet and extracts its SQL query string.
func consumeCHClientQuery(r *chPacketRecorder, protoRev uint64) (string, error) {
	// 1. query_id (string)
	if _, err := readCHString(r); err != nil {
		return "", err
	}
	// 2. ClientInfo: query_kind (1B: 0=no_query, 1=initial, 2=secondary)
	qKind, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	var scratch [24]byte
	if qKind != 0 {
		// initial_user, initial_query_id, initial_address
		for i := 0; i < 3; i++ {
			if _, err := readCHString(r); err != nil {
				return "", err
			}
		}
		if protoRev >= 54449 {
			// initial_query_start_time_microseconds (int64)
			if _, err := io.ReadFull(r, scratch[:8]); err != nil {
				return "", err
			}
		}
		// interface (1B = 1 TCP), os_user, client_hostname, client_name
		if _, err := r.ReadByte(); err != nil {
			return "", err
		}
		for i := 0; i < 3; i++ {
			if _, err := readCHString(r); err != nil {
				return "", err
			}
		}
		// client_version_major, minor, protocol_version
		for i := 0; i < 3; i++ {
			if _, err := readUvarint(r); err != nil {
				return "", err
			}
		}
		if protoRev >= 54060 { // quota_key
			if _, err := readCHString(r); err != nil {
				return "", err
			}
		}
		if protoRev >= 54448 { // distributed_depth
			if _, err := readUvarint(r); err != nil {
				return "", err
			}
		}
		if protoRev >= 54401 { // client_version_patch
			if _, err := readUvarint(r); err != nil {
				return "", err
			}
		}
		if protoRev >= 54442 { // OpenTelemetry trace flag (0 = none)
			otelFlag, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			if otelFlag != 0 {
				if _, err := io.ReadFull(r, scratch[:24]); err != nil {
					return "", err
				}
				if _, err := readCHString(r); err != nil {
					return "", err
				}
				if _, err := r.ReadByte(); err != nil {
					return "", err
				}
			}
		}
		if protoRev >= 54453 { // collaborate_with_initiator..count_participating_replicas (4 varints)
			for i := 0; i < 4; i++ {
				if _, err := readUvarint(r); err != nil {
					return "", err
				}
			}
		}
	}

	// 3. Settings (empty string terminates settings list).
	for {
		name, err := readCHString(r)
		if err != nil {
			return "", err
		}
		if name == "" {
			break
		}
		if protoRev >= 54429 {
			// flags (varint) + string value
			if _, err := readUvarint(r); err != nil {
				return "", err
			}
		}
		if _, err := readCHString(r); err != nil {
			return "", err
		}
	}
	// 4. Optional interserver secret (protoRev >= 54441).
	if protoRev >= 54441 {
		if _, err := readCHString(r); err != nil {
			return "", err
		}
	}
	// 5. stage (varint) + compression (varint) + query (string)!
	if _, err := readUvarint(r); err != nil {
		return "", err
	}
	if _, err := readUvarint(r); err != nil {
		return "", err
	}
	sqlText, err := readCHString(r)
	if err != nil {
		return "", err
	}
	return sqlText, nil
}

func encodeCHClientHello(name string, maj, minV, rev uint64, db, user, pass string) []byte {
	var b bytes.Buffer
	writeUvarint(&b, chClientHello)
	writeCHString(&b, name)
	writeUvarint(&b, maj)
	writeUvarint(&b, minV)
	writeUvarint(&b, rev)
	writeCHString(&b, db)
	writeCHString(&b, user)
	writeCHString(&b, pass)
	return b.Bytes()
}

func writeCHNativeException(w io.Writer, code int32, msg string) error {
	var b bytes.Buffer
	writeUvarint(&b, chServerException)
	_ = binary.Write(&b, binary.LittleEndian, code)
	writeCHString(&b, "DB::Exception")
	writeCHString(&b, msg)
	writeCHString(&b, "") // stack trace
	b.WriteByte(0)        // has_nested = false
	_, err := w.Write(b.Bytes())
	return err
}

func writeUvarint(b *bytes.Buffer, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	b.Write(tmp[:n])
}

func writeCHString(b *bytes.Buffer, s string) {
	writeUvarint(b, uint64(len(s)))
	b.WriteString(s)
}

func readUvarint(r io.ByteReader) (uint64, error) {
	return binary.ReadUvarint(r)
}

type byteAndBlockReader interface {
	io.ByteReader
	io.Reader
}

func readCHString(r byteAndBlockReader) (string, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return "", err
	}
	if n > maxCHHTTPBodyInspect {
		return "", errors.New("clickhouse string exceeds 16MiB limit")
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
