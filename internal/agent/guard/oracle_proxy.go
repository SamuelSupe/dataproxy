package guard

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"dataproxy/internal/transport"
)

// Oracle TNS packet types.
const (
	tnsTypeConnect  byte = 1
	tnsTypeAccept   byte = 2
	tnsTypeAck      byte = 3
	tnsTypeRefuse   byte = 4
	tnsTypeRedirect byte = 5
	tnsTypeData     byte = 6
	tnsTypeNull     byte = 7
	tnsTypeAbort    byte = 9
	tnsTypeResend   byte = 11
	tnsTypeMarker   byte = 12

	maxTNSPacketBytes = 16 * 1024 * 1024
)

// OracleGuardConfig configures tenant-local Oracle TNS read-only SQL enforcement.
type OracleGuardConfig struct {
	ReadOnly  bool
	TargetTLS *tls.Config // Optional TCPS (Oracle direct TLS, e.g. port 2484)
}

func (c OracleGuardConfig) Enabled() bool {
	return c.ReadOnly
}

// OracleProbeInfo holds metadata returned by ProbeOracle via a credential-free TNS CONNECT probe.
type OracleProbeInfo struct {
	TNSVersion uint16
	ReplyType  byte
	Latency    time.Duration
}

// ProbeOracle sends a lightweight TNS CONNECT packet without credentials to verify
// an Oracle Listener is alive and responding to TNS protocol frames.
func ProbeOracle(addr string, timeout time.Duration) (*OracleProbeInfo, error) {
	return ProbeOracleTLS(addr, timeout, nil)
}

// ProbeOracleTLS probes an Oracle Listener over plaintext TNS (1521) or TCPS TLS (2484).
func ProbeOracleTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*OracleProbeInfo, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	start := time.Now()
	var conn net.Conn
	var err error
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

	probePkt := buildTNSConnectProbe("(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=dataproxy-agent))(COMMAND=ping)))")
	if _, err := conn.Write(probePkt); err != nil {
		return nil, fmt.Errorf("write oracle TNS CONNECT: %w", err)
	}
	pType, payload, _, err := readTNSPacket(conn, false)
	if err != nil {
		return nil, fmt.Errorf("read oracle TNS reply: %w", err)
	}
	switch pType {
	case tnsTypeAccept, tnsTypeRefuse, tnsTypeRedirect, tnsTypeData, tnsTypeResend:
		var ver uint16
		if len(payload) >= 2 {
			ver = binary.BigEndian.Uint16(payload[0:2])
		}
		return &OracleProbeInfo{
			TNSVersion: ver,
			ReplyType:  pType,
			Latency:    time.Since(start),
		}, nil
	default:
		return nil, fmt.Errorf("unexpected oracle TNS reply type %d", pType)
	}
}

var oracleDangerousPrefixes = []string{
	"DBMS_", "UTL_FILE", "UTL_HTTP", "UTL_TCP", "UTL_SMTP", "UTL_INADDR", "CTX_DDL",
}

// IsReadOnlyOracleSQL enforces strict read-only Oracle SQL / PL/SQL rules.
func IsReadOnlyOracleSQL(sql string) (bool, string) {
	bufPtr := getSQLTokens()
	defer putSQLTokens(bufPtr)
	tokens := tokenizeSQLInto(sql, *bufPtr)
	*bufPtr = tokens
	if len(tokens) == 0 {
		return true, ""
	}

	for i, tok := range tokens {
		if tok == ";" && i < len(tokens)-1 {
			return false, "multi-statement Oracle SQL is blocked in read-only mode"
		}
		if badSeg := matchOracleDangerousPkg(tok); badSeg != "" {
			return false, "Oracle privileged package " + strings.ToUpper(badSeg) + " is blocked in read-only mode"
		}
	}
	if tokens[len(tokens)-1] == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	if len(tokens) == 0 {
		return true, ""
	}

	first := tokens[0]
	switch {
	case strings.EqualFold(first, "SELECT"):
		if reason := checkForbiddenSelectClauses(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "WITH"):
		for _, tok := range tokens[1:] {
			for _, kw := range mutatingCTEKeywords {
				if strings.EqualFold(tok, kw) {
					return false, "mutating Oracle CTE (" + kw + ") is blocked in read-only mode"
				}
			}
		}
		if reason := checkForbiddenSelectClauses(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "EXPLAIN"), strings.EqualFold(first, "DESCRIBE"), strings.EqualFold(first, "DESC"):
		return true, ""

	case strings.EqualFold(first, "COMMIT"), strings.EqualFold(first, "ROLLBACK"):
		return true, ""

	default:
		return false, "Oracle SQL/PLSQL command " + strings.ToUpper(first) + " is blocked by tenant read-only policy"
	}
}

// matchOracleDangerousPkg scans dot-separated identifier segments with zero heap allocations
// (e.g. SYS.UTL_HTTP.REQUEST, DBMS_SCHEDULER.CREATE_JOB).
func matchOracleDangerousPkg(tok string) string {
	for len(tok) > 0 {
		seg := tok
		if dot := strings.IndexByte(tok, '.'); dot >= 0 {
			seg = tok[:dot]
			tok = tok[dot+1:]
		} else {
			tok = ""
		}
		if len(seg) >= 5 {
			c0 := seg[0]
			if c0 == 'd' || c0 == 'D' || c0 == 'u' || c0 == 'U' || c0 == 'c' || c0 == 'C' {
				for _, pref := range oracleDangerousPrefixes {
					if len(seg) >= len(pref) && strings.EqualFold(seg[:len(pref)], pref) {
						return seg
					}
				}
			}
		}
	}
	return ""
}

// OracleProxy intercepts Oracle TNS DATA packets on the tenant agent to block mutating
// SQL/PLSQL statements before they reach the tenant Oracle database.
type OracleProxy struct {
	cfg            OracleGuardConfig
	blockedQueries atomic.Int64
}

func NewOracleProxy(cfg OracleGuardConfig) *OracleProxy {
	return &OracleProxy{cfg: cfg}
}

func (p *OracleProxy) BlockedQueries() int64 {
	return p.blockedQueries.Load()
}

func (p *OracleProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(sqlText, reason string),
) (bytesIn, bytesOut int64, err error) {
	if !p.cfg.ReadOnly {
		in2, out2 := transport.BidirectionalPipe(clientConn, serverConn)
		return in2, out2, nil
	}

	var largeHeader atomic.Bool
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
				// Detect TNS 3.15+ ACCEPT negotiating 4-byte packet length headers (version >= 315).
				if n >= 10 && buf[4] == tnsTypeAccept {
					ver := binary.BigEndian.Uint16(buf[8:10])
					if ver >= 315 {
						largeHeader.Store(true)
					}
				}
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

	cmdBufPtr := transport.GetCopyBuf()
	defer transport.PutCopyBuf(cmdBufPtr)
	cmdBuf := *cmdBufPtr

	for {
		pType, payload, rawPkt, rerr := readTNSPacketReusable(clientConn, largeHeader.Load(), cmdBuf)
		if rerr != nil {
			break
		}
		bytesIn += int64(len(rawPkt))

		if pType == tnsTypeData && len(payload) > 4 {
			if stmtBytes, found := extractOracleTTCStatementBytes(payload); found {
				stmtView := unsafe.String(unsafe.SliceData(stmtBytes), len(stmtBytes))
				if ok, reason := IsReadOnlyOracleSQL(stmtView); !ok {
					p.blockedQueries.Add(1)
					if onBlocked != nil {
						onBlocked(string(stmtBytes), reason)
					}
					clientWriteMu.Lock()
					werr := writeOracleTNSBlockedError(clientConn, largeHeader.Load(), "ORA-01031: insufficient privileges (dataproxy-agent: "+reason+")")
					clientWriteMu.Unlock()
					if werr != nil {
						break
					}
					continue
				}
			}
		}

		if _, err := serverConn.Write(rawPkt); err != nil {
			break
		}
	}

	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

func buildTNSConnectProbe(connectData string) []byte {
	// Classic TNS v314 CONNECT header (58 bytes) + connectData
	hdrLen := 58
	total := hdrLen + len(connectData)
	pkt := make([]byte, total)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(total))
	pkt[4] = tnsTypeConnect
	binary.BigEndian.PutUint16(pkt[8:10], 314) // version 3.14
	binary.BigEndian.PutUint16(pkt[10:12], 300)
	binary.BigEndian.PutUint16(pkt[14:16], 8192)  // SDU
	binary.BigEndian.PutUint16(pkt[16:18], 65535) // TDU
	binary.BigEndian.PutUint16(pkt[22:24], 1)     // value of 1 in hardware
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(connectData)))
	binary.BigEndian.PutUint16(pkt[26:28], uint16(hdrLen))
	copy(pkt[hdrLen:], connectData)
	return pkt
}

func readTNSPacketReusable(r io.Reader, largeHeader bool, scratch []byte) (pktType byte, payload, rawPkt []byte, err error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, nil, err
	}
	var total int
	if largeHeader {
		total = int(binary.BigEndian.Uint32(hdr[0:4]))
	} else {
		total = int(binary.BigEndian.Uint16(hdr[0:2]))
	}
	if total < 8 || total > maxTNSPacketBytes {
		return 0, nil, nil, fmt.Errorf("invalid oracle TNS packet length %d", total)
	}
	if total <= len(scratch) {
		rawPkt = scratch[:total]
	} else {
		rawPkt = make([]byte, total)
	}
	copy(rawPkt[:8], hdr[:])
	payload = rawPkt[8:]
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, nil, err
		}
	}
	return hdr[4], payload, rawPkt, nil
}

func readTNSPacket(r io.Reader, largeHeader bool) (pktType byte, payload, rawPkt []byte, err error) {
	return readTNSPacketReusable(r, largeHeader, nil)
}

// writeOracleTNSBlockedError emits a TNS DATA packet carrying a TTC OER (0x04) ORA-01031 error frame.
func writeOracleTNSBlockedError(w io.Writer, largeHeader bool, msg string) error {
	// TNS DATA payload: 2B dataFlags(0x0000) + TTC OER (0x04) + error code (1031) + message length + msg
	var body bytes.Buffer
	body.Write([]byte{0x00, 0x00}) // Data flags
	body.WriteByte(0x04)           // TTC_OER
	body.WriteByte(0x01)           // end of call status
	_ = binary.Write(&body, binary.BigEndian, uint16(1031))
	body.WriteByte(byte(min(len(msg), 250)))
	if len(msg) > 250 {
		body.WriteString(msg[:250])
	} else {
		body.WriteString(msg)
	}

	payload := body.Bytes()
	total := 8 + len(payload)
	pkt := make([]byte, total)
	if largeHeader {
		binary.BigEndian.PutUint32(pkt[0:4], uint32(total))
	} else {
		binary.BigEndian.PutUint16(pkt[0:2], uint16(total))
	}
	pkt[4] = tnsTypeData
	copy(pkt[8:], payload)
	_, err := w.Write(pkt)
	return err
}

var oracleSQLStarters = [][]byte{
	[]byte("SELECT "), []byte("INSERT "), []byte("UPDATE "), []byte("DELETE "),
	[]byte("MERGE "), []byte("DROP "), []byte("ALTER "), []byte("CREATE "),
	[]byte("TRUNCATE "), []byte("GRANT "), []byte("REVOKE "), []byte("BEGIN "),
	[]byte("DECLARE "), []byte("CALL "), []byte("EXEC "), []byte("EXECUTE "),
	[]byte("LOCK "), []byte("WITH "), []byte("EXPLAIN "),
}

// extractOracleTTCStatement scans a TNS DATA payload for TTC OALL8 / SQL text segments.
func extractOracleTTCStatement(dataPayload []byte) (string, bool) {
	b, ok := extractOracleTTCStatementBytes(dataPayload)
	if !ok {
		return "", false
	}
	return string(b), true
}

// extractOracleTTCStatementBytes locates SQL bytes inside a TNS DATA payload with zero heap allocations.
func extractOracleTTCStatementBytes(dataPayload []byte) ([]byte, bool) {
	// Skip 2-byte TNS DATA flags.
	if len(dataPayload) < 6 {
		return nil, false
	}
	buf := dataPayload[2:]
	// Skip TTC protocol negotiation / auth handshake packets (TTC_PRO=1, TTC_DTY=2, etc.).
	if buf[0] != 0x03 && buf[0] != 0x11 {
		return nil, false
	}

	// Single-pass case-insensitive ASCII scan without allocating bytes.ToUpper(buf).
	bestIdx := -1
	for i := 0; i < len(buf)-4; i++ {
		c := buf[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c < 'A' || c > 'Z' {
			continue
		}
		for _, starter := range oracleSQLStarters {
			if starter[0] == c && i+len(starter) <= len(buf) && equalFoldASCIIBytes(buf[i:i+len(starter)], starter) {
				bestIdx = i
				break
			}
		}
		if bestIdx >= 0 {
			break
		}
	}
	if bestIdx < 0 {
		return nil, false
	}

	end := bestIdx
	for end < len(buf) {
		b := buf[end]
		if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r' || b >= 0x80 {
			end++
		} else {
			break
		}
	}
	stmt := bytes.TrimSpace(buf[bestIdx:end])
	if len(stmt) < 6 {
		return nil, false
	}
	return stmt, true
}

func equalFoldASCIIBytes(a, upperB []byte) bool {
	for i, ub := range upperB {
		ca := a[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if ca != ub {
			return false
		}
	}
	return true
}
