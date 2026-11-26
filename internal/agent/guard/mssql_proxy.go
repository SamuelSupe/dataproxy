package guard

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"dataproxy/internal/transport"
)

// MS-TDS 7.x packet types.
const (
	tdsPacketSQLBatch      byte = 0x01
	tdsPacketRPCRequest    byte = 0x03
	tdsPacketTabularResult byte = 0x04
	tdsPacketAttention     byte = 0x06
	tdsPacketBulkLoad      byte = 0x07
	tdsPacketTransMgrReq   byte = 0x0E
	tdsPacketLogin7        byte = 0x10
	tdsPacketPreLogin      byte = 0x12

	tdsStatusEOM byte = 0x01

	tdsEncryptOff    byte = 0x00
	tdsEncryptOn     byte = 0x01
	tdsEncryptNotSup byte = 0x02
	tdsEncryptReq    byte = 0x03

	maxTDSMessageBytes = 16 * 1024 * 1024
)

// MSSQLGuardConfig configures tenant-local SQL Server (MS-TDS) read-only enforcement
// and optional LOGIN7 credential injection.
type MSSQLGuardConfig struct {
	ReadOnly     bool
	InjectCreds  bool
	UsernameSpec string
	PasswordSpec string
	TargetTLS    *tls.Config
}

func (c MSSQLGuardConfig) Enabled() bool {
	return c.ReadOnly || c.InjectCreds || c.TargetTLS != nil
}

// MSSQLProbeInfo holds metadata returned by ProbeMSSQL via a credential-free TDS PRELOGIN exchange.
type MSSQLProbeInfo struct {
	ServerVersion string
	Encryption    byte
	Latency       time.Duration
}

// ProbeMSSQL sends a standard MS-TDS PRELOGIN packet without credentials and parses the response.
func ProbeMSSQL(addr string, timeout time.Duration) (*MSSQLProbeInfo, error) {
	return ProbeMSSQLTLS(addr, timeout, nil)
}

// ProbeMSSQLTLS sends a TDS PRELOGIN packet (over optional direct TLS when tlsCfg != nil)
// to verify SQL Server reachability and extract version & encryption policy.
func ProbeMSSQLTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*MSSQLProbeInfo, error) {
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

	if err := writeTDSPackets(conn, tdsPacketPreLogin, buildTDSPreLogin(tdsEncryptNotSup)); err != nil {
		return nil, fmt.Errorf("write mssql PRELOGIN: %w", err)
	}
	pktType, payload, _, err := readTDSMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("read mssql PRELOGIN reply: %w", err)
	}
	if pktType != tdsPacketTabularResult && pktType != tdsPacketPreLogin {
		return nil, fmt.Errorf("unexpected mssql PRELOGIN reply type 0x%02x", pktType)
	}
	ver, enc := parseTDSPreLogin(payload)
	return &MSSQLProbeInfo{
		ServerVersion: ver,
		Encryption:    enc,
		Latency:       time.Since(start),
	}, nil
}

var safeTSQLSetOptions = []string{
	"NOCOUNT", "TRANSACTION", "QUOTED_IDENTIFIER", "ANSI_NULLS", "ANSI_PADDING",
	"ANSI_WARNINGS", "ANSI_NULL_DFLT_ON", "CONCAT_NULL_YIELDS_NULL", "ARITHABORT",
	"DATEFORMAT", "DATEFIRST", "LOCK_TIMEOUT", "ROWCOUNT", "TEXTSIZE", "LANGUAGE",
	"IMPLICIT_TRANSACTIONS", "XACT_ABORT", "NUMERIC_ROUNDABORT",
}

var dangerousTSQLKeywords = []string{
	"XP_CMDSHELL", "SP_CONFIGURE", "SP_OACREATE", "SP_OAMETHOD",
	"SP_ADDEXTENDEDPROC", "OPENROWSET", "OPENDATASOURCE", "OPENQUERY",
}

// IsReadOnlyTSQL enforces strict read-only T-SQL rules for SQL Server queries.
func IsReadOnlyTSQL(sql string) (bool, string) {
	bufPtr := getSQLTokens()
	defer putSQLTokens(bufPtr)
	tokens := tokenizeSQLInto(sql, *bufPtr)
	*bufPtr = tokens
	if len(tokens) == 0 {
		return true, ""
	}

	// Block multi-statement batches (except trailing semicolon) and dangerous procedures.
	for i, tok := range tokens {
		if tok == ";" && i < len(tokens)-1 {
			return false, "multi-statement T-SQL is blocked in read-only mode"
		}
		if len(tok) >= 9 {
			c0 := tok[0]
			if c0 == 'x' || c0 == 'X' || c0 == 's' || c0 == 'S' || c0 == 'o' || c0 == 'O' {
				for _, bad := range dangerousTSQLKeywords {
					if strings.EqualFold(tok, bad) {
						return false, "SQL Server privileged procedure/function " + bad + " is blocked in read-only mode"
					}
				}
			}
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
		if reason := checkForbiddenTSQLSelect(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "WITH"):
		for _, tok := range tokens[1:] {
			for _, kw := range mutatingCTEKeywords {
				if strings.EqualFold(tok, kw) {
					return false, "mutating T-SQL CTE (" + kw + ") is blocked in read-only mode"
				}
			}
		}
		if reason := checkForbiddenTSQLSelect(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "USE"):
		return true, ""

	case strings.EqualFold(first, "SET"):
		if len(tokens) >= 2 {
			for _, opt := range safeTSQLSetOptions {
				if strings.EqualFold(tokens[1], opt) {
					return true, ""
				}
			}
		}
		return false, "non-whitelisted T-SQL SET statement is blocked in read-only mode"

	case strings.EqualFold(first, "COMMIT"), strings.EqualFold(first, "ROLLBACK"):
		return true, ""

	default:
		return false, "T-SQL command " + strings.ToUpper(first) + " is blocked by tenant read-only policy"
	}
}

func checkForbiddenTSQLSelect(tokens []string) string {
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		// In T-SQL, "SELECT ... INTO <new_table>" creates and populates a table!
		if strings.EqualFold(tok, "INTO") {
			return "T-SQL SELECT ... INTO (table creation) is blocked in read-only mode"
		}
		if strings.EqualFold(tok, "UPDLOCK") || strings.EqualFold(tok, "XLOCK") || strings.EqualFold(tok, "TABLOCKX") {
			return "T-SQL exclusive locking hint " + strings.ToUpper(tok) + " is blocked in read-only mode"
		}
	}
	return checkForbiddenSelectClauses(tokens)
}

// MSSQLProxy intercepts MS-TDS traffic on the tenant agent for local LOGIN7 credential
// injection and strict read-only SQL_BATCH / RPC_REQUEST / BULK_LOAD enforcement.
type MSSQLProxy struct {
	cfg            MSSQLGuardConfig
	blockedQueries atomic.Int64
}

func NewMSSQLProxy(cfg MSSQLGuardConfig) *MSSQLProxy {
	return &MSSQLProxy{cfg: cfg}
}

func (p *MSSQLProxy) BlockedQueries() int64 {
	return p.blockedQueries.Load()
}

func (p *MSSQLProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(action, reason string),
) (bytesIn, bytesOut int64, err error) {
	if !p.cfg.ReadOnly && !p.cfg.InjectCreds {
		in2, out2 := transport.BidirectionalPipe(clientConn, serverConn)
		return in2, out2, nil
	}

	var realUser, realPass string
	if p.cfg.InjectCreds {
		realUser, err = ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			_ = writeTDSErrorResponse(clientConn, 18456, "dataproxy-agent: local mssql username resolution failed")
			return 0, 0, fmt.Errorf("resolve local mssql username: %w", err)
		}
		realPass, err = ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			_ = writeTDSErrorResponse(clientConn, 18456, "dataproxy-agent: local mssql password resolution failed")
			return 0, 0, fmt.Errorf("resolve local mssql password: %w", err)
		}
	}

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

	cmdBufPtr := transport.GetCopyBuf()
	defer transport.PutCopyBuf(cmdBufPtr)
	cmdBuf := *cmdBufPtr

	for {
		pktType, payload, rawPackets, rerr := readTDSMessageReusable(clientConn, cmdBuf)
		if rerr != nil {
			break
		}
		bytesIn += int64(len(rawPackets))

		switch pktType {
		case tdsPacketPreLogin:
			// Keep TDS plaintext inside our TLS-encrypted dataproxy tunnel so L7 inspection works.
			if rewritten, changed := setTDSPreLoginEncryption(payload, tdsEncryptNotSup); changed {
				if err := writeTDSPackets(serverConn, pktType, rewritten); err != nil {
					goto Done
				}
				continue
			}

		case tdsPacketLogin7:
			if p.cfg.InjectCreds {
				rewritten, rwErr := rewriteTDSLogin7(payload, realUser, realPass)
				if rwErr != nil {
					clientWriteMu.Lock()
					_ = writeTDSErrorResponse(clientConn, 18456, "dataproxy-agent: malformed TDS LOGIN7 packet")
					clientWriteMu.Unlock()
					goto Done
				}
				if err := writeTDSPackets(serverConn, pktType, rewritten); err != nil {
					goto Done
				}
				continue
			}

		case tdsPacketSQLBatch:
			if p.cfg.ReadOnly {
				var asciiStack [512]byte
				sqlView, isZeroAlloc := extractTDSSQLBatchView(payload, asciiStack[:])
				if ok, reason := IsReadOnlyTSQL(sqlView); !ok {
					p.blockedQueries.Add(1)
					if onBlocked != nil {
						auditSQL := sqlView
						if isZeroAlloc {
							auditSQL = strings.Clone(sqlView)
						}
						onBlocked(auditSQL, reason)
					}
					clientWriteMu.Lock()
					werr := writeTDSErrorResponse(clientConn, 229, "dataproxy-agent: "+reason)
					clientWriteMu.Unlock()
					if werr != nil {
						goto Done
					}
					continue
				}
			}

		case tdsPacketRPCRequest:
			if p.cfg.ReadOnly {
				procName, stmtSQL, allowed, reason := checkTDSRPCReadOnly(payload)
				if !allowed {
					p.blockedQueries.Add(1)
					action := procName
					if stmtSQL != "" {
						action = stmtSQL
					}
					if onBlocked != nil {
						onBlocked(action, reason)
					}
					clientWriteMu.Lock()
					werr := writeTDSErrorResponse(clientConn, 229, "dataproxy-agent: "+reason)
					clientWriteMu.Unlock()
					if werr != nil {
						goto Done
					}
					continue
				}
			}

		case tdsPacketBulkLoad:
			if p.cfg.ReadOnly {
				p.blockedQueries.Add(1)
				reason := "SQL Server BULK_LOAD is blocked by tenant read-only policy"
				if onBlocked != nil {
					onBlocked("BULK_LOAD", reason)
				}
				clientWriteMu.Lock()
				werr := writeTDSErrorResponse(clientConn, 229, "dataproxy-agent: "+reason)
				clientWriteMu.Unlock()
				if werr != nil {
					goto Done
				}
				continue
			}
		}

		if _, err := serverConn.Write(rawPackets); err != nil {
			break
		}
	}

Done:
	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

// readTDSMessageReusable reads a TDS message into scratch with zero heap allocations on
// the common single-packet (EOM) fast path, falling back to multi-packet assembly when needed.
func readTDSMessageReusable(r io.Reader, scratch []byte) (pktType byte, payload, rawPackets []byte, err error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, nil, err
	}
	pLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if pLen < 8 {
		return 0, nil, nil, fmt.Errorf("invalid TDS packet length %d", pLen)
	}
	pktType = hdr[0]
	// Fast path: single-packet EOM fitting inside connection-scoped 64KiB pooled buffer (0 allocs!).
	if (hdr[1]&tdsStatusEOM) != 0 && pLen <= len(scratch) {
		rawPackets = scratch[:pLen]
		copy(rawPackets[:8], hdr[:])
		payload = rawPackets[8:pLen]
		if len(payload) > 0 {
			if _, err := io.ReadFull(r, payload); err != nil {
				return 0, nil, nil, err
			}
		}
		return pktType, payload, rawPackets, nil
	}

	// Multi-packet or oversized path.
	chunk := make([]byte, pLen-8)
	if len(chunk) > 0 {
		if _, err := io.ReadFull(r, chunk); err != nil {
			return 0, nil, nil, err
		}
	}
	rawPackets = make([]byte, 0, pLen)
	rawPackets = append(rawPackets, hdr[:]...)
	rawPackets = append(rawPackets, chunk...)
	payload = append(payload, chunk...)
	if (hdr[1] & tdsStatusEOM) != 0 {
		return pktType, payload, rawPackets, nil
	}
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return 0, nil, nil, err
		}
		pLen = int(binary.BigEndian.Uint16(hdr[2:4]))
		if pLen < 8 {
			return 0, nil, nil, fmt.Errorf("invalid TDS packet length %d", pLen)
		}
		if len(payload)+(pLen-8) > maxTDSMessageBytes {
			return 0, nil, nil, errors.New("TDS message exceeds 16MiB safety limit")
		}
		chunk = make([]byte, pLen-8)
		if len(chunk) > 0 {
			if _, err := io.ReadFull(r, chunk); err != nil {
				return 0, nil, nil, err
			}
		}
		rawPackets = append(rawPackets, hdr[:]...)
		rawPackets = append(rawPackets, chunk...)
		payload = append(payload, chunk...)
		if (hdr[1] & tdsStatusEOM) != 0 {
			return pktType, payload, rawPackets, nil
		}
	}
}

// readTDSMessage reads one complete TDS message (1 or more 8B-header packets until EOM).
func readTDSMessage(r io.Reader) (pktType byte, payload, rawPackets []byte, err error) {
	return readTDSMessageReusable(r, nil)
}

func writeTDSPackets(w io.Writer, pktType byte, payload []byte) error {
	const maxChunk = 4096 - 8
	if len(payload) == 0 {
		hdr := [8]byte{pktType, tdsStatusEOM, 0, 8, 0, 0, 1, 0}
		_, err := w.Write(hdr[:])
		return err
	}
	pktID := byte(1)
	for off := 0; off < len(payload); {
		end := off + maxChunk
		status := byte(0x00)
		if end >= len(payload) {
			end = len(payload)
			status = tdsStatusEOM
		}
		chunk := payload[off:end]
		total := 8 + len(chunk)
		buf := make([]byte, total)
		buf[0] = pktType
		buf[1] = status
		binary.BigEndian.PutUint16(buf[2:4], uint16(total))
		buf[6] = pktID
		copy(buf[8:], chunk)
		if _, err := w.Write(buf); err != nil {
			return err
		}
		pktID++
		off = end
	}
	return nil
}

// writeTDSErrorResponse sends a standard MS-TDS TABULAR_RESULT containing ERROR (0xAA) + DONE (0xFD).
func writeTDSErrorResponse(w io.Writer, errNum int32, msg string) error {
	msgU16 := encodeUTF16LE(msg)
	srvU16 := encodeUTF16LE("dataproxy-agent")

	var errTok bytes.Buffer
	errTok.WriteByte(0xAA) // ERROR token
	// Token length: Number(4) + State(1) + Class(1) + MsgLen(2) + Msg + SrvLen(1) + Srv + ProcLen(1) + Line(4)
	tokLen := 4 + 1 + 1 + 2 + len(msgU16) + 1 + len(srvU16) + 1 + 4
	_ = binary.Write(&errTok, binary.LittleEndian, uint16(tokLen))
	_ = binary.Write(&errTok, binary.LittleEndian, errNum)
	errTok.WriteByte(1)  // state
	errTok.WriteByte(16) // class/severity (user error)
	_ = binary.Write(&errTok, binary.LittleEndian, uint16(len(msgU16)/2))
	errTok.Write(msgU16)
	errTok.WriteByte(byte(len(srvU16) / 2))
	errTok.Write(srvU16)
	errTok.WriteByte(0) // proc name len = 0
	_ = binary.Write(&errTok, binary.LittleEndian, int32(1))

	// DONE token (0xFD): Status(2)=DONE_ERROR(0x0002), CurCmd(2)=0, DoneRowCount(8)=0
	errTok.WriteByte(0xFD)
	_ = binary.Write(&errTok, binary.LittleEndian, uint16(0x0002))
	_ = binary.Write(&errTok, binary.LittleEndian, uint16(0))
	_ = binary.Write(&errTok, binary.LittleEndian, uint64(0))

	return writeTDSPackets(w, tdsPacketTabularResult, errTok.Bytes())
}

func buildTDSPreLogin(enc byte) []byte {
	// Options: VERSION (0x00, 6 bytes), ENCRYPTION (0x01, 1 byte), TERMINATOR (0xFF)
	// Header: 2*5 + 1 = 11 bytes
	buf := make([]byte, 11+6+1)
	buf[0] = 0x00
	binary.BigEndian.PutUint16(buf[1:3], 11)
	binary.BigEndian.PutUint16(buf[3:5], 6)
	buf[5] = 0x01
	binary.BigEndian.PutUint16(buf[6:8], 17)
	binary.BigEndian.PutUint16(buf[8:10], 1)
	buf[10] = 0xFF
	// Version 15.0.0.0
	buf[11] = 15
	buf[17] = enc
	return buf
}

func parseTDSPreLogin(payload []byte) (version string, encryption byte) {
	encryption = tdsEncryptNotSup
	for i := 0; i < len(payload); {
		opt := payload[i]
		if opt == 0xFF {
			break
		}
		if i+5 > len(payload) {
			break
		}
		off := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		i += 5
		if off+length > len(payload) {
			continue
		}
		switch opt {
		case 0x00: // VERSION: major(1), minor(1), build(2), subbuild(2)
			if length >= 4 {
				build := binary.BigEndian.Uint16(payload[off+2 : off+4])
				version = fmt.Sprintf("%d.%d.%d", payload[off], payload[off+1], build)
			}
		case 0x01: // ENCRYPTION
			if length >= 1 {
				encryption = payload[off]
			}
		}
	}
	return version, encryption
}

func setTDSPreLoginEncryption(payload []byte, targetEnc byte) ([]byte, bool) {
	out := append([]byte(nil), payload...)
	for i := 0; i < len(out); {
		opt := out[i]
		if opt == 0xFF {
			break
		}
		if i+5 > len(out) {
			break
		}
		off := int(binary.BigEndian.Uint16(out[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(out[i+3 : i+5]))
		i += 5
		if opt == 0x01 && length >= 1 && off < len(out) {
			if out[off] != targetEnc {
				out[off] = targetEnc
				return out, true
			}
			return out, false
		}
	}
	return out, false
}

// rewriteTDSLogin7 replaces UTF-16LE username and TDS-obfuscated password in a LOGIN7 packet.
func rewriteTDSLogin7(payload []byte, realUser, realPass string) ([]byte, error) {
	// LOGIN7 fixed header is at least 86 bytes (36B base + offset/len pairs up to offset 86).
	if len(payload) < 86 {
		return nil, errors.New("LOGIN7 payload too short")
	}
	userBytes := encodeUTF16LE(realUser)
	passBytes := obfuscateTDSPassword(encodeUTF16LE(realPass))

	// Append new user & password at the end of payload and update ibUserName/cchUserName (offsets 40..44)
	// and ibPassword/cchPassword (offsets 44..48). This avoids shifting any other offset fields!
	out := make([]byte, len(payload)+len(userBytes)+len(passBytes))
	copy(out, payload)

	userOff := len(payload)
	copy(out[userOff:], userBytes)
	passOff := userOff + len(userBytes)
	copy(out[passOff:], passBytes)

	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	binary.LittleEndian.PutUint16(out[40:42], uint16(userOff))
	binary.LittleEndian.PutUint16(out[42:44], uint16(len(userBytes)/2))
	binary.LittleEndian.PutUint16(out[44:46], uint16(passOff))
	binary.LittleEndian.PutUint16(out[46:48], uint16(len(passBytes)/2))
	return out, nil
}

func obfuscateTDSPassword(u16 []byte) []byte {
	out := make([]byte, len(u16))
	for i, b := range u16 {
		out[i] = ((b << 4) | (b >> 4)) ^ 0xA5
	}
	return out
}

func extractTDSSQLBatchText(payload []byte) string {
	sqlBytes := stripTDSAllHeaders(payload)
	return decodeUTF16LE(sqlBytes)
}

// extractTDSSQLBatchView decodes pure-ASCII UTF-16LE SQL into scratch with zero heap allocations,
// falling back to full UTF-16LE decoding if non-ASCII runes or oversized queries are encountered.
func extractTDSSQLBatchView(payload []byte, scratch []byte) (string, bool) {
	sqlBytes := stripTDSAllHeaders(payload)
	n := len(sqlBytes) / 2
	if n == 0 {
		return "", true
	}
	if n <= len(scratch) {
		for i := 0; i < n; i++ {
			if sqlBytes[i*2+1] != 0 || sqlBytes[i*2] >= 0x80 {
				return decodeUTF16LE(sqlBytes), false
			}
			scratch[i] = sqlBytes[i*2]
		}
		return unsafe.String(unsafe.SliceData(scratch), n), true
	}
	return decodeUTF16LE(sqlBytes), false
}

func stripTDSAllHeaders(payload []byte) []byte {
	if len(payload) >= 4 {
		totalHdrLen := int(binary.LittleEndian.Uint32(payload[0:4]))
		// Validate ALL_HEADERS framing: minimum valid header is 10 bytes (4B total + 4B len + 2B type).
		if totalHdrLen >= 10 && totalHdrLen <= len(payload) {
			subLen := int(binary.LittleEndian.Uint32(payload[4:8]))
			subType := binary.LittleEndian.Uint16(payload[8:10])
			if subLen >= 6 && subLen <= totalHdrLen-4 && (subType == 1 || subType == 2 || subType == 3) {
				return payload[totalHdrLen:]
			}
		}
	}
	return payload
}

// checkTDSRPCReadOnly parses an MS-TDS RPC_REQUEST (0x03) packet.
func checkTDSRPCReadOnly(payload []byte) (procName, sqlText string, allowed bool, reason string) {
	body := stripTDSAllHeaders(payload)
	if len(body) < 4 {
		return "RPC", "", false, "malformed SQL Server RPC_REQUEST blocked in read-only mode"
	}
	nameLen := binary.LittleEndian.Uint16(body[0:2])
	pos := 2
	var procID uint16
	if nameLen == 0xFFFF {
		if pos+2 > len(body) {
			return "RPC", "", false, "truncated SQL Server RPC ProcID"
		}
		procID = binary.LittleEndian.Uint16(body[pos : pos+2])
		pos += 2
		procName = tdsProcIDName(procID)
	} else {
		byteLen := int(nameLen) * 2
		if pos+byteLen > len(body) {
			return "RPC", "", false, "truncated SQL Server RPC procedure name"
		}
		procName = decodeUTF16LE(body[pos : pos+byteLen])
		pos += byteLen
	}
	// Skip 2-byte OptionFlags.
	if pos+2 > len(body) {
		return procName, "", false, "truncated SQL Server RPC flags"
	}
	pos += 2

	lowerProc := strings.ToLower(strings.TrimSpace(procName))
	// Benign cursor/prepared lifecycle RPCs that carry no new SQL.
	switch lowerProc {
	case "sp_execute", "sp_unprepare", "sp_cursorfetch", "sp_cursorclose", "sp_cursorunprepare", "sp_reset_connection":
		return procName, "", true, ""
	}

	// Dynamic SQL execution RPCs: extract the SQL string parameter and validate with IsReadOnlyTSQL!
	if lowerProc == "sp_executesql" || lowerProc == "sp_prepare" || lowerProc == "sp_prepexec" {
		extracted, ok := extractFirstNVarcharParam(body[pos:])
		if !ok {
			return procName, "", false, "unable to inspect SQL inside " + procName + " in read-only mode"
		}
		if ro, why := IsReadOnlyTSQL(extracted); !ro {
			return procName, extracted, false, why
		}
		return procName, extracted, true, ""
	}

	return procName, "", false, "SQL Server stored procedure RPC '" + procName + "' is blocked by tenant read-only policy"
}

func tdsProcIDName(id uint16) string {
	switch id {
	case 1:
		return "sp_cursor"
	case 2:
		return "sp_cursoropen"
	case 3:
		return "sp_cursorprepare"
	case 4:
		return "sp_cursorexecute"
	case 5:
		return "sp_cursorprepexec"
	case 6:
		return "sp_cursorunprepare"
	case 7:
		return "sp_cursorfetch"
	case 8:
		return "sp_cursoroption"
	case 9:
		return "sp_cursorclose"
	case 10:
		return "sp_executesql"
	case 11:
		return "sp_prepare"
	case 12:
		return "sp_execute"
	case 13:
		return "sp_prepexec"
	case 14:
		return "sp_prepexecrpc"
	case 15:
		return "sp_unprepare"
	default:
		return fmt.Sprintf("proc_id_%d", id)
	}
}

// extractFirstNVarcharParam locates the first NVARCHAR (0xE7) SQL parameter in a TDS RPC parameter stream.
func extractFirstNVarcharParam(params []byte) (string, bool) {
	pos := 0
	for paramIdx := 0; paramIdx < 4 && pos < len(params); paramIdx++ {
		nameChars := int(params[pos])
		pos += 1 + nameChars*2
		if pos+2 > len(params) {
			return "", false
		}
		pos++ // StatusFlags
		dataType := params[pos]
		pos++

		switch dataType {
		case 0x26: // INTN (e.g. handle output param of sp_prepare/sp_prepexec)
			if pos+1 > len(params) {
				return "", false
			}
			pos++ // maxLen
			if pos >= len(params) {
				return "", false
			}
			valLen := int(params[pos])
			pos += 1 + valLen

		case 0xE7, 0xEF: // NVARCHARTYPE / NCHARTYPE
			// TypeInfo: MaxLen(2) + Collation(5) = 7 bytes
			if pos+7 > len(params) {
				return "", false
			}
			maxLen := binary.LittleEndian.Uint16(params[pos : pos+2])
			pos += 7
			if maxLen == 0xFFFF {
				// PLP (Partially Length-Prefixed) NVARCHAR(MAX): TotalLen(8) + ChunkLen(4) + ChunkBytes...
				if pos+12 > len(params) {
					return "", false
				}
				pos += 8
				var sqlBytes []byte
				for pos+4 <= len(params) {
					chunkLen := int(binary.LittleEndian.Uint32(params[pos : pos+4]))
					pos += 4
					if chunkLen == 0 {
						break
					}
					if pos+chunkLen > len(params) {
						return "", false
					}
					sqlBytes = append(sqlBytes, params[pos:pos+chunkLen]...)
					pos += chunkLen
				}
				return decodeUTF16LE(sqlBytes), true
			}
			if pos+2 > len(params) {
				return "", false
			}
			valLen := int(binary.LittleEndian.Uint16(params[pos : pos+2]))
			pos += 2
			if valLen == 0xFFFF || pos+valLen > len(params) {
				return "", false
			}
			return decodeUTF16LE(params[pos : pos+valLen]), true

		default:
			return "", false
		}
	}
	return "", false
}

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], v)
	}
	return out
}

func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u))
}
