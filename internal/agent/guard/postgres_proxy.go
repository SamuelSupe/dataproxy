package guard

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/transport"
)

const (
	pgSSLRequestCode uint32 = 80877103 // 0x04d2162f
	pgProtocolV3     uint32 = 196608   // 0x00030000
)

// PostgresGuardConfig configures tenant-local PostgreSQL v3 security policies and Split-TLS.
type PostgresGuardConfig struct {
	ReadOnly     bool
	InjectCreds  bool
	UsernameSpec string
	PasswordSpec string
	TargetTLS    *tls.Config // Optional Split-TLS upgrade via PostgreSQL SSLRequest STARTTLS
}

func (c PostgresGuardConfig) Enabled() bool {
	return c.ReadOnly || c.InjectCreds || c.TargetTLS != nil
}

// PostgresProbeInfo holds metadata returned by ProbePostgres / ProbePostgresTLS.
type PostgresProbeInfo struct {
	SupportsSSL    bool
	TLSHandshakeOK bool
	Latency        time.Duration
}

// ProbePostgres checks PostgreSQL reachability without credentials by sending
// a standard 8-byte SSLRequest and reading the 1-byte 'S'/'N' server reply.
func ProbePostgres(addr string, timeout time.Duration) (*PostgresProbeInfo, error) {
	return ProbePostgresTLS(addr, timeout, nil)
}

// ProbePostgresTLS checks PostgreSQL reachability and, when tlsCfg != nil, performs
// the full PostgreSQL SSLRequest -> 'S' -> TLS Handshake verification.
func ProbePostgresTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*PostgresProbeInfo, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], pgSSLRequestCode)
	if _, err := conn.Write(req[:]); err != nil {
		return nil, fmt.Errorf("write pg SSLRequest: %w", err)
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return nil, fmt.Errorf("read pg SSLRequest reply: %w", err)
	}
	switch resp[0] {
	case 'S':
		info := &PostgresProbeInfo{SupportsSSL: true}
		if tlsCfg != nil {
			tlsConn := tls.Client(conn, tlsCfg.Clone())
			if err := tlsConn.Handshake(); err != nil {
				return nil, fmt.Errorf("postgres TLS handshake failed: %w", err)
			}
			info.TLSHandshakeOK = true
		}
		info.Latency = time.Since(start)
		return info, nil
	case 'N':
		if tlsCfg != nil {
			return nil, errors.New("postgres server refused SSLRequest ('N') while target_tls is enabled")
		}
		return &PostgresProbeInfo{SupportsSSL: false, Latency: time.Since(start)}, nil
	default:
		return nil, fmt.Errorf("unexpected response byte 0x%02x (not a PostgreSQL v3 server)", resp[0])
	}
}

var pgDangerousFuncs = []string{
	"PG_TERMINATE_BACKEND",
	"PG_CANCEL_BACKEND",
	"PG_RELOAD_CONF",
	"PG_ROTATE_LOGFILE",
	"PG_READ_FILE",
	"PG_READ_BINARY_FILE",
	"PG_WRITE_FILE",
	"PG_LS_DIR",
	"LO_IMPORT",
	"LO_EXPORT",
	"DBLINK_EXEC",
}

var safePGSetParams = []string{
	"client_encoding",
	"timezone",
	"time", // SET TIME ZONE
	"datestyle",
	"extra_float_digits",
	"search_path",
	"statement_timeout",
	"application_name",
	"standard_conforming_strings",
	"bytea_output",
	"intervalstyle",
	"default_transaction_read_only",
	"transaction",
}

// IsReadOnlyPGSQL extends IsReadOnlySQL with PostgreSQL-specific safety checks
// (blocks COPY, DO blocks, dangerous admin functions, and mutating CTEs) using a
// single pooled tokenization pass with zero heap allocations on allowed queries.
func IsReadOnlyPGSQL(sql string) (bool, string) {
	bufPtr := getSQLTokens()
	defer putSQLTokens(bufPtr)
	tokens := tokenizeSQLInto(sql, *bufPtr)
	*bufPtr = tokens
	if len(tokens) == 0 {
		return true, ""
	}

	// Check PG-specific dangerous built-in functions anywhere in the statement.
	for _, tok := range tokens {
		sub := tok
		if idx := strings.LastIndexByte(sub, '.'); idx >= 0 {
			sub = sub[idx+1:]
		}
		if len(sub) >= 9 {
			c0 := sub[0]
			if c0 == 'p' || c0 == 'P' || c0 == 'l' || c0 == 'L' || c0 == 'd' || c0 == 'D' {
				for _, fn := range pgDangerousFuncs {
					if strings.EqualFold(sub, fn) {
						return false, "PostgreSQL privileged function " + fn + " is blocked in read-only mode"
					}
				}
			}
		}
	}

	first := tokens[0]
	// Allow PG "BEGIN READ ONLY" / "SET ..." safe session setup.
	if strings.EqualFold(first, "BEGIN") {
		hasReadOnly := false
		for i := 1; i+1 < len(tokens); i++ {
			if strings.EqualFold(tokens[i], "READ") && strings.EqualFold(tokens[i+1], "ONLY") {
				hasReadOnly = true
			}
			if strings.EqualFold(tokens[i], "READ") && strings.EqualFold(tokens[i+1], "WRITE") {
				return false, "read-write BEGIN transaction is blocked in read-only mode"
			}
		}
		if hasReadOnly {
			return true, ""
		}
		return false, "BEGIN without READ ONLY is blocked in read-only mode"
	}
	if strings.EqualFold(first, "SET") {
		if len(tokens) >= 2 {
			param := tokens[1]
			if strings.EqualFold(param, "SESSION") && len(tokens) >= 3 {
				param = tokens[2]
			}
			isSafe := false
			for _, sp := range safePGSetParams {
				if strings.EqualFold(param, sp) {
					isSafe = true
					break
				}
			}
			if isSafe {
				isReadOnlyParam := strings.EqualFold(param, "default_transaction_read_only")
				for _, t := range tokens {
					if strings.EqualFold(t, "WRITE") || (isReadOnlyParam && strings.EqualFold(t, "OFF")) {
						return false, "disabling read-only mode via SET is blocked"
					}
				}
				return true, ""
			}
		}
	}

	return isReadOnlySQLTokens(tokens)
}

// PostgresProxy intercepts PostgreSQL v3 connections for local credential injection
// and/or strict SQL read-only enforcement.
type PostgresProxy struct {
	cfg            PostgresGuardConfig
	blockedQueries atomic.Int64
}

func NewPostgresProxy(cfg PostgresGuardConfig) *PostgresProxy {
	return &PostgresProxy{cfg: cfg}
}

func (p *PostgresProxy) BlockedQueries() int64 {
	return p.blockedQueries.Load()
}

func (p *PostgresProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(msgType byte, sql, reason string),
) (bytesIn, bytesOut int64, err error) {
	// 1. Handle optional SSLRequest / GSSENCRequest followed by StartupMessage.
	var startupBody []byte
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
			return 0, 0, fmt.Errorf("read pg startup length: %w", err)
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen < 8 || msgLen > 64*1024 {
			return 0, 0, fmt.Errorf("invalid pg startup length %d", msgLen)
		}
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(clientConn, body); err != nil {
			return 0, 0, fmt.Errorf("read pg startup body: %w", err)
		}
		bytesIn += int64(msgLen)

		code := binary.BigEndian.Uint32(body[0:4])
		if code == pgSSLRequestCode || code == 80877104 { // SSLRequest or GSSENCRequest
			// Reject TLS/GSS upgrade inside tunnel (tunnel is already encrypted) so agent can inspect/inject.
			if _, err := clientConn.Write([]byte{'N'}); err != nil {
				return bytesIn, bytesOut, err
			}
			bytesOut++
			continue
		}
		if code != pgProtocolV3 {
			// CancelRequest (80877102) or other special startup: forward directly.
			if err := writePGStartup(serverConn, body); err != nil {
				return bytesIn, bytesOut, err
			}
			return bytesIn, bytesOut, nil
		}
		startupBody = body
		break
	}

	// 2. Rewrite StartupMessage username if credential injection is enabled.
	var realUser, realPass string
	if p.cfg.InjectCreds {
		realUser, err = ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			_ = writePGError(clientConn, "28P01", "dataproxy-agent: local postgres username resolution failed")
			return bytesIn, bytesOut, err
		}
		realPass, err = ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			_ = writePGError(clientConn, "28P01", "dataproxy-agent: local postgres password resolution failed")
			return bytesIn, bytesOut, err
		}
		startupBody = rewritePGStartupUser(startupBody, realUser)
	}

	// 2.5 Optional Split-TLS upgrade (PostgreSQL SSLRequest -> 'S' -> TLS Handshake) toward tenant PostgreSQL/RDS.
	if p.cfg.TargetTLS != nil {
		var sslReq [8]byte
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], pgSSLRequestCode)
		if _, err := serverConn.Write(sslReq[:]); err != nil {
			return bytesIn, bytesOut, fmt.Errorf("write pg SSLRequest to server: %w", err)
		}
		var sslReply [1]byte
		if _, err := io.ReadFull(serverConn, sslReply[:]); err != nil {
			return bytesIn, bytesOut, fmt.Errorf("read pg SSLRequest reply from server: %w", err)
		}
		if sslReply[0] != 'S' {
			_ = writePGError(clientConn, "08006", "dataproxy-agent: target PostgreSQL refused SSLRequest while target_tls is enabled")
			return bytesIn, bytesOut, fmt.Errorf("postgres target refused SSLRequest (got 0x%02x)", sslReply[0])
		}
		tlsConn := tls.Client(serverConn, p.cfg.TargetTLS.Clone())
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = writePGError(clientConn, "08006", "dataproxy-agent: TLS handshake with target PostgreSQL failed")
			return bytesIn, bytesOut, fmt.Errorf("postgres target TLS handshake failed: %w", err)
		}
		_ = tlsConn.SetDeadline(time.Time{})
		serverConn = tlsConn
	}

	if err := writePGStartup(serverConn, startupBody); err != nil {
		return bytesIn, bytesOut, fmt.Errorf("write pg startup to server: %w", err)
	}

	// 3. Authentication phase: handle Cleartext, MD5, and SCRAM-SHA-256 locally when InjectCreds=true.
	var scram *scramClient
	for {
		mType, payload, err := readPGMsg(serverConn)
		if err != nil {
			return bytesIn, bytesOut, fmt.Errorf("read pg auth msg: %w", err)
		}
		bytesOut += int64(len(payload) + 5)

		if mType == 'E' {
			_ = writePGMsg(clientConn, mType, payload)
			return bytesIn, bytesOut, nil
		}

		if mType == 'R' && len(payload) >= 4 {
			authCode := binary.BigEndian.Uint32(payload[0:4])
			if authCode == 0 {
				// AuthenticationOk -> forward to client and proceed to startup completion / command phase!
				if err := writePGMsg(clientConn, mType, payload); err != nil {
					return bytesIn, bytesOut, err
				}
				break
			}

			if p.cfg.InjectCreds {
				switch authCode {
				case 3: // AuthenticationCleartextPassword
					if err := writePGMsg(serverConn, 'p', append([]byte(realPass), 0x00)); err != nil {
						return bytesIn, bytesOut, err
					}
					continue

				case 5: // AuthenticationMD5Password
					if len(payload) < 8 {
						return bytesIn, bytesOut, errors.New("truncated pg md5 salt")
					}
					resp := computePGMD5(realUser, realPass, payload[4:8])
					if err := writePGMsg(serverConn, 'p', append([]byte(resp), 0x00)); err != nil {
						return bytesIn, bytesOut, err
					}
					continue

				case 10: // AuthenticationSASL (PG 16 default: SCRAM-SHA-256)
					if !bytes.Contains(payload[4:], []byte("SCRAM-SHA-256")) {
						_ = writePGError(clientConn, "0A000", "dataproxy-agent: server does not offer SCRAM-SHA-256")
						return bytesIn, bytesOut, errors.New("unsupported pg SASL mechanism")
					}
					scram, err = newSCRAMSHA256Client(realUser, realPass)
					if err != nil {
						return bytesIn, bytesOut, err
					}
					firstMsg := scram.ClientFirstMessage()
					var saslInit bytes.Buffer
					saslInit.WriteString("SCRAM-SHA-256")
					saslInit.WriteByte(0x00)
					var l [4]byte
					binary.BigEndian.PutUint32(l[:], uint32(len(firstMsg)))
					saslInit.Write(l[:])
					saslInit.WriteString(firstMsg)
					if err := writePGMsg(serverConn, 'p', saslInit.Bytes()); err != nil {
						return bytesIn, bytesOut, err
					}
					continue

				case 11: // AuthenticationSASLContinue
					if scram == nil {
						return bytesIn, bytesOut, errors.New("unexpected SASLContinue without SCRAM state")
					}
					clientFinal, err := scram.ProcessServerFirst(string(payload[4:]))
					if err != nil {
						_ = writePGError(clientConn, "28P01", "dataproxy-agent: SCRAM handshake error")
						return bytesIn, bytesOut, err
					}
					if err := writePGMsg(serverConn, 'p', []byte(clientFinal)); err != nil {
						return bytesIn, bytesOut, err
					}
					continue

				case 12: // AuthenticationSASLFinal
					if scram != nil {
						if err := scram.VerifyServerFinal(string(payload[4:])); err != nil {
							_ = writePGError(clientConn, "28P01", "dataproxy-agent: SCRAM server verification failed")
							return bytesIn, bytesOut, err
						}
					}
					// Next message from server will be AuthenticationOk ('R', 0).
					continue
				}
			}

			// Transparent auth relay when InjectCreds=false
			if err := writePGMsg(clientConn, mType, payload); err != nil {
				return bytesIn, bytesOut, err
			}
			// Read client's password/SASL response ('p') and forward to server
			if authCode != 12 {
				cType, cPayload, err := readPGMsg(clientConn)
				if err != nil {
					return bytesIn, bytesOut, err
				}
				bytesIn += int64(len(cPayload) + 5)
				if err := writePGMsg(serverConn, cType, cPayload); err != nil {
					return bytesIn, bytesOut, err
				}
			}
			continue
		}

		// Relay any other server message (ParameterStatus, BackendKeyData, etc.)
		if err := writePGMsg(clientConn, mType, payload); err != nil {
			return bytesIn, bytesOut, err
		}
		if mType == 'Z' {
			break
		}
	}

	// 4. If only credential injection was enabled, switch to zero-copy pipe!
	if !p.cfg.ReadOnly {
		in2, out2 := transport.BidirectionalPipe(clientConn, serverConn)
		return bytesIn + in2, bytesOut + out2, nil
	}

	// 5. Read-Only Command Phase: inspect every client message ('Q', 'P', Copy*).
	var clientWriteMu sync.Mutex
	var serverCopyBytes atomic.Int64
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
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

	skipUntilSync := false
	var blockedReason string

	for {
		cType, cPayload, err := readPGMsg(clientConn)
		if err != nil {
			break
		}
		bytesIn += int64(len(cPayload) + 5)

		if skipUntilSync {
			if cType == 'S' { // Sync ends extended query pipeline
				clientWriteMu.Lock()
				_ = writePGError(clientConn, "25006", "dataproxy-agent: "+blockedReason)
				_ = writePGMsg(clientConn, 'Z', []byte{'I'}) // ReadyForQuery (Idle)
				clientWriteMu.Unlock()
				skipUntilSync = false
				blockedReason = ""
			}
			continue
		}

		switch cType {
		case 'Q': // Simple Query: payload is NUL-terminated SQL
			sqlText := string(bytes.TrimRight(cPayload, "\x00"))
			if ok, reason := IsReadOnlyPGSQL(sqlText); !ok {
				p.blockedQueries.Add(1)
				if onBlocked != nil {
					onBlocked(cType, sqlText, reason)
				}
				clientWriteMu.Lock()
				_ = writePGError(clientConn, "25006", "dataproxy-agent: "+reason)
				_ = writePGMsg(clientConn, 'Z', []byte{'I'}) // ReadyForQuery (Idle)
				clientWriteMu.Unlock()
				continue
			}

		case 'P': // Extended Query Parse: stmtName\0query\0numParams(2B)...
			firstNul := bytes.IndexByte(cPayload, 0x00)
			if firstNul >= 0 && firstNul+1 < len(cPayload) {
				rest := cPayload[firstNul+1:]
				secondNul := bytes.IndexByte(rest, 0x00)
				if secondNul >= 0 {
					sqlText := string(rest[:secondNul])
					if ok, reason := IsReadOnlyPGSQL(sqlText); !ok {
						p.blockedQueries.Add(1)
						if onBlocked != nil {
							onBlocked(cType, sqlText, reason)
						}
						skipUntilSync = true
						blockedReason = reason
						continue
					}
				}
			}

		case 'd', 'c', 'f': // CopyData / CopyDone / CopyFail
			p.blockedQueries.Add(1)
			if onBlocked != nil {
				onBlocked(cType, "", "COPY stream is blocked in read-only mode")
			}
			clientWriteMu.Lock()
			_ = writePGError(clientConn, "25006", "dataproxy-agent: COPY stream is blocked in read-only mode")
			_ = writePGMsg(clientConn, 'Z', []byte{'I'})
			clientWriteMu.Unlock()
			continue
		}

		if err := writePGMsg(serverConn, cType, cPayload); err != nil {
			break
		}
		if cType == 'X' { // Terminate
			break
		}
	}

	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

func rewritePGStartupUser(body []byte, realUser string) []byte {
	if len(body) <= 4 {
		return body
	}
	var out bytes.Buffer
	out.Write(body[0:4]) // protocol version 3.0

	params := body[4:]
	pos := 0
	replaced := false
	for pos < len(params) {
		if params[pos] == 0x00 {
			break
		}
		kEnd := bytes.IndexByte(params[pos:], 0x00)
		if kEnd < 0 {
			break
		}
		key := string(params[pos : pos+kEnd])
		pos += kEnd + 1
		if pos >= len(params) {
			break
		}
		vEnd := bytes.IndexByte(params[pos:], 0x00)
		if vEnd < 0 {
			break
		}
		val := string(params[pos : pos+vEnd])
		pos += vEnd + 1

		if key == "user" {
			val = realUser
			replaced = true
		}
		out.WriteString(key)
		out.WriteByte(0x00)
		out.WriteString(val)
		out.WriteByte(0x00)
	}
	if !replaced {
		out.WriteString("user")
		out.WriteByte(0x00)
		out.WriteString(realUser)
		out.WriteByte(0x00)
	}
	out.WriteByte(0x00) // terminator
	return out.Bytes()
}

func computePGMD5(user, password string, salt []byte) string {
	h1 := md5.Sum([]byte(password + user))
	h1Hex := hex.EncodeToString(h1[:])
	h2 := md5.Sum(append([]byte(h1Hex), salt...))
	return "md5" + hex.EncodeToString(h2[:])
}

func readPGMsg(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > 64*1024*1024 {
		return 0, nil, fmt.Errorf("invalid pg message length %d", length)
	}
	payload := make([]byte, length-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}

func writePGMsg(w io.Writer, msgType byte, payload []byte) error {
	total := 5 + len(payload)
	if total <= transport.CopyBufferSize {
		bufPtr := transport.GetCopyBuf()
		buf := (*bufPtr)[:total]
		buf[0] = msgType
		binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
		copy(buf[5:], payload)
		_, err := w.Write(buf)
		transport.PutCopyBuf(bufPtr)
		return err
	}
	buf := make([]byte, total)
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

func writePGStartup(w io.Writer, body []byte) error {
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(body)+4))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

func writePGError(w io.Writer, sqlState, msg string) error {
	var p bytes.Buffer
	p.WriteByte('S')
	p.WriteString("ERROR")
	p.WriteByte(0)
	p.WriteByte('V')
	p.WriteString("ERROR")
	p.WriteByte(0)
	p.WriteByte('C')
	p.WriteString(sqlState)
	p.WriteByte(0)
	p.WriteByte('M')
	p.WriteString(msg)
	p.WriteByte(0)
	p.WriteByte(0) // terminator
	return writePGMsg(w, 'E', p.Bytes())
}
