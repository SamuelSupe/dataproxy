package guard

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"dataproxy/internal/transport"
)

// MySQL capability flags (MySQL Internals Protocol v10).
const (
	capClientLongPassword               uint32 = 0x00000001
	capClientConnectWithDB              uint32 = 0x00000008
	capClientCompress                   uint32 = 0x00000020
	capClientProtocol41                 uint32 = 0x00000200
	capClientSSL                        uint32 = 0x00000800
	capClientSecureConnection           uint32 = 0x00008000
	capClientMultiStatements            uint32 = 0x00010000
	capClientPluginAuth                 uint32 = 0x00080000
	capClientConnectAttrs               uint32 = 0x00100000
	capClientPluginAuthLenencClientData uint32 = 0x00200000
	capClientZstdCompression            uint32 = 0x04000000
	capClientQueryAttributes            uint32 = 0x08000000
)

// MySQL command phase bytes.
const (
	comQuit            byte = 0x01
	comInitDB          byte = 0x02
	comQuery           byte = 0x03
	comFieldList       byte = 0x04
	comStatistics      byte = 0x09
	comPing            byte = 0x0e
	comStmtPrepare     byte = 0x16
	comStmtExecute     byte = 0x17
	comStmtSendLong    byte = 0x18
	comStmtClose       byte = 0x19
	comStmtReset       byte = 0x1a
	comStmtFetch       byte = 0x1c
	comResetConnection byte = 0x1f
)

// MySQLGuardConfig configures tenant-local MySQL read-only enforcement, credential injection,
// and optional Split-TLS (MySQL SSLRequest STARTTLS upgrade toward tenant MySQL/RDS).
type MySQLGuardConfig struct {
	ReadOnly     bool
	InjectCreds  bool
	UsernameSpec string      // Supports literal, env:VAR, file:/path
	PasswordSpec string      // Supports literal, env:VAR, file:/path
	TargetTLS    *tls.Config // Optional Split-TLS upgrade toward local MySQL/RDS
}

// Enabled reports whether MySQL wire-protocol interception is needed.
func (c MySQLGuardConfig) Enabled() bool {
	return c.ReadOnly || c.InjectCreds || c.TargetTLS != nil
}

// MySQLProbeInfo holds metadata extracted from a MySQL server's Initial Handshake Packet.
type MySQLProbeInfo struct {
	ProtocolVersion byte
	ServerVersion   string
	AuthPlugin      string
	SupportsSSL     bool
	TLSHandshakeOK  bool
	Latency         time.Duration
}

// ProbeMySQLGreeting connects to addr and inspects the Server-First MySQL Initial Handshake Packet.
func ProbeMySQLGreeting(addr string, timeout time.Duration) (*MySQLProbeInfo, error) {
	return ProbeMySQLGreetingTLS(addr, timeout, nil)
}

// ProbeMySQLGreetingTLS connects to addr, inspects the MySQL greeting, and when tlsCfg != nil
// verifies MySQL STARTTLS (SSLRequest + TLS handshake) against the configured CA/ServerName.
func ProbeMySQLGreetingTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*MySQLProbeInfo, error) {
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

	seq, payload, err := readMySQLPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("read initial greeting: %w", err)
	}
	if seq != 0 || len(payload) < 5 {
		return nil, fmt.Errorf("unexpected mysql greeting (seq=%d, len=%d)", seq, len(payload))
	}
	if payload[0] == 0xff {
		// Server sent an ERR packet immediately (e.g. Host not allowed to connect!).
		msg := extractMySQLErrMsg(payload)
		return nil, fmt.Errorf("mysql server rejected connection immediately: %s", msg)
	}
	if payload[0] != 0x0a {
		return nil, fmt.Errorf("unsupported mysql protocol version 0x%02x (expected 0x0a)", payload[0])
	}

	parsed, err := parseInitialHandshake(payload)
	if err != nil {
		return nil, err
	}
	info := &MySQLProbeInfo{
		ProtocolVersion: payload[0],
		ServerVersion:   parsed.serverVersion,
		AuthPlugin:      parsed.authPlugin,
		SupportsSSL:     (parsed.capabilities & capClientSSL) != 0,
	}
	if tlsCfg != nil {
		if !info.SupportsSSL {
			return nil, errors.New("mysql server does not advertise CLIENT_SSL while target_tls is enabled")
		}
		sslReq := buildMySQLSSLRequest(nil)
		if err := writeMySQLPacket(conn, 1, sslReq); err != nil {
			return nil, fmt.Errorf("write mysql SSLRequest: %w", err)
		}
		tlsConn := tls.Client(conn, tlsCfg.Clone())
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("mysql TLS handshake failed: %w", err)
		}
		info.TLSHandshakeOK = true
	}
	info.Latency = time.Since(start)
	return info, nil
}

func buildMySQLSSLRequest(cliResp []byte) []byte {
	var sslReq [32]byte
	caps := capClientProtocol41 | capClientLongPassword | capClientSecureConnection | capClientSSL
	maxPkt := uint32(16 * 1024 * 1024)
	charset := byte(0xff) // utf8mb4
	if len(cliResp) >= 9 {
		caps = binary.LittleEndian.Uint32(cliResp[0:4]) | capClientProtocol41 | capClientSSL
		maxPkt = binary.LittleEndian.Uint32(cliResp[4:8])
		charset = cliResp[8]
	}
	binary.LittleEndian.PutUint32(sslReq[0:4], caps)
	binary.LittleEndian.PutUint32(sslReq[4:8], maxPkt)
	sslReq[8] = charset
	return sslReq[:]
}

// MySQLProxy intercepts MySQL v10 traffic on the tenant agent for local credential
// injection and/or strict SQL read-only enforcement.
type MySQLProxy struct {
	cfg            MySQLGuardConfig
	blockedQueries atomic.Int64
}

// NewMySQLProxy creates a new tenant-side MySQL protocol proxy guard.
func NewMySQLProxy(cfg MySQLGuardConfig) *MySQLProxy {
	return &MySQLProxy{cfg: cfg}
}

// BlockedQueries returns the number of blocked write queries/commands.
func (p *MySQLProxy) BlockedQueries() int64 {
	return p.blockedQueries.Load()
}

// Proxy handles a single MySQL session between clientConn (hub stream) and serverConn (tenant local MySQL).
func (p *MySQLProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(cmd byte, sql, reason string),
) (bytesIn, bytesOut int64, err error) {
	// Bound the handshake phase so stalled clients or backends never leak streams indefinitely.
	hsDeadline := time.Now().Add(15 * time.Second)
	_ = clientConn.SetDeadline(hsDeadline)
	_ = serverConn.SetDeadline(hsDeadline)

	// 1. Read Server-First Initial Handshake Packet (seq=0) from tenant MySQL.
	srvSeq, greeting, err := readMySQLPacket(serverConn)
	if err != nil {
		return 0, 0, fmt.Errorf("read server greeting: %w", err)
	}
	if len(greeting) == 0 {
		return 0, 0, errors.New("empty mysql greeting")
	}
	// If MySQL immediately returned ERR (0xff), relay as-is and stop.
	if greeting[0] == 0xff {
		_ = writeMySQLPacket(clientConn, srvSeq, greeting)
		return 0, int64(len(greeting) + 4), nil
	}

	hs, err := parseInitialHandshake(greeting)
	if err != nil {
		// Not a standard full handshake v10 payload (e.g. minimal mock); only strip SSL if parseable.
		hs = &parsedHandshake{authPlugin: "mysql_native_password"}
	} else {
		// Clear CLIENT_SSL, CLIENT_COMPRESS, and ZSTD in the greeting forwarded to the hub
		// because the tunnel is already TLS-encrypted and the agent must inspect/rewrite packets.
		greeting = clearGreetingCapabilities(greeting, hs.capLowOffset, hs.capHighOffset)
	}

	if err := writeMySQLPacket(clientConn, srvSeq, greeting); err != nil {
		return 0, 0, fmt.Errorf("forward server greeting: %w", err)
	}
	bytesOut += int64(len(greeting) + 4)

	// 2. Read HandshakeResponse41 (seq=1) from central client.
	cliSeq, cliResp, err := readMySQLPacket(clientConn)
	if err != nil {
		return bytesIn, bytesOut, fmt.Errorf("read client handshake response: %w", err)
	}
	bytesIn += int64(len(cliResp) + 4)

	var realUser, realPass string
	if p.cfg.InjectCreds {
		realUser, err = ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			_ = writeMySQLErrPacket(clientConn, cliSeq+1, 1045, "28000", "dataproxy-agent: local credential username error")
			return bytesIn, bytesOut, fmt.Errorf("resolve local mysql username: %w", err)
		}
		realPass, err = ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			_ = writeMySQLErrPacket(clientConn, cliSeq+1, 1045, "28000", "dataproxy-agent: local credential password error")
			return bytesIn, bytesOut, fmt.Errorf("resolve local mysql password: %w", err)
		}
		rewritten, rwErr := rewriteHandshakeResponse41(cliResp, realUser, realPass, hs.salt, hs.authPlugin, p.cfg.ReadOnly)
		if rwErr != nil {
			_ = writeMySQLErrPacket(clientConn, cliSeq+1, 1045, "28000", "dataproxy-agent: malformed client handshake")
			return bytesIn, bytesOut, fmt.Errorf("rewrite handshake response: %w", rwErr)
		}
		cliResp = rewritten
	} else if p.cfg.ReadOnly && len(cliResp) >= 4 {
		// Strip CLIENT_MULTI_STATEMENTS / CLIENT_COMPRESS when read-only guard is active.
		caps := binary.LittleEndian.Uint32(cliResp[0:4])
		caps &^= (capClientMultiStatements | capClientCompress | capClientZstdCompression)
		binary.LittleEndian.PutUint32(cliResp[0:4], caps)
	}

	// 2.5 Optional Split-TLS upgrade (MySQL SSLRequest STARTTLS) toward tenant MySQL/RDS.
	upstreamSeq := cliSeq
	if p.cfg.TargetTLS != nil {
		if (hs.capabilities & capClientSSL) == 0 {
			_ = writeMySQLErrPacket(clientConn, cliSeq+1, 2026, "HY000", "dataproxy-agent: target MySQL does not support SSL")
			return bytesIn, bytesOut, errors.New("mysql target does not advertise CLIENT_SSL while target_tls is enabled")
		}
		sslReq := buildMySQLSSLRequest(cliResp)
		if err := writeMySQLPacket(serverConn, cliSeq, sslReq); err != nil {
			return bytesIn, bytesOut, fmt.Errorf("write mysql SSLRequest: %w", err)
		}
		tlsConn := tls.Client(serverConn, p.cfg.TargetTLS.Clone())
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = writeMySQLErrPacket(clientConn, cliSeq+1, 2026, "HY000", "dataproxy-agent: TLS handshake with target MySQL failed")
			return bytesIn, bytesOut, fmt.Errorf("mysql target TLS handshake failed: %w", err)
		}
		_ = tlsConn.SetDeadline(hsDeadline)
		serverConn = tlsConn

		// After SSLRequest (seq=1), MySQL protocol mandates CLIENT_SSL set and seq=2 on HandshakeResponse41.
		if len(cliResp) >= 4 {
			caps := binary.LittleEndian.Uint32(cliResp[0:4]) | capClientSSL
			binary.LittleEndian.PutUint32(cliResp[0:4], caps)
		}
		upstreamSeq = cliSeq + 1
	}

	if err := writeMySQLPacket(serverConn, upstreamSeq, cliResp); err != nil {
		return bytesIn, bytesOut, fmt.Errorf("write handshake response to mysql: %w", err)
	}

	// 3. Complete Authentication Exchange (handles OK, ERR, AuthSwitchRequest 0xfe, AuthMoreData 0x01).
	lastCliSeq := cliSeq
	useAlignedSeq := p.cfg.InjectCreds || p.cfg.TargetTLS != nil
	activeSalt := hs.salt
	for {
		sSeq, sPayload, err := readMySQLPacket(serverConn)
		if err != nil {
			return bytesIn, bytesOut, fmt.Errorf("read mysql auth result: %w", err)
		}
		bytesOut += int64(len(sPayload) + 4)
		if len(sPayload) == 0 {
			return bytesIn, bytesOut, errors.New("empty mysql auth packet")
		}

		switch sPayload[0] {
		case 0x00: // OK_Packet -> authenticated!
			outSeq := sSeq
			if useAlignedSeq {
				outSeq = lastCliSeq + 1
			}
			if err := writeMySQLPacket(clientConn, outSeq, sPayload); err != nil {
				return bytesIn, bytesOut, err
			}
			goto CommandPhase

		case 0xff: // ERR_Packet -> auth failed
			outSeq := sSeq
			if useAlignedSeq {
				outSeq = lastCliSeq + 1
			}
			_ = writeMySQLPacket(clientConn, outSeq, sPayload)
			return bytesIn, bytesOut, nil

		case 0xfe: // AuthSwitchRequest
			if p.cfg.InjectCreds {
				swPlugin, swSalt := parseAuthSwitchRequest(sPayload)
				if len(swSalt) > 0 {
					activeSalt = swSalt
				}
				authData := computeMySQLAuthResponse(swPlugin, realPass, activeSalt)
				if err := writeMySQLPacket(serverConn, sSeq+1, authData); err != nil {
					return bytesIn, bytesOut, fmt.Errorf("write auth switch response: %w", err)
				}
				continue
			}
			outSeq := sSeq
			if useAlignedSeq {
				outSeq = lastCliSeq + 1
			}
			if err := writeMySQLPacket(clientConn, outSeq, sPayload); err != nil {
				return bytesIn, bytesOut, err
			}
			cSeq, cPayload, err := readMySQLPacket(clientConn)
			if err != nil {
				return bytesIn, bytesOut, err
			}
			bytesIn += int64(len(cPayload) + 4)
			lastCliSeq = cSeq
			if err := writeMySQLPacket(serverConn, sSeq+1, cPayload); err != nil {
				return bytesIn, bytesOut, err
			}

		case 0x01: // AuthMoreData (caching_sha2_password fast auth = 0x01 0x03, full auth = 0x01 0x04)
			if len(sPayload) == 2 && sPayload[1] == 0x03 {
				// Fast auth succeeded; server immediately follows with OK_Packet.
				if !p.cfg.InjectCreds {
					outSeq := sSeq
					if useAlignedSeq {
						outSeq = lastCliSeq + 1
						lastCliSeq = outSeq
					}
					if err := writeMySQLPacket(clientConn, outSeq, sPayload); err != nil {
						return bytesIn, bytesOut, err
					}
				}
				continue
			}
			if p.cfg.InjectCreds && len(sPayload) == 2 && sPayload[1] == 0x04 {
				if p.cfg.TargetTLS != nil {
					// Over TLS, MySQL caching_sha2_password accepts NUL-terminated password directly!
					if err := writeMySQLPacket(serverConn, sSeq+1, append([]byte(realPass), 0x00)); err != nil {
						return bytesIn, bytesOut, fmt.Errorf("write mysql tls cleartext password: %w", err)
					}
					continue
				}
				// Plaintext fallback: RSA-OAEP public key full auth (works on stock MySQL 8.0/8.4 without TLS).
				if err := writeMySQLPacket(serverConn, sSeq+1, []byte{0x02}); err != nil {
					return bytesIn, bytesOut, fmt.Errorf("request mysql rsa public key: %w", err)
				}
				pubSeq, pubPayload, err := readMySQLPacket(serverConn)
				if err != nil || len(pubPayload) < 2 || pubPayload[0] != 0x01 {
					_ = writeMySQLErrPacket(clientConn, lastCliSeq+1, 1045, "28000", "dataproxy-agent: failed fetching mysql rsa public key")
					return bytesIn, bytesOut, fmt.Errorf("read mysql rsa public key: %w", err)
				}
				encPass, encErr := encryptMySQLPasswordRSA(pubPayload[1:], realPass, activeSalt)
				if encErr != nil {
					_ = writeMySQLErrPacket(clientConn, lastCliSeq+1, 1045, "28000", "dataproxy-agent: rsa encrypt password failed")
					return bytesIn, bytesOut, encErr
				}
				if err := writeMySQLPacket(serverConn, pubSeq+1, encPass); err != nil {
					return bytesIn, bytesOut, fmt.Errorf("write mysql rsa encrypted password: %w", err)
				}
				continue
			}
			outSeq := sSeq
			if useAlignedSeq {
				outSeq = lastCliSeq + 1
			}
			if err := writeMySQLPacket(clientConn, outSeq, sPayload); err != nil {
				return bytesIn, bytesOut, err
			}
			cSeq, cPayload, err := readMySQLPacket(clientConn)
			if err != nil {
				return bytesIn, bytesOut, err
			}
			bytesIn += int64(len(cPayload) + 4)
			lastCliSeq = cSeq
			if err := writeMySQLPacket(serverConn, sSeq+1, cPayload); err != nil {
				return bytesIn, bytesOut, err
			}

		default:
			outSeq := sSeq
			if useAlignedSeq {
				outSeq = lastCliSeq + 1
			}
			if err := writeMySQLPacket(clientConn, outSeq, sPayload); err != nil {
				return bytesIn, bytesOut, err
			}
			goto CommandPhase
		}
	}

CommandPhase:
	_ = clientConn.SetDeadline(time.Time{})
	_ = serverConn.SetDeadline(time.Time{})

	// If only credential injection was enabled (not ReadOnly), switch immediately to
	// zero-copy BidirectionalPipe for full native performance!
	if !p.cfg.ReadOnly {
		in2, out2 := transport.BidirectionalPipe(clientConn, serverConn)
		return bytesIn + in2, bytesOut + out2, nil
	}

	// Read-Only Command Phase: inspect every client command packet before forwarding to MySQL.
	var clientWriteMu sync.Mutex
	var serverCopyBytes atomic.Int64
	srvDone := make(chan struct{})
	go func() {
		defer func() {
			// Unblock client read loop immediately if the backend MySQL server disconnects.
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

	// Reuse a single pooled 64KiB buffer across the command loop so normal queries
	// require ZERO heap allocations and ZERO copies when forwarding raw packets to MySQL.
	cmdBufPtr := transport.GetCopyBuf()
	defer transport.PutCopyBuf(cmdBufPtr)
	cmdBuf := *cmdBufPtr

	for {
		cSeq, cPayload, rawFrame, err := readMySQLPacketReusable(clientConn, cmdBuf)
		if err != nil {
			break
		}
		bytesIn += int64(len(rawFrame))
		if len(cPayload) == 0 {
			continue
		}
		// Reject 16MiB-1 split continuation packets in read-only mode so continuation
		// payloads cannot desynchronize command-byte framing.
		if len(cPayload) == 0xffffff {
			p.blockedQueries.Add(1)
			clientWriteMu.Lock()
			_ = writeMySQLErrPacket(clientConn, cSeq+1, 1290, "HY000", "dataproxy-agent: multi-packet SQL (>16MiB) is blocked in read-only mode")
			clientWriteMu.Unlock()
			break
		}

		cmd := cPayload[0]
		allowed, reason := p.checkCommandAllowed(cmd, cPayload[1:])
		if !allowed {
			p.blockedQueries.Add(1)
			sqlText := ""
			if cmd == comQuery || cmd == comStmtPrepare {
				sqlText = string(cPayload[1:])
			}
			if onBlocked != nil {
				onBlocked(cmd, sqlText, reason)
			}
			clientWriteMu.Lock()
			werr := writeMySQLErrPacket(clientConn, cSeq+1, 1290, "HY000", "dataproxy-agent: "+reason)
			clientWriteMu.Unlock()
			if werr != nil {
				break
			}
			continue
		}

		if _, err := serverConn.Write(rawFrame); err != nil {
			break
		}
		if cmd == comQuit {
			break
		}
	}

	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

func (p *MySQLProxy) checkCommandAllowed(cmd byte, body []byte) (bool, string) {
	switch cmd {
	case comQuit, comInitDB, comFieldList, comStatistics, comPing,
		comStmtExecute, comStmtSendLong, comStmtClose, comStmtReset, comStmtFetch,
		comResetConnection:
		return true, ""

	case comQuery, comStmtPrepare:
		// Zero-alloc read-only view: IsReadOnlySQL never retains references to its input string.
		sqlView := unsafe.String(unsafe.SliceData(body), len(body))
		return IsReadOnlySQL(sqlView)

	default:
		return false, fmt.Sprintf("MySQL command 0x%02x is blocked by tenant read-only policy", cmd)
	}
}

type parsedHandshake struct {
	serverVersion string
	salt          []byte
	capabilities  uint32
	capLowOffset  int
	capHighOffset int
	authPlugin    string
}

func parseInitialHandshake(payload []byte) (*parsedHandshake, error) {
	if len(payload) < 2 || payload[0] != 0x0a {
		return nil, errors.New("not a MySQL v10 initial handshake")
	}
	pos := 1
	endVer := bytes.IndexByte(payload[pos:], 0x00)
	if endVer < 0 {
		return nil, errors.New("unterminated server version")
	}
	serverVersion := string(payload[pos : pos+endVer])
	pos += endVer + 1

	// Need at least: 4B connID + 8B salt1 + 1B filler + 2B capLow = 15 bytes
	if pos+15 > len(payload) {
		return nil, errors.New("truncated initial handshake")
	}
	pos += 4 // skip connection id
	salt := make([]byte, 0, 20)
	salt = append(salt, payload[pos:pos+8]...)
	pos += 8
	pos += 1 // filler 0x00

	capLowOffset := pos
	capLow := uint32(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	caps := capLow
	capHighOffset := -1
	authPlugin := "mysql_native_password"

	// Optional extended handshake fields (1B charset + 2B status + 2B capHigh + 1B authLen + 10B reserved = 16B)
	if pos+16 <= len(payload) {
		pos += 1 // charset
		pos += 2 // status flags
		capHighOffset = pos
		capHigh := uint32(binary.LittleEndian.Uint16(payload[pos : pos+2]))
		caps |= capHigh << 16
		pos += 2

		authDataLen := int(payload[pos])
		pos += 1
		pos += 10 // reserved zeros

		if (caps & capClientSecureConnection) != 0 {
			part2Len := 13
			if authDataLen-8 > part2Len {
				part2Len = authDataLen - 8
			}
			if pos+part2Len <= len(payload) {
				part2 := payload[pos : pos+part2Len]
				// Trim trailing NUL terminator from salt part 2
				if len(part2) > 0 && part2[len(part2)-1] == 0x00 {
					part2 = part2[:len(part2)-1]
				}
				salt = append(salt, part2...)
				pos += part2Len
			}
		}

		if (caps&capClientPluginAuth) != 0 && pos < len(payload) {
			endPlug := bytes.IndexByte(payload[pos:], 0x00)
			if endPlug >= 0 {
				authPlugin = string(payload[pos : pos+endPlug])
			} else {
				authPlugin = string(payload[pos:])
			}
		}
	}

	return &parsedHandshake{
		serverVersion: serverVersion,
		salt:          salt,
		capabilities:  caps,
		capLowOffset:  capLowOffset,
		capHighOffset: capHighOffset,
		authPlugin:    authPlugin,
	}, nil
}

func clearGreetingCapabilities(greeting []byte, capLowOff, capHighOff int) []byte {
	out := append([]byte(nil), greeting...)
	if capLowOff >= 0 && capLowOff+2 <= len(out) {
		low := binary.LittleEndian.Uint16(out[capLowOff : capLowOff+2])
		low &^= uint16(capClientSSL | capClientCompress)
		binary.LittleEndian.PutUint16(out[capLowOff:capLowOff+2], low)
	}
	if capHighOff >= 0 && capHighOff+2 <= len(out) {
		high := binary.LittleEndian.Uint16(out[capHighOff : capHighOff+2])
		high &^= uint16((capClientZstdCompression | capClientQueryAttributes) >> 16)
		binary.LittleEndian.PutUint16(out[capHighOff:capHighOff+2], high)
	}
	return out
}

func rewriteHandshakeResponse41(
	orig []byte,
	realUser, realPass string,
	salt []byte,
	serverPlugin string,
	readOnly bool,
) ([]byte, error) {
	if len(orig) < 32 {
		return nil, errors.New("handshake response too short")
	}
	caps := binary.LittleEndian.Uint32(orig[0:4])
	maxPacket := orig[4:8]
	charset := orig[8]

	pos := 32
	// Skip placeholder username (NUL-terminated)
	endUser := bytes.IndexByte(orig[pos:], 0x00)
	if endUser < 0 {
		return nil, errors.New("unterminated placeholder username")
	}
	pos += endUser + 1

	// Skip placeholder auth response (using uint64 bounds checks to prevent int overflow panics).
	switch {
	case (caps & capClientPluginAuthLenencClientData) != 0:
		authLen, n := readLenEncInt(orig[pos:])
		if n == 0 || pos+n > len(orig) || authLen > uint64(len(orig)-pos-n) {
			return nil, errors.New("truncated or oversized lenenc auth response")
		}
		pos += n + int(authLen)
	case (caps & capClientSecureConnection) != 0:
		if pos >= len(orig) {
			return nil, errors.New("missing placeholder auth length")
		}
		authLen := int(orig[pos])
		if 1+authLen > len(orig)-pos {
			return nil, errors.New("truncated auth response")
		}
		pos += 1 + authLen
	default:
		endAuth := bytes.IndexByte(orig[pos:], 0x00)
		if endAuth < 0 {
			return nil, errors.New("unterminated placeholder auth")
		}
		pos += endAuth + 1
	}
	if pos > len(orig) {
		return nil, errors.New("truncated auth response")
	}

	// Preserve optional database name
	var dbName string
	if (caps&capClientConnectWithDB) != 0 && pos < len(orig) {
		endDB := bytes.IndexByte(orig[pos:], 0x00)
		if endDB >= 0 {
			dbName = string(orig[pos : pos+endDB])
			pos += endDB + 1
		}
	}

	// Skip placeholder auth plugin name if present
	if (caps&capClientPluginAuth) != 0 && pos < len(orig) {
		endPlug := bytes.IndexByte(orig[pos:], 0x00)
		if endPlug >= 0 {
			pos += endPlug + 1
		}
	}

	// Preserve any trailing connect attrs
	var trailingAttrs []byte
	if (caps&capClientConnectAttrs) != 0 && pos < len(orig) {
		trailingAttrs = orig[pos:]
	}

	// Normalize capabilities for injected response.
	caps |= capClientProtocol41 | capClientSecureConnection | capClientPluginAuth
	caps &^= (capClientSSL | capClientCompress | capClientZstdCompression | capClientQueryAttributes | capClientPluginAuthLenencClientData)
	if readOnly {
		caps &^= capClientMultiStatements
	}

	plugin := serverPlugin
	if plugin == "" {
		plugin = "mysql_native_password"
	}
	authResp := computeMySQLAuthResponse(plugin, realPass, salt)

	var out bytes.Buffer
	var capBytes [4]byte
	binary.LittleEndian.PutUint32(capBytes[:], caps)
	out.Write(capBytes[:])
	out.Write(maxPacket)
	out.WriteByte(charset)
	out.Write(make([]byte, 23)) // reserved
	out.WriteString(realUser)
	out.WriteByte(0x00)
	out.WriteByte(byte(len(authResp)))
	out.Write(authResp)
	if (caps & capClientConnectWithDB) != 0 {
		out.WriteString(dbName)
		out.WriteByte(0x00)
	}
	out.WriteString(plugin)
	out.WriteByte(0x00)
	if len(trailingAttrs) > 0 {
		out.Write(trailingAttrs)
	}
	return out.Bytes(), nil
}

func parseAuthSwitchRequest(payload []byte) (pluginName string, salt []byte) {
	if len(payload) <= 1 {
		return "mysql_native_password", nil
	}
	rest := payload[1:]
	idx := bytes.IndexByte(rest, 0x00)
	if idx < 0 {
		return string(rest), nil
	}
	pluginName = string(rest[:idx])
	salt = rest[idx+1:]
	if len(salt) > 0 && salt[len(salt)-1] == 0x00 {
		salt = salt[:len(salt)-1]
	}
	return pluginName, salt
}

// computeMySQLAuthResponse computes the cryptographic scramble for mysql_native_password
// or caching_sha2_password using the local tenant password and the server's random salt.
func computeMySQLAuthResponse(plugin, password string, salt []byte) []byte {
	if password == "" {
		return nil
	}
	switch plugin {
	case "caching_sha2_password":
		// XOR(SHA256(password), SHA256(SHA256(SHA256(password)) || salt))
		stage1 := sha256.Sum256([]byte(password))
		stage2 := sha256.Sum256(stage1[:])
		h := sha256.New()
		h.Write(stage2[:])
		h.Write(salt)
		scramble := h.Sum(nil)
		out := make([]byte, len(stage1))
		for i := range stage1 {
			out[i] = stage1[i] ^ scramble[i]
		}
		return out

	default:
		// mysql_native_password: SHA1(password) XOR SHA1(salt || SHA1(SHA1(password)))
		stage1 := sha1.Sum([]byte(password))
		stage2 := sha1.Sum(stage1[:])
		h := sha1.New()
		h.Write(salt)
		h.Write(stage2[:])
		scramble := h.Sum(nil)
		out := make([]byte, len(stage1))
		for i := range stage1 {
			out[i] = stage1[i] ^ scramble[i]
		}
		return out
	}
}

func readLenEncInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, len(b)
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3
	case 0xfd:
		if len(b) < 4 {
			return 0, len(b)
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case 0xfe:
		if len(b) < 9 {
			return 0, len(b)
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9
	default:
		return uint64(b[0]), 1
	}
}

func readMySQLPacketReusable(r io.Reader, scratch []byte) (seq byte, payload, rawFrame []byte, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	total := 4 + length
	if total <= len(scratch) {
		rawFrame = scratch[:total]
	} else {
		rawFrame = make([]byte, total)
	}
	copy(rawFrame[:4], hdr[:])
	payload = rawFrame[4:total]
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, nil, err
		}
	}
	return hdr[3], payload, rawFrame, nil
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

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	n := len(payload)
	total := 4 + n
	if total <= transport.CopyBufferSize {
		bufPtr := transport.GetCopyBuf()
		buf := (*bufPtr)[:total]
		buf[0] = byte(n)
		buf[1] = byte(n >> 8)
		buf[2] = byte(n >> 16)
		buf[3] = seq
		copy(buf[4:], payload)
		_, err := w.Write(buf)
		transport.PutCopyBuf(bufPtr)
		return err
	}
	buf := make([]byte, total)
	buf[0] = byte(n)
	buf[1] = byte(n >> 8)
	buf[2] = byte(n >> 16)
	buf[3] = seq
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

func writeMySQLErrPacket(w io.Writer, seq byte, errCode uint16, sqlState, msg string) error {
	var payload bytes.Buffer
	payload.WriteByte(0xff)
	var codeBytes [2]byte
	binary.LittleEndian.PutUint16(codeBytes[:], errCode)
	payload.Write(codeBytes[:])
	payload.WriteByte('#')
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	payload.WriteString(sqlState)
	payload.WriteString(msg)
	return writeMySQLPacket(w, seq, payload.Bytes())
}

func extractMySQLErrMsg(payload []byte) string {
	if len(payload) <= 3 {
		return "unknown mysql error"
	}
	if len(payload) > 9 && payload[3] == '#' {
		return string(payload[9:])
	}
	return string(payload[3:])
}

func encryptMySQLPasswordRSA(pemBytes []byte, password string, salt []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed decoding mysql RSA PEM public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse mysql RSA public key: %w", err)
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("mysql server key is not RSA")
	}
	plain := append([]byte(password), 0x00)
	if len(salt) > 0 {
		for i := range plain {
			plain[i] ^= salt[i%len(salt)]
		}
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, plain, nil)
}
