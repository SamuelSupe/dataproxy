package hub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

// SmartDBIngress provides single-port multi-tenant database routing using short-lived
// job-scoped tickets embedded directly in standard database client credentials
// (Ticket-in-Auth). Central platform services (psql, mysql, redis-cli, JDBC, Flink,
// SQLAlchemy, AI Agents) connect to ONE hub port per DB type without SOCKS5 or per-tenant ports.
type SmartDBIngress struct {
	registry *Registry
	tickets  *auth.TicketManager
	logger   *slog.Logger
}

func NewSmartDBIngress(registry *Registry, tickets *auth.TicketManager, logger *slog.Logger) *SmartDBIngress {
	if logger == nil {
		logger = slog.Default()
	}
	return &SmartDBIngress{
		registry: registry,
		tickets:  tickets,
		logger:   logger.With("component", "smart_db_ingress"),
	}
}

// ============================================================================
// 1. Single-Port Multi-Tenant PostgreSQL Ticket Router
//    Usage: psql "postgresql://<tenant>.<service>:<JWT_TICKET>@hub:5432/db?sslmode=disable"
// ============================================================================

func (s *SmartDBIngress) ServePostgres(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handlePGConn(conn)
	}
}

func (s *SmartDBIngress) handlePGConn(clientConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("recovered panic in pg smart router", "panic", r)
		}
		_ = clientConn.Close()
	}()
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. Read optional SSLRequest / GSSENCRequest and then StartupMessage.
	var startupBody []byte
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		if msgLen < 8 || msgLen > 64*1024 {
			return
		}
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(clientConn, body); err != nil {
			return
		}
		code := binary.BigEndian.Uint32(body[0:4])
		if code == 80877103 || code == 80877104 { // SSLRequest / GSSENCRequest
			if _, err := clientConn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		}
		if code != 196608 { // Protocol v3.0
			return
		}
		startupBody = body
		break
	}

	routeUser := extractPGStartupUser(startupBody)
	if routeUser == "" {
		writeHubPGError(clientConn, "28000", "dataproxy-hub: missing user in PostgreSQL startup")
		return
	}

	// 2. Request CleartextPassword ('R', authCode=3) so central client sends the Job Ticket.
	if err := writeHubPGMsg(clientConn, 'R', []byte{0, 0, 0, 3}); err != nil {
		return
	}

	pType, pPayload, err := readHubPGMsg(clientConn)
	if err != nil || pType != 'p' {
		return
	}
	ticketToken := string(bytes.TrimRight(pPayload, "\x00"))
	_ = clientConn.SetDeadline(time.Time{})

	// 3. Verify Job Ticket & strict single-tenant/service scope!
	claims, err := s.verifyRouteAndTicket(routeUser, ticketToken)
	if err != nil {
		s.logger.Warn("AUDIT: pg smart router rejected ticket", "route_user", routeUser, "error", err)
		writeHubPGError(clientConn, "28P01", "dataproxy-hub: "+err.Error())
		return
	}

	// 4. Open tenant stream carrying Job Ticket ID & Business Purpose straight to tenant Agent!
	stream, err := s.registry.OpenTenantStreamWithMeta(
		context.Background(),
		claims.TenantID,
		claims.ServiceName,
		protocol.ProtocolTCP,
		StreamMeta{
			CallerID: "pg-smart:" + claims.TicketID,
			TicketID: claims.TicketID,
			Purpose:  claims.Purpose,
		},
	)
	if err != nil {
		s.logger.Warn("pg smart router open stream failed", "tenant", claims.TenantID, "service", claims.ServiceName, "error", err)
		writeHubPGError(clientConn, "08006", "dataproxy-hub: "+err.Error())
		return
	}
	defer func() { _ = stream.Close() }()

	// 5. Replay client's StartupMessage to tenant Agent (whose PostgresProxy handles local SCRAM-SHA-256 auth!).
	startupFrame := make([]byte, 4+len(startupBody))
	binary.BigEndian.PutUint32(startupFrame[0:4], uint32(len(startupBody)+4))
	copy(startupFrame[4:], startupBody)
	if _, err := stream.Write(startupFrame); err != nil {
		return
	}

	transport.BidirectionalPipe(clientConn, stream)
}

// ============================================================================
// 2. Single-Port Multi-Tenant MySQL Ticket Router
//    Usage: mysql --ssl-mode=DISABLED -h hub -P 3306 -u <ticket_id> -p<ticket_secret>
//    Works with stock MySQL CLI / JDBC / PyMySQL / Go driver with ZERO extra flags!
// ============================================================================

func (s *SmartDBIngress) ServeMySQL(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleMySQLConn(conn)
	}
}

func (s *SmartDBIngress) handleMySQLConn(clientConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("recovered panic in mysql smart router", "panic", r)
		}
		_ = clientConn.Close()
	}()
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. Generate random 20-byte salt and emit synthetic MySQL v10 Initial Handshake Packet (seq=0).
	var hubSalt [20]byte
	_, _ = rand.Read(hubSalt[:])
	// Ensure no NUL byte in salt (MySQL handshake uses NUL-terminated part2).
	for i := range hubSalt {
		if hubSalt[i] == 0 {
			hubSalt[i] = 0x21
		}
	}
	if err := writeHubMySQLPacket(clientConn, 0, buildHubMySQLGreeting(hubSalt[:])); err != nil {
		return
	}

	// 2. Read client HandshakeResponse41 (seq=1).
	cliSeq, cliResp, err := readHubMySQLPacket(clientConn)
	if err != nil {
		s.logger.Warn("mysql smart router read handshake response failed", "error", err)
		return
	}
	_ = clientConn.SetDeadline(time.Time{})

	username, authResp, err := parseHubMySQLHandshake41(cliResp)
	if err != nil {
		s.logger.Warn("mysql smart router parse handshake failed", "error", err)
		_ = writeHubMySQLErr(clientConn, cliSeq+1, 1045, "28000", "dataproxy-hub: malformed handshake")
		return
	}

	// Support either "<ticket_id>" or "<tenant>.<service>#<ticket_id>".
	ticketID := username
	var expectTenant, expectSvc string
	if prefix, tid, hasHash := strings.Cut(username, "#"); hasHash {
		ticketID = tid
		expectTenant, expectSvc, _ = parseRouteUser(prefix)
	}

	claims, err := s.tickets.VerifyMySQLNativeScramble(ticketID, hubSalt[:], authResp)
	if err != nil {
		s.logger.Warn("AUDIT: mysql smart router rejected ticket", "user", username, "error", err)
		_ = writeHubMySQLErr(clientConn, cliSeq+1, 1045, "28000", "dataproxy-hub: "+err.Error())
		return
	}
	if (expectTenant != "" && claims.TenantID != expectTenant) || (expectSvc != "" && claims.ServiceName != expectSvc) {
		_ = writeHubMySQLErr(clientConn, cliSeq+1, 1045, "28000", "dataproxy-hub: ticket scope mismatch")
		return
	}

	// 3. Open tenant stream carrying Job Ticket ID & Business Purpose!
	stream, err := s.registry.OpenTenantStreamWithMeta(
		context.Background(),
		claims.TenantID,
		claims.ServiceName,
		protocol.ProtocolTCP,
		StreamMeta{
			CallerID: "mysql-smart:" + claims.TicketID,
			TicketID: claims.TicketID,
			Purpose:  claims.Purpose,
		},
	)
	if err != nil {
		s.logger.Warn("mysql smart router open stream failed", "tenant", claims.TenantID, "service", claims.ServiceName, "error", err)
		_ = writeHubMySQLErr(clientConn, cliSeq+1, 1045, "28000", "dataproxy-hub: "+err.Error())
		return
	}
	defer func() { _ = stream.Close() }()

	// 4. Consume and discard the real tenant MySQL's seq=0 greeting coming back from the Agent
	//    (because Hub already sent seq=0 to the central client, and Agent already captured tenant salt!).
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, tenantGreeting, err := readHubMySQLPacket(stream)
	if err != nil {
		_ = writeHubMySQLErr(clientConn, cliSeq+1, 2013, "HY000", "dataproxy-hub: lost connection during tenant handshake")
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	if len(tenantGreeting) > 0 && tenantGreeting[0] == 0xff {
		_ = writeHubMySQLPacket(clientConn, cliSeq+1, tenantGreeting)
		return
	}

	// 5. Forward central client's HandshakeResponse41 (seq=1) -> Agent injects real tenant DB credentials
	//    (via caching_sha2_password RSA-OAEP or mysql_native_password) and returns seq=2 OK_Packet straight to client!
	if err := writeHubMySQLPacket(stream, cliSeq, cliResp); err != nil {
		return
	}

	transport.BidirectionalPipe(clientConn, stream)
}

// ============================================================================
// 3. Single-Port Multi-Tenant Redis Ticket Router
//    Usage: redis-cli -h hub -p 6379 --user <tenant>.<service> -a <JWT_TICKET>
//       or: redis-cli -h hub -p 6379 -a <JWT_TICKET>
// ============================================================================

func (s *SmartDBIngress) ServeRedis(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleRedisConn(conn)
	}
}

func (s *SmartDBIngress) handleRedisConn(clientConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("recovered panic in redis smart router", "panic", r)
		}
		_ = clientConn.Close()
	}()
	br := transport.GetBufioReader(clientConn)
	defer transport.PutBufioReader(br)
	_ = clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))

	args, _, err := readHubRESP(br)
	if err != nil || len(args) == 0 {
		return
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	cmd := strings.ToUpper(args[0])
	var routeUser, token string
	isHello := false

	switch {
	case cmd == "AUTH" && len(args) == 2:
		token = args[1]
	case cmd == "AUTH" && len(args) >= 3:
		routeUser = args[1]
		token = args[2]
	case cmd == "HELLO":
		isHello = true
		for i := 1; i+2 < len(args); i++ {
			if strings.EqualFold(args[i], "AUTH") {
				routeUser = args[i+1]
				token = args[i+2]
				break
			}
		}
	default:
		_, _ = io.WriteString(clientConn, "-NOAUTH dataproxy-hub: AUTH with short-lived job ticket required\r\n")
		return
	}

	if token == "" {
		_, _ = io.WriteString(clientConn, "-NOAUTH dataproxy-hub: missing job ticket in AUTH/HELLO\r\n")
		return
	}

	var claims *auth.JobTicketClaims
	if routeUser == "" || strings.EqualFold(routeUser, "default") {
		claims, err = s.tickets.VerifyJWT(token)
	} else {
		claims, err = s.verifyRouteAndTicket(routeUser, token)
	}
	if err != nil {
		s.logger.Warn("AUDIT: redis smart router rejected ticket", "route_user", routeUser, "error", err)
		_, _ = fmt.Fprintf(clientConn, "-WRONGPASS dataproxy-hub: %v\r\n", err)
		return
	}

	stream, err := s.registry.OpenTenantStreamWithMeta(
		context.Background(),
		claims.TenantID,
		claims.ServiceName,
		protocol.ProtocolTCP,
		StreamMeta{
			CallerID: "redis-smart:" + claims.TicketID,
			TicketID: claims.TicketID,
			Purpose:  claims.Purpose,
		},
	)
	if err != nil {
		s.logger.Warn("redis smart router open stream failed", "tenant", claims.TenantID, "service", claims.ServiceName, "error", err)
		_, _ = fmt.Fprintf(clientConn, "-ERR dataproxy-hub: %v\r\n", err)
		return
	}
	defer func() { _ = stream.Close() }()

	if isHello {
		// Forward HELLO without dummy AUTH (Agent RedisProxy already authenticated locally).
		var cleaned []string
		for i := 0; i < len(args); i++ {
			if i > 0 && strings.EqualFold(args[i], "AUTH") && i+2 < len(args) {
				i += 2
				continue
			}
			cleaned = append(cleaned, args[i])
		}
		if _, err := stream.Write(encodeHubRESP(cleaned)); err != nil {
			return
		}
	} else {
		if _, err := io.WriteString(clientConn, "+OK\r\n"); err != nil {
			return
		}
	}

	bconn := &bufferedConn{Conn: clientConn, r: br}
	transport.BidirectionalPipe(bconn, stream)
}

// ============================================================================
// Shared Helpers
// ============================================================================

func (s *SmartDBIngress) verifyRouteAndTicket(routeUser, secretOrJWT string) (*auth.JobTicketClaims, error) {
	claims, err := s.tickets.VerifySecret(routeUser, secretOrJWT)
	if err != nil {
		return nil, err
	}
	// If routeUser is "<tenant>.<service>" or "<tenant>--<service>", enforce exact scope match!
	if tenant, svc, ok := parseRouteUser(routeUser); ok {
		if claims.TenantID != tenant || claims.ServiceName != svc {
			return nil, fmt.Errorf("%w: route=%s.%s ticket=%s.%s", auth.ErrTicketScope, tenant, svc, claims.TenantID, claims.ServiceName)
		}
	}
	return claims, nil
}

func parseRouteUser(u string) (tenantID, serviceName string, ok bool) {
	if t, s, found := strings.Cut(u, "--"); found && t != "" && s != "" {
		return t, s, true
	}
	if t, s, found := strings.Cut(u, "."); found && t != "" && s != "" && !strings.Contains(s, ".") {
		return t, s, true
	}
	return "", "", false
}

func extractPGStartupUser(body []byte) string {
	if len(body) <= 4 {
		return ""
	}
	params := body[4:]
	pos := 0
	for pos < len(params) && params[pos] != 0x00 {
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
			return val
		}
	}
	return ""
}

func readHubPGMsg(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > 64*1024 {
		return 0, nil, errors.New("invalid pg message length")
	}
	payload := make([]byte, length-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}

func writeHubPGMsg(w io.Writer, msgType byte, payload []byte) error {
	buf := make([]byte, 5+len(payload))
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

func writeHubPGError(w io.Writer, sqlState, msg string) {
	var p bytes.Buffer
	p.WriteByte('S')
	p.WriteString("FATAL")
	p.WriteByte(0)
	p.WriteByte('V')
	p.WriteString("FATAL")
	p.WriteByte(0)
	p.WriteByte('C')
	p.WriteString(sqlState)
	p.WriteByte(0)
	p.WriteByte('M')
	p.WriteString(msg)
	p.WriteByte(0)
	p.WriteByte(0)
	_ = writeHubPGMsg(w, 'E', p.Bytes())
}

func buildHubMySQLGreeting(salt []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x0a)
	b.WriteString("8.4.0-dataproxy-hub")
	b.WriteByte(0x00)
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // conn id
	b.Write(salt[:8])
	b.WriteByte(0x00)
	// capLow: standard MySQL 8.4 lower capabilities (SSL 0x0800 & COMPRESS 0x0020 cleared)
	_ = binary.Write(&b, binary.LittleEndian, uint16(0xf7df))
	b.WriteByte(0x21)
	_ = binary.Write(&b, binary.LittleEndian, uint16(0x0002))
	// capHigh: MULTI_RESULTS | PS_MULTI_RESULTS | PLUGIN_AUTH | CONNECT_ATTRS | PLUGIN_AUTH_LENENC | SESSION_TRACK | DEPRECATE_EOF (0x01be)
	_ = binary.Write(&b, binary.LittleEndian, uint16(0x01be))
	b.WriteByte(21)
	b.Write(make([]byte, 10))
	b.Write(salt[8:20])
	b.WriteByte(0x00)
	b.WriteString("caching_sha2_password")
	b.WriteByte(0x00)
	return b.Bytes()
}

func readHubMySQLPacket(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length > 64*1024 {
		return 0, nil, fmt.Errorf("mysql handshake packet exceeds 64KiB limit (%d bytes)", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

func writeHubMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	buf := make([]byte, 4+len(payload))
	n := len(payload)
	buf[0] = byte(n)
	buf[1] = byte(n >> 8)
	buf[2] = byte(n >> 16)
	buf[3] = seq
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

func writeHubMySQLErr(w io.Writer, seq byte, code uint16, sqlState, msg string) error {
	var p bytes.Buffer
	p.WriteByte(0xff)
	_ = binary.Write(&p, binary.LittleEndian, code)
	p.WriteByte('#')
	p.WriteString(sqlState)
	p.WriteString(msg)
	return writeHubMySQLPacket(w, seq, p.Bytes())
}

func parseHubMySQLHandshake41(orig []byte) (username string, authResp []byte, err error) {
	if len(orig) < 33 {
		return "", nil, errors.New("handshake too short")
	}
	caps := binary.LittleEndian.Uint32(orig[0:4])
	pos := 32
	uEnd := bytes.IndexByte(orig[pos:], 0x00)
	if uEnd < 0 {
		return "", nil, errors.New("unterminated username")
	}
	username = string(orig[pos : pos+uEnd])
	pos += uEnd + 1
	if pos >= len(orig) {
		return username, nil, nil
	}
	if (caps&0x00200000) != 0 || (caps&0x00008000) != 0 {
		aLen := int(orig[pos])
		pos++
		if pos+aLen > len(orig) {
			return "", nil, errors.New("truncated auth response")
		}
		authResp = orig[pos : pos+aLen]
	}
	return username, authResp, nil
}

func readHubRESP(br *bufio.Reader) ([]string, []byte, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, nil, err
	}
	if first[0] != '*' {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		return strings.Fields(string(line)), line, nil
	}
	var raw bytes.Buffer
	hdrLine, err := br.ReadBytes('\n')
	if err != nil {
		return nil, nil, err
	}
	raw.Write(hdrLine)
	count, err := strconv.Atoi(strings.TrimSpace(string(hdrLine[1:])))
	if err != nil || count < 0 || count > 1000 {
		return nil, nil, errors.New("invalid RESP array")
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lenLine, err := br.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		raw.Write(lenLine)
		if len(lenLine) < 2 || lenLine[0] != '$' {
			return nil, nil, errors.New("expected bulk string")
		}
		bLen, err := strconv.Atoi(strings.TrimSpace(string(lenLine[1:])))
		if err != nil || bLen < 0 || bLen > 64*1024 {
			return nil, nil, errors.New("invalid bulk len")
		}
		buf := make([]byte, bLen+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, nil, err
		}
		raw.Write(buf)
		args = append(args, string(buf[:bLen]))
	}
	return args, raw.Bytes(), nil
}

func encodeHubRESP(args []string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.Bytes()
}
