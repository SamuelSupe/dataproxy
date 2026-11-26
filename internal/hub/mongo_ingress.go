package hub

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"time"

	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

const (
	hubMongoOpReply uint32 = 1
	hubMongoOpQuery uint32 = 2004
	hubMongoOpMsg   uint32 = 2013
)

// Pre-computed static BSON replies avoid per-heartbeat allocations on MongoDB SDAM probes.
var (
	staticHubMongoHelloDoc  = buildHubMongoHelloDoc()
	staticHubMongoPingOKDoc = buildHubBSON(hubBsonDouble("ok", 1.0))
	staticHubMongoAuthOKDoc = buildHubBSON(
		hubBsonInt32("conversationId", 1),
		hubBsonBool("done", true),
		hubBsonBin("payload", nil),
		hubBsonDouble("ok", 1.0),
	)
)

// ServeMongo serves the single-port multi-tenant MongoDB Ticket router (mongo_smart_addr).
// Central clients connect using standard MongoDB drivers / mongosh with SASL PLAIN:
//
//	mongodb://<tenant>.<service>:<JWT_TICKET>@hub:27017/demo?authMechanism=PLAIN&authSource=$external&directConnection=true
//
// Hub verifies the short-lived job ticket & tenant/service scope, opens the tenant tunnel
// (where the tenant Agent proactively authenticates to real MongoDB using local SCRAM-SHA-256
// credentials), completes the SASL PLAIN handshake, and pipes all subsequent OP_MSG commands.
func (s *SmartDBIngress) ServeMongo(ln net.Listener) error {
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Warn("mongo smart router accept error, backing off", "error", err)
			sleepAcceptBackoff(&tempDelay)
			continue
		}
		tempDelay = 0
		go s.handleMongoConn(conn)
	}
}

func (s *SmartDBIngress) handleMongoConn(clientConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("recovered panic in mongo smart router", "panic", r)
		}
		_ = clientConn.Close()
	}()

	var synthID uint32 = 800000000
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		reqID, _, opCode, body, err := readHubMongoMsg(clientConn)
		if err != nil {
			return
		}
		_ = clientConn.SetReadDeadline(time.Time{})

		// Handle legacy OP_QUERY isMaster/hello sent by some drivers on initial handshake.
		if opCode == hubMongoOpQuery {
			synthID++
			if err := writeHubMongoOpReply(clientConn, synthID, reqID, staticHubMongoHelloDoc); err != nil {
				return
			}
			continue
		}

		if opCode != hubMongoOpMsg {
			return
		}
		cmdDoc, err := extractHubOpMsgDoc(body)
		if err != nil {
			return
		}
		cmdName, fields := parseHubMongoBSON(cmdDoc)

		switch cmdName {
		case "hello", "isMaster", "ismaster":
			// Reply with standalone primary hello (without speculativeAuthenticate so drivers
			// proceed immediately to saslStart PLAIN on the command socket while SDAM monitors stay happy).
			synthID++
			if err := writeHubMongoOpMsg(clientConn, synthID, reqID, staticHubMongoHelloDoc); err != nil {
				return
			}
			continue

		case "ping":
			synthID++
			if err := writeHubMongoOpMsg(clientConn, synthID, reqID, staticHubMongoPingOKDoc); err != nil {
				return
			}
			continue

		case "saslStart":
			mech := fields["mechanism"].strVal
			if mech != "PLAIN" {
				synthID++
				_ = writeHubMongoAuthErr(clientConn, synthID, reqID, "dataproxy-hub: use authMechanism=PLAIN with short-lived job ticket")
				return
			}
			routeUser, ticketToken, ok := parseSASLPlainPayload(fields["payload"].binVal)
			if !ok {
				synthID++
				_ = writeHubMongoAuthErr(clientConn, synthID, reqID, "dataproxy-hub: malformed SASL PLAIN credentials")
				return
			}

			claims, err := s.verifyRouteAndTicket(routeUser, ticketToken)
			if err != nil {
				s.logger.Warn("AUDIT: mongo smart router rejected ticket", "route_user", routeUser, "error", err)
				synthID++
				_ = writeHubMongoAuthErr(clientConn, synthID, reqID, "dataproxy-hub: "+err.Error())
				return
			}

			openCtx, cancelOpen := context.WithTimeout(context.Background(), 15*time.Second)
			stream, err := s.registry.OpenTenantStreamWithMeta(
				openCtx,
				claims.TenantID,
				claims.ServiceName,
				protocol.ProtocolTCP,
				StreamMeta{
					CallerID: "mongo-smart:" + claims.TicketID,
					TicketID: claims.TicketID,
					Purpose:  claims.Purpose,
				},
			)
			cancelOpen()
			if err != nil {
				s.logger.Warn("mongo smart router open stream failed", "tenant", claims.TenantID, "service", claims.ServiceName, "error", err)
				synthID++
				_ = writeHubMongoAuthErr(clientConn, synthID, reqID, "dataproxy-hub: "+err.Error())
				return
			}
			defer func() { _ = stream.Close() }()

			// Acknowledge SASL PLAIN auth success to central client!
			synthID++
			if err := writeHubMongoOpMsg(clientConn, synthID, reqID, staticHubMongoAuthOKDoc); err != nil {
				return
			}

			// Pipe all subsequent MongoDB commands directly to tenant Agent (which already
			// authenticated to tenant MongoDB via local SCRAM-SHA-256 and enforces read-only guard!).
			transport.BidirectionalPipe(clientConn, stream)
			return

		default:
			synthID++
			_ = writeHubMongoAuthErr(clientConn, synthID, reqID, "dataproxy-hub: SASL PLAIN authentication with job ticket required before commands")
			return
		}
	}
}

// RFC 4616 SASL PLAIN format: [authzid] NUL authcid NUL passwd
func parseSASLPlainPayload(b []byte) (user, pass string, ok bool) {
	parts := bytes.Split(b, []byte{0x00})
	if len(parts) != 3 {
		return "", "", false
	}
	user = string(parts[1])
	pass = string(parts[2])
	return user, pass, user != "" && pass != ""
}

func buildHubMongoHelloDoc() []byte {
	mechsArr := buildHubBSON(hubBsonStr("0", "PLAIN"))
	return buildHubBSON(
		hubBsonBool("isWritablePrimary", true),
		hubBsonBool("ismaster", true),
		hubBsonInt32("maxBsonObjectSize", 16777216),
		hubBsonInt32("maxMessageSizeBytes", 48000000),
		hubBsonInt32("maxWriteBatchSize", 100000),
		hubBsonInt32("logicalSessionTimeoutMinutes", 30),
		hubBsonInt32("minWireVersion", 0),
		hubBsonInt32("maxWireVersion", 25),
		hubBsonBool("readOnly", false),
		append([]byte{0x04, 's', 'a', 's', 'l', 'S', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', 'M', 'e', 'c', 'h', 's', 0x00}, mechsArr...),
		hubBsonDouble("ok", 1.0),
	)
}

func writeHubMongoAuthErr(w io.Writer, reqID, respTo uint32, msg string) error {
	doc := buildHubBSON(
		hubBsonDouble("ok", 0.0),
		hubBsonStr("errmsg", msg),
		hubBsonInt32("code", 18),
		hubBsonStr("codeName", "AuthenticationFailed"),
	)
	return writeHubMongoOpMsg(w, reqID, respTo, doc)
}

const maxHubPreAuthMongoMsgBytes = 256 * 1024 // Pre-auth hello / saslStart safety cap

func readHubMongoMsg(r io.Reader) (reqID, respTo, opCode uint32, body []byte, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	msgLen := binary.LittleEndian.Uint32(hdr[0:4])
	if msgLen < 16 || msgLen > maxHubPreAuthMongoMsgBytes {
		return 0, 0, 0, nil, errors.New("invalid or oversized pre-auth mongo msg len")
	}
	reqID = binary.LittleEndian.Uint32(hdr[4:8])
	respTo = binary.LittleEndian.Uint32(hdr[8:12])
	opCode = binary.LittleEndian.Uint32(hdr[12:16])
	body = make([]byte, msgLen-16)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, 0, nil, err
	}
	return reqID, respTo, opCode, body, nil
}

func writeHubMongoOpMsg(w io.Writer, reqID, respTo uint32, bsonDoc []byte) error {
	total := 16 + 5 + len(bsonDoc)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:8], reqID)
	binary.LittleEndian.PutUint32(buf[8:12], respTo)
	binary.LittleEndian.PutUint32(buf[12:16], hubMongoOpMsg)
	// flagBits=0 (4B), section kind=0 (1B)
	copy(buf[21:], bsonDoc)
	_, err := w.Write(buf)
	return err
}

func writeHubMongoOpReply(w io.Writer, reqID, respTo uint32, bsonDoc []byte) error {
	// OP_REPLY: header(16) + responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + doc
	total := 16 + 20 + len(bsonDoc)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:8], reqID)
	binary.LittleEndian.PutUint32(buf[8:12], respTo)
	binary.LittleEndian.PutUint32(buf[12:16], hubMongoOpReply)
	binary.LittleEndian.PutUint32(buf[32:36], 1) // numberReturned=1
	copy(buf[36:], bsonDoc)
	_, err := w.Write(buf)
	return err
}

func extractHubOpMsgDoc(body []byte) ([]byte, error) {
	if len(body) < 10 {
		return nil, errors.New("short OP_MSG")
	}
	pos := 4
	for pos < len(body) {
		kind := body[pos]
		pos++
		if kind == 0 {
			if pos+4 > len(body) {
				return nil, errors.New("short bson len")
			}
			dLen := int(binary.LittleEndian.Uint32(body[pos : pos+4]))
			if dLen < 5 || pos+dLen > len(body) {
				return nil, errors.New("invalid bson len")
			}
			return body[pos : pos+dLen], nil
		}
		if kind == 1 && pos+4 <= len(body) {
			sLen := int(binary.LittleEndian.Uint32(body[pos : pos+4]))
			if sLen < 4 || pos+sLen > len(body) {
				return nil, errors.New("invalid section 1")
			}
			pos += sLen
			continue
		}
		return nil, errors.New("unsupported section kind")
	}
	return nil, errors.New("no kind-0 section")
}

type hubBsonField struct {
	strVal string
	binVal []byte
}

func parseHubMongoBSON(doc []byte) (cmdName string, fields map[string]hubBsonField) {
	fields = make(map[string]hubBsonField)
	if len(doc) < 5 {
		return "", fields
	}
	end := int(binary.LittleEndian.Uint32(doc[0:4])) - 1
	if end > len(doc)-1 {
		end = len(doc) - 1
	}
	pos := 4
	for pos < end {
		vType := doc[pos]
		pos++
		if vType == 0x00 {
			break
		}
		kEnd := bytes.IndexByte(doc[pos:end], 0x00)
		if kEnd < 0 {
			break
		}
		key := string(doc[pos : pos+kEnd])
		if cmdName == "" {
			cmdName = key
		}
		pos += kEnd + 1
		switch vType {
		case 0x01, 0x09, 0x11, 0x12:
			pos += 8
		case 0x02, 0x0d, 0x0e:
			if pos+4 > end {
				return cmdName, fields
			}
			sLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4
			if sLen < 1 || pos+sLen > end {
				return cmdName, fields
			}
			fields[key] = hubBsonField{strVal: string(doc[pos : pos+sLen-1])}
			pos += sLen
		case 0x03, 0x04:
			if pos+4 > end {
				return cmdName, fields
			}
			subLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			if subLen < 5 || pos+subLen > end {
				return cmdName, fields
			}
			pos += subLen
		case 0x05:
			if pos+5 > end {
				return cmdName, fields
			}
			bLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 5
			if bLen < 0 || pos+bLen > end {
				return cmdName, fields
			}
			fields[key] = hubBsonField{binVal: doc[pos : pos+bLen]}
			pos += bLen
		case 0x06, 0x0a, 0x7f, 0xff:
		case 0x07:
			pos += 12
		case 0x08:
			pos += 1
		case 0x10:
			pos += 4
		case 0x13:
			pos += 16
		default:
			return cmdName, fields
		}
	}
	return cmdName, fields
}

func buildHubBSON(fields ...[]byte) []byte {
	total := 5
	for _, f := range fields {
		total += len(f)
	}
	buf := make([]byte, 0, total)
	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], uint32(total))
	buf = append(buf, lb[:]...)
	for _, f := range fields {
		buf = append(buf, f...)
	}
	buf = append(buf, 0x00)
	return buf
}

func hubBsonInt32(k string, v int32) []byte {
	var b bytes.Buffer
	b.WriteByte(0x10)
	b.WriteString(k)
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, v)
	return b.Bytes()
}

func hubBsonDouble(k string, v float64) []byte {
	var b bytes.Buffer
	b.WriteByte(0x01)
	b.WriteString(k)
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, math.Float64bits(v))
	return b.Bytes()
}

func hubBsonBool(k string, v bool) []byte {
	var b bytes.Buffer
	b.WriteByte(0x08)
	b.WriteString(k)
	b.WriteByte(0)
	if v {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func hubBsonStr(k, v string) []byte {
	var b bytes.Buffer
	b.WriteByte(0x02)
	b.WriteString(k)
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(v)+1))
	b.WriteString(v)
	b.WriteByte(0)
	return b.Bytes()
}

func hubBsonBin(k string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x05)
	b.WriteString(k)
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	b.WriteByte(0)
	b.Write(data)
	return b.Bytes()
}
