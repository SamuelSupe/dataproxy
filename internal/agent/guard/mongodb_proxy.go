package guard

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/transport"
)

const (
	mongoOpReply uint32 = 1
	mongoOpQuery uint32 = 2004
	mongoOpMsg   uint32 = 2013
)

// MongoGuardConfig configures tenant-local MongoDB OP_MSG read-only guard and credential injection.
type MongoGuardConfig struct {
	ReadOnly     bool
	InjectCreds  bool
	UsernameSpec string
	PasswordSpec string
	AuthSource   string // Default "admin"
}

func (c MongoGuardConfig) Enabled() bool {
	return c.ReadOnly || c.InjectCreds
}

// MongoProbeInfo holds metadata returned by ProbeMongoDB via an unauthenticated {hello: 1} OP_MSG.
type MongoProbeInfo struct {
	IsWritablePrimary bool
	IsSecondary       bool
	MaxWireVersion    int32
	SetName           string
	Latency           time.Duration
}

// ProbeMongoDB sends an OP_MSG {hello: 1, $db: "admin"} command to probe MongoDB without credentials.
func ProbeMongoDB(addr string, timeout time.Duration) (*MongoProbeInfo, error) {
	return ProbeMongoDBTLS(addr, timeout, nil)
}

// ProbeMongoDBTLS probes MongoDB over optional direct TLS (--tlsMode requireTLS).
func ProbeMongoDBTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*MongoProbeInfo, error) {
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

	doc := buildBSONDoc(
		bsonInt32("hello", 1),
		bsonString("$db", "admin"),
	)
	if err := writeMongoOpMsg(conn, 1, 0, doc); err != nil {
		return nil, fmt.Errorf("write mongo hello: %w", err)
	}
	_, _, opCode, body, err := readMongoMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("read mongo hello reply: %w", err)
	}
	if opCode != mongoOpMsg || len(body) < 10 {
		return nil, fmt.Errorf("unexpected mongo reply opcode %d", opCode)
	}
	respDoc, err := extractOpMsgBodyDoc(body)
	if err != nil {
		return nil, err
	}
	elems, err := parseBSONTopLevel(respDoc)
	if err != nil {
		return nil, err
	}
	info := &MongoProbeInfo{Latency: time.Since(start)}
	for _, el := range elems {
		switch el.key {
		case "isWritablePrimary":
			info.IsWritablePrimary = el.boolVal
		case "secondary":
			info.IsSecondary = el.boolVal
		case "maxWireVersion":
			info.MaxWireVersion = el.int32Val
		case "setName":
			info.SetName = el.strVal
		}
	}
	return info, nil
}

// Strict allowlist of read-only MongoDB commands.
var mongoReadOnlyCommands = map[string]bool{
	"hello": true, "ismaster": true, "isMaster": true, "ping": true,
	"buildInfo": true, "buildinfo": true, "serverStatus": true, "hostInfo": true,
	"whatsmyuri": true, "connectionStatus": true, "getLog": true,
	"find": true, "getMore": true, "killCursors": true,
	"count": true, "distinct": true, "aggregate": true, "explain": true,
	"listDatabases": true, "listCollections": true, "listIndexes": true,
	"collStats": true, "dbStats": true, "dataSize": true,
	"saslStart": true, "saslContinue": true, "endSessions": true,
	"getParameter": true, "features": true, "atlasVersion": true,
}

// CheckMongoCommandReadOnly inspects a BSON command document and verifies it is strictly read-only.
// For "aggregate", it additionally inspects every pipeline stage to block "$out" and "$merge".
func CheckMongoCommandReadOnly(bsonDoc []byte) (cmdName string, allowed bool, reason string) {
	elems, err := parseBSONTopLevel(bsonDoc)
	if err != nil || len(elems) == 0 {
		return "unknown", false, "malformed MongoDB BSON command blocked in read-only mode"
	}
	cmdName = elems[0].key
	if !mongoReadOnlyCommands[cmdName] {
		return cmdName, false, "MongoDB command '" + cmdName + "' is blocked by tenant read-only policy"
	}
	if cmdName == "aggregate" {
		for _, el := range elems {
			if el.key == "pipeline" && el.valType == 0x04 { // BSON Array
				stages, _ := parseBSONTopLevel(el.rawVal)
				for _, st := range stages {
					if st.valType == 0x03 { // Embedded stage document
						stageFields, _ := parseBSONTopLevel(st.rawVal)
						for _, f := range stageFields {
							if f.key == "$out" || f.key == "$merge" {
								return cmdName, false, "MongoDB aggregate stage '" + f.key + "' is blocked by tenant read-only policy"
							}
						}
					}
				}
			}
		}
	}
	return cmdName, true, ""
}

// MongoProxy intercepts MongoDB OP_MSG traffic for local proactive SCRAM-SHA-256
// credential injection and/or strict command read-only filtering.
type MongoProxy struct {
	cfg          MongoGuardConfig
	blockedCount atomic.Int64
}

func NewMongoProxy(cfg MongoGuardConfig) *MongoProxy {
	if cfg.AuthSource == "" {
		cfg.AuthSource = "admin"
	}
	return &MongoProxy{cfg: cfg}
}

func (p *MongoProxy) BlockedCommands() int64 {
	return p.blockedCount.Load()
}

func (p *MongoProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(cmd, reason string),
) (bytesIn, bytesOut int64, err error) {
	// 1. Proactively authenticate tenant-side MongoDB connection using local env/file credentials!
	// Central clients connect without DB passwords; tenant DB password never leaves the intranet.
	if p.cfg.InjectCreds {
		realUser, err := ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			return 0, 0, fmt.Errorf("resolve local mongo username: %w", err)
		}
		realPass, err := ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			return 0, 0, fmt.Errorf("resolve local mongo password: %w", err)
		}
		if err := authenticateMongoSCRAM(serverConn, p.cfg.AuthSource, realUser, realPass); err != nil {
			return 0, 0, fmt.Errorf("local mongo SCRAM-SHA-256 auth failed: %w", err)
		}
	}

	if !p.cfg.ReadOnly {
		in2, out2 := transport.BidirectionalPipe(clientConn, serverConn)
		return in2, out2, nil
	}

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

	var synthReqID uint32 = 900000000
	for {
		reqID, respTo, opCode, body, err := readMongoMessage(clientConn)
		if err != nil {
			break
		}
		bytesIn += int64(len(body) + 16)

		switch opCode {
		case mongoOpMsg:
			cmdDoc, parseErr := extractOpMsgBodyDoc(body)
			if parseErr != nil {
				p.blockedCount.Add(1)
				synthReqID++
				clientWriteMu.Lock()
				_ = writeMongoErrorOpMsg(clientConn, synthReqID, reqID, "malformed OP_MSG blocked by tenant policy")
				clientWriteMu.Unlock()
				continue
			}
			cmdName, ok, reason := CheckMongoCommandReadOnly(cmdDoc)
			if !ok {
				p.blockedCount.Add(1)
				if onBlocked != nil {
					onBlocked(cmdName, reason)
				}
				synthReqID++
				clientWriteMu.Lock()
				_ = writeMongoErrorOpMsg(clientConn, synthReqID, reqID, "dataproxy-agent: "+reason)
				clientWriteMu.Unlock()
				continue
			}

		case mongoOpQuery:
			// Legacy OP_QUERY (used by some older drivers only for admin.$cmd hello/isMaster).
			// Block any legacy OP_QUERY that isn't a read-only $cmd query!
			if !isLegacyReadOnlyOpQuery(body) {
				p.blockedCount.Add(1)
				if onBlocked != nil {
					onBlocked("OP_QUERY", "legacy non-readonly OP_QUERY blocked")
				}
				break
			}

		default:
			// Legacy write opcodes (OP_INSERT=2002, OP_UPDATE=2001, OP_DELETE=2006) are strictly blocked!
			p.blockedCount.Add(1)
			if onBlocked != nil {
				onBlocked(fmt.Sprintf("OPCODE_%d", opCode), "legacy MongoDB write opcode blocked")
			}
			continue
		}

		if err := writeRawMongoMessage(serverConn, reqID, respTo, opCode, body); err != nil {
			break
		}
	}

	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

// authenticateMongoSCRAM performs MongoDB SCRAM-SHA-256 authentication directly over serverConn.
func authenticateMongoSCRAM(conn net.Conn, authSource, username, password string) error {
	scram, err := newSCRAMSHA256Client(username, password)
	if err != nil {
		return err
	}
	if authSource == "" {
		authSource = "admin"
	}

	// Step 1: saslStart
	startDoc := buildBSONDoc(
		bsonInt32("saslStart", 1),
		bsonString("mechanism", "SCRAM-SHA-256"),
		bsonBinary("payload", []byte(scram.ClientFirstMessage())),
		bsonString("$db", authSource),
	)
	if err := writeMongoOpMsg(conn, 1001, 0, startDoc); err != nil {
		return err
	}
	_, _, opCode, body, err := readMongoMessage(conn)
	if err != nil || opCode != mongoOpMsg {
		return fmt.Errorf("read saslStart reply: err=%v opcode=%d", err, opCode)
	}
	respDoc, err := extractOpMsgBodyDoc(body)
	if err != nil {
		return err
	}
	convID, serverFirst, done, okVal, errMsg := parseMongoSASLReply(respDoc)
	if okVal != 1.0 {
		return fmt.Errorf("saslStart rejected: %s", errMsg)
	}
	if done {
		return nil
	}

	// Step 2: saslContinue with client proof
	clientFinal, err := scram.ProcessServerFirst(string(serverFirst))
	if err != nil {
		return err
	}
	cont1Doc := buildBSONDoc(
		bsonInt32("saslContinue", 1),
		bsonInt32("conversationId", convID),
		bsonBinary("payload", []byte(clientFinal)),
		bsonString("$db", authSource),
	)
	if err := writeMongoOpMsg(conn, 1002, 0, cont1Doc); err != nil {
		return err
	}
	_, _, opCode, body, err = readMongoMessage(conn)
	if err != nil || opCode != mongoOpMsg {
		return fmt.Errorf("read saslContinue-1 reply: err=%v opcode=%d", err, opCode)
	}
	respDoc, err = extractOpMsgBodyDoc(body)
	if err != nil {
		return err
	}
	convID, serverFinal, done, okVal, errMsg := parseMongoSASLReply(respDoc)
	if okVal != 1.0 {
		return fmt.Errorf("saslContinue-1 rejected: %s", errMsg)
	}
	if err := scram.VerifyServerFinal(string(serverFinal)); err != nil {
		return err
	}
	if done {
		return nil
	}

	// Step 3: final empty saslContinue to complete MongoDB SCRAM conversation
	cont2Doc := buildBSONDoc(
		bsonInt32("saslContinue", 1),
		bsonInt32("conversationId", convID),
		bsonBinary("payload", nil),
		bsonString("$db", authSource),
	)
	if err := writeMongoOpMsg(conn, 1003, 0, cont2Doc); err != nil {
		return err
	}
	_, _, opCode, body, err = readMongoMessage(conn)
	if err != nil || opCode != mongoOpMsg {
		return fmt.Errorf("read saslContinue-2 reply: err=%v opcode=%d", err, opCode)
	}
	respDoc, err = extractOpMsgBodyDoc(body)
	if err != nil {
		return err
	}
	_, _, _, okVal, errMsg = parseMongoSASLReply(respDoc)
	if okVal != 1.0 {
		return fmt.Errorf("saslContinue-2 rejected: %s", errMsg)
	}
	return nil
}

func parseMongoSASLReply(doc []byte) (convID int32, payload []byte, done bool, okVal float64, errMsg string) {
	elems, _ := parseBSONTopLevel(doc)
	for _, el := range elems {
		switch el.key {
		case "conversationId":
			convID = el.int32Val
		case "payload":
			payload = el.binVal
		case "done":
			done = el.boolVal
		case "ok":
			if el.valType == 0x01 {
				okVal = el.doubleVal
			} else if el.valType == 0x10 {
				okVal = float64(el.int32Val)
			}
		case "errmsg":
			errMsg = el.strVal
		}
	}
	return
}

func isLegacyReadOnlyOpQuery(body []byte) bool {
	// OP_QUERY: flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4) + query(BSON)
	if len(body) < 13 {
		return false
	}
	pos := 4
	nul := bytes.IndexByte(body[pos:], 0x00)
	if nul < 0 {
		return false
	}
	coll := string(body[pos : pos+nul])
	pos += nul + 1 + 8
	if pos >= len(body) {
		return false
	}
	if coll != "admin.$cmd" && !bytes.HasSuffix([]byte(coll), []byte(".$cmd")) {
		return false
	}
	_, ok, _ := CheckMongoCommandReadOnly(body[pos:])
	return ok
}

func readMongoMessage(r io.Reader) (reqID, respTo, opCode uint32, body []byte, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	msgLen := binary.LittleEndian.Uint32(hdr[0:4])
	if msgLen < 16 || msgLen > 48*1024*1024 {
		return 0, 0, 0, nil, fmt.Errorf("invalid mongo message length %d", msgLen)
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

func writeRawMongoMessage(w io.Writer, reqID, respTo, opCode uint32, body []byte) error {
	total := 16 + len(body)
	if total <= transport.CopyBufferSize {
		bufPtr := transport.GetCopyBuf()
		buf := (*bufPtr)[:total]
		binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
		binary.LittleEndian.PutUint32(buf[4:8], reqID)
		binary.LittleEndian.PutUint32(buf[8:12], respTo)
		binary.LittleEndian.PutUint32(buf[12:16], opCode)
		copy(buf[16:], body)
		_, err := w.Write(buf)
		transport.PutCopyBuf(bufPtr)
		return err
	}
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:8], reqID)
	binary.LittleEndian.PutUint32(buf[8:12], respTo)
	binary.LittleEndian.PutUint32(buf[12:16], opCode)
	copy(buf[16:], body)
	_, err := w.Write(buf)
	return err
}

func writeMongoOpMsg(w io.Writer, reqID, respTo uint32, bsonDoc []byte) error {
	body := make([]byte, 5+len(bsonDoc))
	// flagBits = 0 (4B), section kind = 0 (1B)
	copy(body[5:], bsonDoc)
	return writeRawMongoMessage(w, reqID, respTo, mongoOpMsg, body)
}

func writeMongoErrorOpMsg(w io.Writer, reqID, respTo uint32, msg string) error {
	doc := buildBSONDoc(
		bsonDouble("ok", 0.0),
		bsonString("errmsg", msg),
		bsonInt32("code", 13),
		bsonString("codeName", "Unauthorized"),
	)
	return writeMongoOpMsg(w, reqID, respTo, doc)
}

func extractOpMsgBodyDoc(body []byte) ([]byte, error) {
	// OP_MSG body: flagBits(4) + sections...
	if len(body) < 10 {
		return nil, errors.New("truncated OP_MSG")
	}
	pos := 4
	for pos < len(body) {
		kind := body[pos]
		pos++
		switch kind {
		case 0: // Kind 0: Body BSON document
			if pos+4 > len(body) {
				return nil, errors.New("truncated BSON length in OP_MSG")
			}
			docLen := int(binary.LittleEndian.Uint32(body[pos : pos+4]))
			if docLen < 5 || pos+docLen > len(body) {
				return nil, errors.New("invalid BSON length in OP_MSG")
			}
			return body[pos : pos+docLen], nil
		case 1: // Kind 1: Document sequence (skip to find kind 0 body)
			if pos+4 > len(body) {
				return nil, errors.New("truncated section 1 length")
			}
			secLen := int(binary.LittleEndian.Uint32(body[pos : pos+4]))
			if secLen < 4 || pos+secLen > len(body) {
				return nil, errors.New("invalid section 1 length")
			}
			pos += secLen
		default:
			return nil, fmt.Errorf("unknown OP_MSG section kind %d", kind)
		}
	}
	return nil, errors.New("no kind-0 body document in OP_MSG")
}

// --- Minimal Zero-Dependency BSON Encoder & Top-Level Parser ---

type bsonElem struct {
	key       string
	valType   byte
	doubleVal float64
	strVal    string
	boolVal   bool
	int32Val  int32
	binVal    []byte
	rawVal    []byte
}

func parseBSONTopLevel(doc []byte) ([]bsonElem, error) {
	if len(doc) < 5 {
		return nil, errors.New("bson too short")
	}
	docLen := int(binary.LittleEndian.Uint32(doc[0:4]))
	if docLen > len(doc) || docLen < 5 {
		return nil, errors.New("invalid bson length")
	}
	var out []bsonElem
	pos := 4
	end := docLen - 1 // final byte is 0x00
	for pos < end {
		vType := doc[pos]
		pos++
		if vType == 0x00 {
			break
		}
		kEnd := bytes.IndexByte(doc[pos:end], 0x00)
		if kEnd < 0 {
			return nil, errors.New("unterminated bson key")
		}
		key := string(doc[pos : pos+kEnd])
		pos += kEnd + 1

		el := bsonElem{key: key, valType: vType}
		switch vType {
		case 0x01: // double (8B)
			if pos+8 > end {
				return nil, errors.New("truncated double")
			}
			el.doubleVal = math.Float64frombits(binary.LittleEndian.Uint64(doc[pos : pos+8]))
			pos += 8
		case 0x02, 0x0d, 0x0e: // UTF-8 string / JS / symbol
			if pos+4 > end {
				return nil, errors.New("truncated string len")
			}
			sLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4
			if sLen < 1 || pos+sLen > end {
				return nil, errors.New("truncated string")
			}
			el.strVal = string(doc[pos : pos+sLen-1])
			pos += sLen
		case 0x03, 0x04: // embedded document / array
			if pos+4 > end {
				return nil, errors.New("truncated subdoc len")
			}
			subLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			if subLen < 5 || pos+subLen > end {
				return nil, errors.New("truncated subdoc")
			}
			el.rawVal = doc[pos : pos+subLen]
			pos += subLen
		case 0x05: // binary
			if pos+5 > end {
				return nil, errors.New("truncated binary header")
			}
			bLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 5 // len(4) + subtype(1)
			if bLen < 0 || pos+bLen > end {
				return nil, errors.New("truncated binary payload")
			}
			el.binVal = doc[pos : pos+bLen]
			pos += bLen
		case 0x06, 0x0a, 0x7f, 0xff: // undefined / null / maxKey / minKey (0B)
		case 0x07: // ObjectId (12B)
			pos += 12
		case 0x08: // boolean (1B)
			if pos+1 > end {
				return nil, errors.New("truncated bool")
			}
			el.boolVal = doc[pos] != 0
			pos++
		case 0x09, 0x11, 0x12: // UTC datetime / timestamp / int64 (8B)
			pos += 8
		case 0x0b: // regex (two cstrings)
			for c := 0; c < 2; c++ {
				z := bytes.IndexByte(doc[pos:end], 0x00)
				if z < 0 {
					return nil, errors.New("unterminated regex")
				}
				pos += z + 1
			}
		case 0x10: // int32 (4B)
			if pos+4 > end {
				return nil, errors.New("truncated int32")
			}
			el.int32Val = int32(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4
		case 0x13: // decimal128 (16B)
			pos += 16
		default:
			return out, nil // stop safely on unknown exotic type after capturing leading command key
		}
		if pos > end {
			return nil, errors.New("bson element overran document")
		}
		out = append(out, el)
	}
	return out, nil
}

func buildBSONDoc(fields ...[]byte) []byte {
	total := 5 // 4B length + 1B trailing NUL
	for _, f := range fields {
		total += len(f)
	}
	buf := make([]byte, 0, total)
	var lenBytes [4]byte
	binary.LittleEndian.PutUint32(lenBytes[:], uint32(total))
	buf = append(buf, lenBytes[:]...)
	for _, f := range fields {
		buf = append(buf, f...)
	}
	buf = append(buf, 0x00)
	return buf
}

func bsonInt32(key string, val int32) []byte {
	var b bytes.Buffer
	b.WriteByte(0x10)
	b.WriteString(key)
	b.WriteByte(0x00)
	_ = binary.Write(&b, binary.LittleEndian, val)
	return b.Bytes()
}

func bsonDouble(key string, val float64) []byte {
	var b bytes.Buffer
	b.WriteByte(0x01)
	b.WriteString(key)
	b.WriteByte(0x00)
	_ = binary.Write(&b, binary.LittleEndian, math.Float64bits(val))
	return b.Bytes()
}

func bsonString(key, val string) []byte {
	var b bytes.Buffer
	b.WriteByte(0x02)
	b.WriteString(key)
	b.WriteByte(0x00)
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(val)+1))
	b.WriteString(val)
	b.WriteByte(0x00)
	return b.Bytes()
}

func bsonBinary(key string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x05)
	b.WriteString(key)
	b.WriteByte(0x00)
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	b.WriteByte(0x00) // subtype generic binary
	b.Write(data)
	return b.Bytes()
}
