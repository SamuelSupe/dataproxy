package guard

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dataproxy/internal/transport"
)

// RedisGuardConfig configures tenant-local Redis RESP2/3 read-only guard and credential injection.
type RedisGuardConfig struct {
	ReadOnly     bool
	InjectCreds  bool
	UsernameSpec string // Optional (Redis 6+ ACL username; empty uses default user)
	PasswordSpec string // Supports literal, env:VAR, file:/path
}

func (c RedisGuardConfig) Enabled() bool {
	return c.ReadOnly || c.InjectCreds
}

// RedisProbeInfo holds metadata returned by ProbeRedis.
type RedisProbeInfo struct {
	AuthRequired bool
	Reply        string
	Latency      time.Duration
}

// ProbeRedis sends a RESP PING command to check Redis reachability and auth requirement.
func ProbeRedis(addr string, timeout time.Duration) (*RedisProbeInfo, error) {
	return ProbeRedisTLS(addr, timeout, nil)
}

// ProbeRedisTLS sends a RESP PING over optional direct TLS (--tls-port).
func ProbeRedisTLS(addr string, timeout time.Duration, tlsCfg *tls.Config) (*RedisProbeInfo, error) {
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

	if _, err := io.WriteString(conn, "*1\r\n$4\r\nPING\r\n"); err != nil {
		return nil, fmt.Errorf("write redis PING: %w", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read redis PING reply: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "+PONG") {
		return &RedisProbeInfo{AuthRequired: false, Reply: line, Latency: time.Since(start)}, nil
	}
	if strings.HasPrefix(line, "-NOAUTH") || strings.Contains(line, "Authentication required") {
		return &RedisProbeInfo{AuthRequired: true, Reply: line, Latency: time.Since(start)}, nil
	}
	return nil, fmt.Errorf("unexpected redis reply %q", line)
}

var redisReadOnlyCommands = map[string]bool{
	"PING": true, "ECHO": true, "QUIT": true, "SELECT": true,
	"AUTH": true, "HELLO": true, "INFO": true, "TIME": true, "ROLE": true,
	"DBSIZE": true, "RANDOMKEY": true, "COMMAND": true,
	// Keys / Strings
	"GET": true, "MGET": true, "STRLEN": true, "GETRANGE": true, "SUBSTR": true,
	"EXISTS": true, "TYPE": true, "TTL": true, "PTTL": true, "EXPIRETIME": true, "PEXPIRETIME": true,
	"KEYS": true, "SCAN": true, "BITCOUNT": true, "BITPOS": true, "GETBIT": true,
	// Hashes
	"HGET": true, "HMGET": true, "HGETALL": true, "HKEYS": true, "HVALS": true,
	"HLEN": true, "HEXISTS": true, "HSCAN": true, "HSTRLEN": true,
	// Lists
	"LLEN": true, "LRANGE": true, "LINDEX": true, "LPOS": true,
	// Sets
	"SCARD": true, "SISMEMBER": true, "SMISMEMBER": true, "SMEMBERS": true, "SRANDMEMBER": true, "SSCAN": true,
	// Sorted Sets
	"ZCARD": true, "ZCOUNT": true, "ZLEXCOUNT": true, "ZRANGE": true, "ZRANGEBYLEX": true,
	"ZRANGEBYSCORE": true, "ZREVRANGE": true, "ZREVRANGEBYLEX": true, "ZREVRANGEBYSCORE": true,
	"ZRANK": true, "ZREVRANK": true, "ZSCORE": true, "ZMSCORE": true, "ZSCAN": true,
	// Streams / HyperLogLog / Geo / JSON
	"XLEN": true, "XRANGE": true, "XREVRANGE": true, "XREAD": true, "XINFO": true,
	"PFCOUNT": true, "GEOPOS": true, "GEODIST": true, "GEORADIUS_RO": true, "GEORADIUSBYMEMBER_RO": true, "GEOSEARCH": true,
	"JSON.GET": true, "JSON.MGET": true, "JSON.TYPE": true, "JSON.OBJLEN": true, "JSON.ARRLEN": true, "JSON.OBJKEYS": true,
}

// IsReadOnlyRedisCommand checks whether a parsed RESP command is safe for read-only mode.
func IsReadOnlyRedisCommand(args []string) (bool, string) {
	if len(args) == 0 {
		return true, ""
	}
	cmd := strings.ToUpper(args[0])
	if cmd == "CLIENT" {
		if len(args) >= 2 {
			sub := strings.ToUpper(args[1])
			if sub == "GETNAME" || sub == "ID" || sub == "INFO" || sub == "LIST" || sub == "SETNAME" || sub == "SETINFO" {
				return true, ""
			}
		}
		return false, "Redis CLIENT subcommand is blocked in read-only mode"
	}
	if cmd == "CLUSTER" {
		if len(args) >= 2 {
			sub := strings.ToUpper(args[1])
			if sub == "INFO" || sub == "NODES" || sub == "SLOTS" || sub == "SHARDS" {
				return true, ""
			}
		}
		return false, "Redis CLUSTER subcommand is blocked in read-only mode"
	}
	if redisReadOnlyCommands[cmd] {
		return true, ""
	}
	return false, "Redis command " + cmd + " is blocked by tenant read-only policy"
}

// RedisProxy intercepts Redis RESP2/RESP3 traffic for local credential injection and/or read-only filtering.
type RedisProxy struct {
	cfg          RedisGuardConfig
	blockedCount atomic.Int64
}

func NewRedisProxy(cfg RedisGuardConfig) *RedisProxy {
	return &RedisProxy{cfg: cfg}
}

func (p *RedisProxy) BlockedCommands() int64 {
	return p.blockedCount.Load()
}

func (p *RedisProxy) Proxy(
	clientConn, serverConn net.Conn,
	onBlocked func(cmd, reason string),
) (bytesIn, bytesOut int64, err error) {
	var realUser, realPass string
	if p.cfg.InjectCreds {
		realUser, err = ResolveSecret(p.cfg.UsernameSpec)
		if err != nil {
			_, _ = io.WriteString(clientConn, "-ERR dataproxy-agent: local redis username resolution failed\r\n")
			return 0, 0, err
		}
		realPass, err = ResolveSecret(p.cfg.PasswordSpec)
		if err != nil {
			_, _ = io.WriteString(clientConn, "-ERR dataproxy-agent: local redis password resolution failed\r\n")
			return 0, 0, err
		}
		// Proactively authenticate the tenant-side Redis connection using real local credentials!
		if realPass != "" {
			var authArgs []string
			if realUser != "" {
				authArgs = []string{"AUTH", realUser, realPass}
			} else {
				authArgs = []string{"AUTH", realPass}
			}
			if _, err := serverConn.Write(encodeRESPArray(authArgs)); err != nil {
				return 0, 0, fmt.Errorf("send proactive redis AUTH: %w", err)
			}
			srvBR := transport.GetBufioReader(serverConn)
			defer transport.PutBufioReader(srvBR)
			line, err := srvBR.ReadString('\n')
			if err != nil {
				return 0, 0, fmt.Errorf("read proactive redis AUTH reply: %w", err)
			}
			if !strings.HasPrefix(line, "+OK") {
				_, _ = io.WriteString(clientConn, "-ERR dataproxy-agent: local redis credential authentication failed\r\n")
				return 0, 0, fmt.Errorf("redis local AUTH failed: %s", strings.TrimSpace(line))
			}
			// Wrap serverConn if any extra bytes were buffered
			if srvBR.Buffered() > 0 {
				serverConn = &peekedConn{Conn: serverConn, r: srvBR}
			}
		}
	}

	// If only credential injection is enabled (no ReadOnly) AND we still need to intercept
	// dummy AUTH/HELLO commands from the client so they don't overwrite our real AUTH with WRONGPASS,
	// we parse client commands cleanly and stream server replies back concurrently.
	if !p.cfg.ReadOnly && !p.cfg.InjectCreds {
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

	cliBR := transport.GetBufioReader(clientConn)
	defer transport.PutBufioReader(cliBR)
	for {
		args, raw, err := readRESPCommand(cliBR)
		if err != nil {
			break
		}
		bytesIn += int64(len(raw))
		if len(args) == 0 {
			continue
		}

		cmdUpper := strings.ToUpper(args[0])

		// Handle dummy AUTH / HELLO ... AUTH when local credential injection is enabled.
		if p.cfg.InjectCreds && cmdUpper == "AUTH" {
			clientWriteMu.Lock()
			_, werr := io.WriteString(clientConn, "+OK\r\n")
			clientWriteMu.Unlock()
			if werr != nil {
				break
			}
			continue
		}
		if p.cfg.InjectCreds && cmdUpper == "HELLO" && realPass != "" {
			args = rewriteRedisHelloAuth(args, realUser, realPass)
			raw = encodeRESPArray(args)
		}

		if p.cfg.ReadOnly {
			if ok, reason := IsReadOnlyRedisCommand(args); !ok {
				p.blockedCount.Add(1)
				if onBlocked != nil {
					onBlocked(cmdUpper, reason)
				}
				clientWriteMu.Lock()
				_, werr := fmt.Fprintf(clientConn, "-ERR dataproxy-agent: %s\r\n", reason)
				clientWriteMu.Unlock()
				if werr != nil {
					break
				}
				continue
			}
		}

		if _, err := serverConn.Write(raw); err != nil {
			break
		}
		if cmdUpper == "QUIT" {
			break
		}
	}

	_ = serverConn.Close()
	<-srvDone
	return bytesIn, bytesOut + serverCopyBytes.Load(), nil
}

func rewriteRedisHelloAuth(args []string, realUser, realPass string) []string {
	out := append([]string(nil), args...)
	u := realUser
	if u == "" {
		u = "default"
	}
	for i := 1; i < len(out); i++ {
		if strings.EqualFold(out[i], "AUTH") && i+2 < len(out) {
			out[i+1] = u
			out[i+2] = realPass
			return out
		}
	}
	return out
}

func encodeRESPArray(args []string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.Bytes()
}

func readRESPCommand(br *bufio.Reader) ([]string, []byte, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, nil, err
	}
	if first[0] != '*' {
		// Inline command (e.g. "PING\r\n")
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		fields := strings.Fields(string(line))
		return fields, line, nil
	}

	var raw bytes.Buffer
	hdrLine, err := br.ReadBytes('\n')
	if err != nil {
		return nil, nil, err
	}
	raw.Write(hdrLine)
	count, err := strconv.Atoi(strings.TrimSpace(string(hdrLine[1:])))
	if err != nil || count < 0 || count > 100000 {
		return nil, nil, errors.New("invalid RESP array length")
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lenLine, err := br.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		raw.Write(lenLine)
		if len(lenLine) < 2 || lenLine[0] != '$' {
			return nil, nil, errors.New("expected RESP bulk string")
		}
		bulkLen, err := strconv.Atoi(strings.TrimSpace(string(lenLine[1:])))
		if err != nil || bulkLen < 0 || bulkLen > 64*1024*1024 {
			return nil, nil, errors.New("invalid RESP bulk string length")
		}
		buf := make([]byte, bulkLen+2) // payload + \r\n
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, nil, err
		}
		raw.Write(buf)
		args = append(args, string(buf[:bulkLen]))
	}
	return args, raw.Bytes(), nil
}
