package hub

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"
)

// ProxyIngress serves both SOCKS5 (RFC 1928/1929) and HTTP CONNECT on a single TCP port
// by peeking the first byte of each incoming connection.
type ProxyIngress struct {
	registry     *Registry
	acl          *auth.CallerACL
	domainSuffix string
	logger       *slog.Logger
}

// NewProxyIngress creates a unified SOCKS5 + HTTP CONNECT gateway.
func NewProxyIngress(registry *Registry, acl *auth.CallerACL, domainSuffix string, logger *slog.Logger) *ProxyIngress {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProxyIngress{
		registry:     registry,
		acl:          acl,
		domainSuffix: domainSuffix,
		logger:       logger.With("component", "proxy_ingress"),
	}
}

// Serve accepts incoming connections on ln until ln is closed.
func (p *ProxyIngress) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go p.handleConn(conn)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

func (p *ProxyIngress) handleConn(rawConn net.Conn) {
	br := transport.GetBufioReader(rawConn)
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("recovered panic in proxy ingress handler", "remote", rawConn.RemoteAddr(), "panic", r)
		}
		transport.PutBufioReader(br)
		_ = rawConn.Close()
	}()

	_ = rawConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	firstByte, err := br.Peek(1)
	if err != nil {
		return
	}
	_ = rawConn.SetReadDeadline(time.Time{})

	bconn := &bufferedConn{Conn: rawConn, r: br}
	if firstByte[0] == 0x05 {
		p.handleSOCKS5(bconn)
	} else {
		p.handleHTTPConnect(bconn)
	}
}

// handleSOCKS5 implements RFC 1928 (CONNECT + Domain ATYP=0x03) and RFC 1929 (Username/Password auth).
func (p *ProxyIngress) handleSOCKS5(conn *bufferedConn) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Single stack scratch buffer eliminates 4 small heap allocations per SOCKS5 handshake.
	var scratch [260]byte

	// 1. Method negotiation: VER(1) NMETHODS(1) METHODS(1..255)
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := scratch[:int(hdr[1])]
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	hasUserPass := false
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
		} else if m == 0x00 {
			hasNoAuth = true
		}
	}

	var callerID string
	switch {
	case hasUserPass:
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// RFC 1929: VER(1)=0x01 ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
		var authHdr [2]byte
		if _, err := io.ReadFull(conn, authHdr[:]); err != nil || authHdr[0] != 0x01 {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		unameBuf := scratch[:int(authHdr[1])]
		if _, err := io.ReadFull(conn, unameBuf); err != nil {
			return
		}
		uname := string(unameBuf)
		var plen [1]byte
		if _, err := io.ReadFull(conn, plen[:]); err != nil {
			return
		}
		passwdBuf := scratch[:int(plen[0])]
		if _, err := io.ReadFull(conn, passwdBuf); err != nil {
			return
		}

		id, err := p.acl.AuthenticateBasic(uname, string(passwdBuf))
		if err != nil {
			p.logger.Warn("AUDIT: socks5 authentication failed", "caller", uname, "remote", conn.RemoteAddr())
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		callerID = id
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}

	case hasNoAuth && p.acl.AllowNoAuth():
		callerID = "anonymous-dev"
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

	default:
		_, _ = conn.Write([]byte{0x05, 0xff})
		return
	}

	// 2. Request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT(2)
	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		return
	}
	if reqHdr[1] != 0x01 { // Only CONNECT is supported
		writeSOCKS5Reply(conn, 0x07) // Command not supported
		return
	}
	if reqHdr[3] != 0x03 { // Only Domain Name virtual addressing is supported
		writeSOCKS5Reply(conn, 0x08) // Address type not supported
		return
	}

	var domLen [1]byte
	if _, err := io.ReadFull(conn, domLen[:]); err != nil {
		return
	}
	domBuf := scratch[:int(domLen[0])+2] // domain + 2-byte port
	if _, err := io.ReadFull(conn, domBuf); err != nil {
		return
	}
	targetHost := string(domBuf[:domLen[0]])
	_ = conn.SetDeadline(time.Time{})

	tenantID, serviceName, err := ParseVirtualTarget(targetHost, p.domainSuffix)
	if err != nil {
		p.logger.Warn("socks5 invalid virtual target", "host", targetHost, "caller", callerID, "error", err)
		writeSOCKS5Reply(conn, 0x04) // Host unreachable
		return
	}

	if err := p.acl.Authorize(callerID, tenantID, serviceName); err != nil {
		p.logger.Warn("AUDIT: socks5 ACL denied",
			"caller", callerID,
			"tenant_id", tenantID,
			"service", serviceName,
			"reason", err.Error(),
		)
		writeSOCKS5Reply(conn, 0x02) // Connection not allowed by ruleset
		return
	}

	stream, err := p.registry.OpenTenantStream(context.Background(), tenantID, serviceName, protocol.ProtocolTCP, callerID)
	if err != nil {
		p.logger.Warn("socks5 open tenant stream failed",
			"caller", callerID,
			"tenant_id", tenantID,
			"service", serviceName,
			"error", err,
		)
		writeSOCKS5Reply(conn, 0x05) // Connection refused / unreachable
		return
	}
	defer func() { _ = stream.Close() }()

	if !writeSOCKS5Reply(conn, 0x00) {
		return
	}
	transport.BidirectionalPipe(conn, stream)
}

func writeSOCKS5Reply(w io.Writer, rep byte) bool {
	_, err := w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err == nil
}

// handleHTTPConnect handles standard HTTP CONNECT tunneling with Basic Proxy-Authorization.
func (p *ProxyIngress) handleHTTPConnect(conn *bufferedConn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	req, err := http.ReadRequest(conn.r)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}

	callerID, err := p.authenticateProxyHeader(req.Header.Get("Proxy-Authorization"))
	if err != nil {
		p.logger.Warn("AUDIT: http connect auth failed", "remote", conn.RemoteAddr(), "error", err)
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"dataproxy\"\r\nContent-Length: 0\r\n\r\n")
		return
	}

	tenantID, serviceName, err := ParseVirtualTarget(req.Host, p.domainSuffix)
	if err != nil {
		p.logger.Warn("http connect invalid virtual target", "host", req.Host, "caller", callerID, "error", err)
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}

	if err := p.acl.Authorize(callerID, tenantID, serviceName); err != nil {
		p.logger.Warn("AUDIT: http connect ACL denied",
			"caller", callerID,
			"tenant_id", tenantID,
			"service", serviceName,
			"reason", err.Error(),
		)
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}

	stream, err := p.registry.OpenTenantStream(context.Background(), tenantID, serviceName, protocol.ProtocolTCP, callerID)
	if err != nil {
		p.logger.Warn("http connect open tenant stream failed",
			"caller", callerID,
			"tenant_id", tenantID,
			"service", serviceName,
			"error", err,
		)
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer func() { _ = stream.Close() }()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	transport.BidirectionalPipe(conn, stream)
}

func (p *ProxyIngress) authenticateProxyHeader(hdr string) (string, error) {
	hdr = strings.TrimSpace(hdr)
	if hdr == "" {
		if p.acl.AllowNoAuth() {
			return "anonymous-dev", nil
		}
		return "", auth.ErrCallerUnauthorized
	}
	if strings.HasPrefix(hdr, "Basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
		if err != nil {
			return "", auth.ErrCallerUnauthorized
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			return "", auth.ErrCallerUnauthorized
		}
		return p.acl.AuthenticateBasic(user, pass)
	}
	if strings.HasPrefix(hdr, "Bearer ") {
		return p.acl.AuthenticateBearer(strings.TrimPrefix(hdr, "Bearer "))
	}
	return "", auth.ErrCallerUnauthorized
}
