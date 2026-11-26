package guard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"dataproxy/internal/transport"
)

// HTTPMethodGuard enforces a tenant-local HTTP method allowlist (e.g. ["GET", "HEAD"])
// and/or injects local tenant API credentials into outgoing HTTP headers (e.g.
// Authorization: "Bearer env:ERP_API_TOKEN") so internal platform secrets never leave the tenant intranet.
type HTTPMethodGuard struct {
	allowed       map[string]struct{}
	injectHeaders map[string]string // HeaderName -> template (supports "Bearer env:VAR", "file:/path", etc.)
	blockedCount  atomic.Int64
}

// NewHTTPMethodGuard builds an HTTP guard. Returns nil if both methods and injectHeaders are empty.
func NewHTTPMethodGuard(methods []string, injectHeaders map[string]string) *HTTPMethodGuard {
	allowed := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m != "" {
			allowed[m] = struct{}{}
		}
	}
	hdrs := make(map[string]string, len(injectHeaders))
	for k, v := range injectHeaders {
		k = strings.TrimSpace(k)
		if k != "" {
			hdrs[k] = v
		}
	}
	if len(allowed) == 0 && len(hdrs) == 0 {
		return nil
	}
	return &HTTPMethodGuard{
		allowed:       allowed,
		injectHeaders: hdrs,
	}
}

// BlockedCount returns total blocked HTTP requests.
func (g *HTTPMethodGuard) BlockedCount() int64 {
	if g == nil {
		return 0
	}
	return g.blockedCount.Load()
}

// IsAllowed reports whether method is permitted by the local allowlist.
func (g *HTTPMethodGuard) IsAllowed(method string) bool {
	if g == nil || len(g.allowed) == 0 {
		return true
	}
	_, ok := g.allowed[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

// Proxy relays HTTP/1.1 requests over a single stream, blocking disallowed methods
// locally with 403 Forbidden and injecting local tenant secret headers before forwarding.
func (g *HTTPMethodGuard) Proxy(
	clientConn, upstreamConn net.Conn,
	onBlocked func(method, path string),
) (bytesIn, bytesOut int64) {
	cliBR := transport.GetBufioReader(clientConn)
	defer transport.PutBufioReader(cliBR)
	upBR := transport.GetBufioReader(upstreamConn)
	defer transport.PutBufioReader(upBR)

	for {
		req, err := http.ReadRequest(cliBR)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return bytesIn, bytesOut
			}
			return bytesIn, bytesOut
		}

		if !g.IsAllowed(req.Method) {
			g.blockedCount.Add(1)
			if onBlocked != nil {
				onBlocked(req.Method, req.URL.Path)
			}
			// Only drain small known-length bodies (<= 64 KiB) to preserve HTTP/1.1 keep-alive.
			// For large or chunked/streaming blocked requests, skip draining and req.Body.Close()
			// (whose stdlib implementation attempts to drain unread body bytes) and immediately
			// return 403 Forbidden with Connection: close so huge blocked POSTs never stall the stream.
			const maxBlockedDrain = 64 * 1024
			forceClose := req.Close || req.ContentLength < 0 || req.ContentLength > maxBlockedDrain
			if !forceClose && req.ContentLength > 0 {
				nDrained, derr := io.Copy(io.Discard, io.LimitReader(req.Body, maxBlockedDrain+1))
				bytesIn += nDrained
				if derr != nil || nDrained > maxBlockedDrain {
					forceClose = true
				} else {
					_ = req.Body.Close()
				}
			}

			body := fmt.Sprintf("dataproxy-agent: HTTP method %s is blocked by tenant read-only policy\n", req.Method)
			connHdr := "keep-alive"
			if forceClose {
				connHdr = "close"
			}
			respStr := fmt.Sprintf(
				"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n%s",
				len(body), connHdr, body,
			)
			nWritten, werr := io.WriteString(clientConn, respStr)
			bytesOut += int64(nWritten)
			if werr != nil || forceClose {
				_ = clientConn.Close()
				return bytesIn, bytesOut
			}
			continue
		}

		// Inject tenant-local API credential headers (never exposed to central platform!).
		if len(g.injectHeaders) > 0 {
			for k, tmpl := range g.injectHeaders {
				val, err := ResolveHeaderTemplate(tmpl)
				if err != nil {
					_ = req.Body.Close()
					errBody := "dataproxy-agent: local HTTP credential header resolution failed\n"
					_, _ = fmt.Fprintf(clientConn,
						"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
						len(errBody), errBody)
					return bytesIn, bytesOut
				}
				req.Header.Set(k, val)
			}
		}

		// Allowed method -> forward exact HTTP/1.1 request to tenant internal service.
		inCounter := &countingWriter{w: upstreamConn}
		if err := req.Write(inCounter); err != nil {
			_ = req.Body.Close()
			return bytesIn + inCounter.n, bytesOut
		}
		_ = req.Body.Close()
		bytesIn += inCounter.n

		resp, err := http.ReadResponse(upBR, req)
		if err != nil {
			return bytesIn, bytesOut
		}
		outCounter := &countingWriter{w: clientConn}
		werr := resp.Write(outCounter)
		_ = resp.Body.Close()
		bytesOut += outCounter.n
		if werr != nil {
			return bytesIn, bytesOut
		}

		if resp.StatusCode == http.StatusSwitchingProtocols {
			in2, out2 := transport.BidirectionalPipe(
				&peekedConn{Conn: clientConn, r: cliBR},
				&peekedConn{Conn: upstreamConn, r: upBR},
			)
			return bytesIn + in2, bytesOut + out2
		}

		if req.Close || resp.Close {
			return bytesIn, bytesOut
		}
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *peekedConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Conn.Close()
}
