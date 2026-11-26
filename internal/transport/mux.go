package transport

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

// QUICALPN is the dedicated TLS 1.3 ALPN token for dataproxy QUIC tunnels.
const QUICALPN = "dataproxy-quic-v1"

// StreamMux abstracts multiplexed bidirectional byte streams across Yamux (WSS/TLS/TCP)
// and native QUIC streams (zero Yamux layer overhead).
type StreamMux interface {
	OpenStream() (net.Conn, error)
	OpenStreamContext(ctx context.Context) (net.Conn, error)
	AcceptStream() (net.Conn, error)
	Ping() (time.Duration, error)
	IsClosed() bool
	Close() error
}

// QUICListener wraps a *quic.Listener together with its caller-owned *net.UDPConn
// so Close() deterministically releases the underlying UDP socket file descriptor.
type QUICListener struct {
	*quic.Listener
	udpConn   *net.UDPConn
	closeOnce sync.Once
}

// Close stops accepting QUIC connections and closes the underlying UDP socket.
func (l *QUICListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		if l.Listener != nil {
			err = l.Listener.Close()
		}
		if l.udpConn != nil {
			_ = l.udpConn.Close()
		}
	})
	return err
}

// DefaultQUICConfig returns a tuned *quic.Config for high-throughput database streaming
// with native keepalive, generous BDP receive windows, and stream-independent flow control.
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:                15 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          0,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,  // 4 MiB
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16 MiB
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,  // 8 MiB
		MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32 MiB
	}
}

// ListenQUIC binds a UDP socket with enlarged OS send/receive buffers (best-effort 7 MiB)
// and starts a QUIC listener with TLS 1.3 + dataproxy ALPN.
func ListenQUIC(addr string, baseTLS *tls.Config) (*QUICListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	tuneUDPSocketBuffers(udpConn)
	ln, err := quic.Listen(udpConn, PrepareQUICTLSConfig(baseTLS), DefaultQUICConfig())
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	return &QUICListener{Listener: ln, udpConn: udpConn}, nil
}

// tuneUDPSocketBuffers requests larger kernel UDP buffers (best-effort; silently ignored if OS caps lower).
func tuneUDPSocketBuffers(conn *net.UDPConn) {
	const targetBuf = 7 * 1024 * 1024
	_ = conn.SetReadBuffer(targetBuf)
	_ = conn.SetWriteBuffer(targetBuf)
}

// PrepareQUICTLSConfig clones base and configures TLS 1.3 + dataproxy QUIC ALPN.
func PrepareQUICTLSConfig(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{}
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{QUICALPN}
	return cfg
}

// ---- Yamux StreamMux implementation (WSS / TLS / TCP) ----

type yamuxMux struct {
	sess      *yamux.Session
	under     net.Conn
	onClose   func()
	closeOnce sync.Once
}

// NewYamuxMux wraps a *yamux.Session (and optional underlying net.Conn) as a StreamMux.
func NewYamuxMux(sess *yamux.Session, under net.Conn) StreamMux {
	return &yamuxMux{sess: sess, under: under}
}

func (y *yamuxMux) OpenStream() (net.Conn, error) {
	return y.sess.OpenStream()
}

func (y *yamuxMux) OpenStreamContext(ctx context.Context) (net.Conn, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return y.sess.OpenStream()
}

func (y *yamuxMux) AcceptStream() (net.Conn, error) {
	return y.sess.AcceptStream()
}

func (y *yamuxMux) Ping() (time.Duration, error) {
	return y.sess.Ping()
}

func (y *yamuxMux) IsClosed() bool {
	return y.sess.IsClosed()
}

func (y *yamuxMux) Close() error {
	var err error
	y.closeOnce.Do(func() {
		err = y.sess.Close()
		if y.under != nil {
			_ = y.under.Close()
		}
		if y.onClose != nil {
			y.onClose()
		}
	})
	return err
}

// ---- Native QUIC StreamMux implementation (UDP + TLS 1.3, zero Yamux!) ----

type quicMux struct {
	conn      *quic.Conn
	closeOnce sync.Once
}

// NewQUICMux wraps a *quic.Conn as a StreamMux using QUIC native bidirectional streams.
func NewQUICMux(conn *quic.Conn) StreamMux {
	return &quicMux{conn: conn}
}

func (q *quicMux) OpenStream() (net.Conn, error) {
	return q.OpenStreamContext(q.conn.Context())
}

func (q *quicMux) OpenStreamContext(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		ctx = q.conn.Context()
	}
	s, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStreamConn{
		Stream: s,
		local:  q.conn.LocalAddr(),
		remote: q.conn.RemoteAddr(),
	}, nil
}

func (q *quicMux) AcceptStream() (net.Conn, error) {
	s, err := q.conn.AcceptStream(q.conn.Context())
	if err != nil {
		return nil, err
	}
	return &quicStreamConn{
		Stream: s,
		local:  q.conn.LocalAddr(),
		remote: q.conn.RemoteAddr(),
	}, nil
}

func (q *quicMux) Ping() (time.Duration, error) {
	stats := q.conn.ConnectionStats()
	if stats.SmoothedRTT > 0 {
		return stats.SmoothedRTT, nil
	}
	return stats.LatestRTT, nil
}

func (q *quicMux) IsClosed() bool {
	return q.conn.Context().Err() != nil
}

func (q *quicMux) Close() error {
	var err error
	q.closeOnce.Do(func() {
		err = q.conn.CloseWithError(0, "session closed")
	})
	return err
}

// quicStreamConn adapts *quic.Stream to net.Conn with full TCP-style half-close (CloseWrite).
type quicStreamConn struct {
	*quic.Stream
	local     net.Addr
	remote    net.Addr
	closeOnce sync.Once
}

func (s *quicStreamConn) LocalAddr() net.Addr  { return s.local }
func (s *quicStreamConn) RemoteAddr() net.Addr { return s.remote }

// CloseWrite sends a QUIC FIN on the send side while keeping the receive side readable.
func (s *quicStreamConn) CloseWrite() error {
	return s.Stream.Close()
}

// Close closes both directions of the QUIC stream cleanly.
func (s *quicStreamConn) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.Stream.CancelRead(0)
		err = s.Stream.Close()
	})
	return err
}
