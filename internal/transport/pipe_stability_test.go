package transport

import (
	"errors"
	"net"
	"testing"
	"time"
)

// halfCloseTestConn wraps net.Conn with a CloseWrite method that does NOT unblock Read
// (simulating a TCP/QUIC peer that holds its read side open when only CloseWrite is called).
type halfCloseTestConn struct {
	net.Conn
}

func (c *halfCloseTestConn) CloseWrite() error {
	// Intentionally no-op on Read to verify BidirectionalPipe calls Close() on abrupt errors.
	return nil
}

type failingReadConn struct {
	net.Conn
	err error
}

func (c *failingReadConn) Read([]byte) (int, error) {
	return 0, c.err
}

func TestBidirectionalPipe_AbruptErrorTearsDownReverseHalfCloseConn(t *testing.T) {
	aPeer, aPipe := net.Pipe()
	bPeer, bPipe := net.Pipe()
	defer func() {
		_ = aPeer.Close()
		_ = aPipe.Close()
		_ = bPeer.Close()
		_ = bPipe.Close()
	}()

	// a immediately fails Read with a non-EOF transport error (e.g. ECONNRESET).
	// b supports CloseWrite() and its remote peer never sends EOF.
	// BidirectionalPipe MUST call Close() on b so the b->a goroutine exits immediately!
	done := make(chan struct{})
	go func() {
		defer close(done)
		BidirectionalPipe(&failingReadConn{Conn: aPipe, err: errors.New("connection reset by peer")}, &halfCloseTestConn{Conn: bPipe})
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("BidirectionalPipe hung on non-EOF transport error against CloseWrite-capable peer")
	}
}
