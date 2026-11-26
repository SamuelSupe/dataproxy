package transport

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countingDeadlineConn struct {
	net.Conn
	readDeadlines  atomic.Int64
	writeDeadlines atomic.Int64
}

func (c *countingDeadlineConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	return c.Conn.SetReadDeadline(t)
}

func (c *countingDeadlineConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines.Add(1)
	return c.Conn.SetWriteDeadline(t)
}

// TestIdleTimeoutConn_ThrottledRefreshStillEnforcesTimeout verifies that:
// 1) High-frequency I/O does NOT call SetReadDeadline/SetWriteDeadline on every Read/Write.
// 2) An idle connection still times out promptly when no data arrives.
func TestIdleTimeoutConn_ThrottledRefreshStillEnforcesTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	ca := &countingDeadlineConn{Conn: a}
	wrapped := WrapConnWithIdleTimeout(ca, 200*time.Millisecond)

	// Send 50 rapid small packets from b -> a within a few milliseconds.
	done := make(chan struct{})
	go func() {
		defer close(done)
		msg := []byte("ping")
		for i := 0; i < 50; i++ {
			if _, err := b.Write(msg); err != nil {
				return
			}
		}
	}()

	var buf [4]byte
	for i := 0; i < 50; i++ {
		if _, err := io.ReadFull(wrapped, buf[:]); err != nil {
			t.Fatalf("read %d failed: %v", i, err)
		}
	}
	<-done

	// With throttling (refresh = 50ms), 50 rapid reads should trigger far fewer than 50 SetReadDeadline calls!
	if got := ca.readDeadlines.Load(); got > 5 {
		t.Fatalf("expected throttled SetReadDeadline calls <= 5 for 50 rapid reads, got %d", got)
	}

	// Now go completely idle and confirm Read still times out cleanly.
	start := time.Now()
	_, err := wrapped.Read(buf[:])
	if err == nil {
		t.Fatalf("expected idle timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond || elapsed > 1*time.Second {
		t.Fatalf("unexpected idle timeout elapsed: %v", elapsed)
	}
}

func BenchmarkBufioReaderPool(b *testing.B) {
	src := bytes.NewReader([]byte("hello world\n"))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		src.Reset([]byte("hello world\n"))
		br := GetBufioReader(src)
		_, _ = br.Peek(5)
		PutBufioReader(br)
	}
}

func BenchmarkIdleTimeoutConn_ThrottledWrite(b *testing.B) {
	a, c := net.Pipe()
	defer func() { _ = a.Close(); _ = c.Close() }()
	go func() {
		_, _ = io.Copy(io.Discard, c)
	}()
	wrapped := WrapConnWithIdleTimeout(a, 10*time.Second)
	payload := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := wrapped.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}
