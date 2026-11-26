package transport

import (
	"bufio"
	"io"
	"net"
	"sync"
)

const (
	CopyBufferSize  = 64 * 1024
	BufioReaderSize = 8 * 1024
)

var (
	copyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, CopyBufferSize)
			return &b
		},
	}
	bufioReaderPool = sync.Pool{
		New: func() any {
			return bufio.NewReaderSize(nil, BufioReaderSize)
		},
	}
)

// GetCopyBuf borrows a 64KiB byte slice from the shared pool to reduce GC churn on hot relay paths.
func GetCopyBuf() *[]byte {
	return copyBufPool.Get().(*[]byte)
}

// PutCopyBuf returns a 64KiB byte slice previously obtained via GetCopyBuf.
func PutCopyBuf(b *[]byte) {
	if b != nil && cap(*b) >= CopyBufferSize {
		*b = (*b)[:CopyBufferSize]
		copyBufPool.Put(b)
	}
}

// GetBufioReader borrows a pooled 8KiB *bufio.Reader reset to r.
func GetBufioReader(r io.Reader) *bufio.Reader {
	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

// PutBufioReader resets br to nil (releasing any underlying net.Conn reference) and returns it to the pool.
func PutBufioReader(br *bufio.Reader) {
	if br != nil {
		br.Reset(nil)
		bufioReaderPool.Put(br)
	}
}

type closeWriter interface {
	CloseWrite() error
}

// BidirectionalPipe copies bytes in both directions between a and b using pooled
// 64KiB buffers, propagating half-close (CloseWrite) when supported and ensuring
// both connections are closed cleanly once both directions finish.
func BidirectionalPipe(a, b net.Conn) (aToB int64, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn, written *int64) {
		defer wg.Done()
		bufPtr := GetCopyBuf()
		defer PutCopyBuf(bufPtr)

		n, _ := io.CopyBuffer(dst, src, *bufPtr)
		*written = n

		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copyDir(b, a, &aToB)
	go copyDir(a, b, &bToA)

	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return aToB, bToA
}
