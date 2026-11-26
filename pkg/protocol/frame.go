package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

var frameWriteBufPool = sync.Pool{
	New: func() any {
		b := bytes.NewBuffer(make([]byte, 0, 1024))
		return b
	},
}

const (
	// Magic bytes "DPX" + protocol version 0x01.
	magic0 = 'D'
	magic1 = 'P'
	magic2 = 'X'
	magic3 = 0x01

	// HeaderSize is 4-byte magic + 1-byte type + 1-byte flags + 4-byte length.
	HeaderSize = 10

	// DefaultMaxFrameSize prevents unbounded allocations on untrusted streams.
	DefaultMaxFrameSize uint32 = 64 * 1024
)

// Frame types used on control and data streams.
const (
	FrameRegisterReq    uint8 = 0x01
	FrameRegisterResp   uint8 = 0x02
	FramePing           uint8 = 0x03
	FramePong           uint8 = 0x04
	FrameDrain          uint8 = 0x05
	FrameServiceUpdate  uint8 = 0x06
	FrameHealthReport   uint8 = 0x07
	FrameStreamOpenReq  uint8 = 0x10
	FrameStreamOpenResp uint8 = 0x11
)

var (
	ErrInvalidMagic   = errors.New("protocol: invalid frame magic")
	ErrFrameTooLarge  = errors.New("protocol: frame payload exceeds limit")
	ErrUnexpectedType = errors.New("protocol: unexpected frame type")
)

// Frame represents a single framed control or handshake message.
type Frame struct {
	Type    uint8
	Flags   uint8
	Payload []byte
}

// WriteFrame marshals v as JSON into a pooled single contiguous buffer and writes
// an exact-length framed message in one Write call.
func WriteFrame(w io.Writer, frameType uint8, v any) error {
	buf := frameWriteBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= 64*1024 {
			buf.Reset()
			frameWriteBufPool.Put(buf)
		}
	}()

	var hdr [HeaderSize]byte
	hdr[0] = magic0
	hdr[1] = magic1
	hdr[2] = magic2
	hdr[3] = magic3
	hdr[4] = frameType
	hdr[5] = 0x00
	buf.Write(hdr[:])

	if v != nil {
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return fmt.Errorf("protocol: marshal frame type 0x%02x: %w", frameType, err)
		}
		// Strip trailing newline added by json.Encoder for compact identical wire bytes.
		if b := buf.Bytes(); len(b) > HeaderSize && b[len(b)-1] == '\n' {
			buf.Truncate(len(b) - 1)
		}
	}

	raw := buf.Bytes()
	payloadLen := len(raw) - HeaderSize
	if uint64(payloadLen) > uint64(DefaultMaxFrameSize) {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, payloadLen)
	}
	binary.BigEndian.PutUint32(raw[6:10], uint32(payloadLen))

	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

// ReadFrame reads exactly one framed message from r using io.ReadFull.
// Crucially, it NEVER over-reads past the frame boundary, making it safe to
// switch r immediately to raw TCP byte passthrough (e.g., MySQL Server-First greeting).
func ReadFrame(r io.Reader, maxLen uint32) (*Frame, error) {
	if maxLen == 0 {
		maxLen = DefaultMaxFrameSize
	}
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != magic0 || hdr[1] != magic1 || hdr[2] != magic2 || hdr[3] != magic3 {
		return nil, ErrInvalidMagic
	}
	length := binary.BigEndian.Uint32(hdr[6:10])
	if length > maxLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, maxLen)
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{
		Type:    hdr[4],
		Flags:   hdr[5],
		Payload: payload,
	}, nil
}

// ReadTypedFrame reads a frame, validates its type, and unmarshals its JSON payload into dst.
func ReadTypedFrame(r io.Reader, expectedType uint8, dst any) error {
	f, err := ReadFrame(r, DefaultMaxFrameSize)
	if err != nil {
		return err
	}
	if f.Type != expectedType {
		return fmt.Errorf("%w: got 0x%02x, want 0x%02x", ErrUnexpectedType, f.Type, expectedType)
	}
	if dst != nil && len(f.Payload) > 0 {
		if err := json.Unmarshal(f.Payload, dst); err != nil {
			return fmt.Errorf("protocol: unmarshal frame type 0x%02x: %w", expectedType, err)
		}
	}
	return nil
}
