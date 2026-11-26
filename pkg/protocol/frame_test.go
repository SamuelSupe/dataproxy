package protocol

import (
	"bytes"
	"io"
	"testing"
)

// TestFrameExactBoundaryForServerFirstProtocol verifies that reading a framed
// StreamOpenResponse never over-reads into immediately following raw protocol bytes
// (such as a MySQL v10 Initial Handshake Packet).
func TestFrameExactBoundaryForServerFirstProtocol(t *testing.T) {
	var wire bytes.Buffer

	resp := StreamOpenResponse{OK: true}
	if err := WriteFrame(&wire, FrameStreamOpenResp, resp); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	// Simulate MySQL v10 Server-First greeting immediately appended to the stream.
	mysqlGreeting := []byte{
		0x4a, 0x00, 0x00, 0x00, // packet length & seq 0
		0x0a,                   // protocol version 10
		'8', '.', '0', '.', '3', '6', 0x00,
		0x01, 0x02, 0x03, 0x04, // connection id
	}
	wire.Write(mysqlGreeting)

	var gotResp StreamOpenResponse
	if err := ReadTypedFrame(&wire, FrameStreamOpenResp, &gotResp); err != nil {
		t.Fatalf("ReadTypedFrame failed: %v", err)
	}
	if !gotResp.OK {
		t.Fatalf("expected OK=true, got false")
	}

	remaining, err := io.ReadAll(&wire)
	if err != nil {
		t.Fatalf("ReadAll remaining failed: %v", err)
	}
	if !bytes.Equal(remaining, mysqlGreeting) {
		t.Fatalf("trailing raw bytes mismatch: got %x, want %x", remaining, mysqlGreeting)
	}
}

func TestFrameInvalidMagicAndOversize(t *testing.T) {
	bad := bytes.NewReader([]byte("HTTP/1.1 200 OK\r\n"))
	if _, err := ReadFrame(bad, DefaultMaxFrameSize); err != ErrInvalidMagic {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, FramePing, PingMessage{SentAtUnixNano: 12345}); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	if _, err := ReadFrame(&buf, 4); err == nil {
		t.Fatalf("expected oversize error, got nil")
	}
}
