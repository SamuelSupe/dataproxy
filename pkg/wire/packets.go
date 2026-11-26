package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"dataproxy/internal/transport"
)

// ReadMySQLPacket reads a single length-prefixed MySQL wire packet.
func ReadMySQLPacket(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

// WriteMySQLPacket writes a MySQL wire packet using the shared 64KiB buffer pool when possible.
func WriteMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	n := len(payload)
	total := 4 + n
	if total <= transport.CopyBufferSize {
		bufPtr := transport.GetCopyBuf()
		buf := (*bufPtr)[:total]
		buf[0] = byte(n)
		buf[1] = byte(n >> 8)
		buf[2] = byte(n >> 16)
		buf[3] = seq
		copy(buf[4:], payload)
		_, err := w.Write(buf)
		transport.PutCopyBuf(bufPtr)
		return err
	}
	buf := make([]byte, total)
	buf[0] = byte(n)
	buf[1] = byte(n >> 8)
	buf[2] = byte(n >> 16)
	buf[3] = seq
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadPGMessage reads a single PostgreSQL v3 typed message.
func ReadPGMessage(r io.Reader, maxLen uint32) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || (maxLen > 0 && length > maxLen) {
		return 0, nil, fmt.Errorf("wire: invalid pg message length %d", length)
	}
	payload := make([]byte, length-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}

// WritePGMessage writes a PostgreSQL v3 typed message using the shared 64KiB pool when possible.
func WritePGMessage(w io.Writer, msgType byte, payload []byte) error {
	total := 5 + len(payload)
	if total <= transport.CopyBufferSize {
		bufPtr := transport.GetCopyBuf()
		buf := (*bufPtr)[:total]
		buf[0] = msgType
		binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
		copy(buf[5:], payload)
		_, err := w.Write(buf)
		transport.PutCopyBuf(bufPtr)
		return err
	}
	buf := make([]byte, total)
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadMongoMessage reads a single 16-byte-header MongoDB wire message.
func ReadMongoMessage(r io.Reader) (reqID, respTo, opCode uint32, body []byte, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	msgLen := binary.LittleEndian.Uint32(hdr[0:4])
	if msgLen < 16 || msgLen > 48*1024*1024 {
		return 0, 0, 0, nil, errors.New("wire: invalid mongo message length")
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

// WriteMongoMessage writes a raw MongoDB wire message using the shared 64KiB pool when possible.
func WriteMongoMessage(w io.Writer, reqID, respTo, opCode uint32, body []byte) error {
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
