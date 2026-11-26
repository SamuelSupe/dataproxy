package protocol

import (
	"io"
	"testing"
)

func BenchmarkWriteFrame_StreamOpenReq(b *testing.B) {
	req := StreamOpenRequest{
		TraceID:        "a1b2c3d4e5f60708",
		Traceparent:    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		ServiceName:    "pg-analytics",
		Protocol:       ProtocolTCP,
		CallerIdentity: "pg-smart:tkt_1234567890",
		TicketID:       "tkt_1234567890",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := WriteFrame(io.Discard, FrameStreamOpenReq, req); err != nil {
			b.Fatal(err)
		}
	}
}
