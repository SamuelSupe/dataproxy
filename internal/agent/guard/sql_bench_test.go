package guard

import (
	"bufio"
	"bytes"
	"testing"
)

const sampleSelectSQL = "SELECT o.id, o.customer_id, o.total_amount, o.status FROM orders o WHERE o.status = 'DELETE' AND o.created_at >= '2026-01-01' ORDER BY o.id DESC LIMIT 100"

func BenchmarkIsReadOnlySQL_Select(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok, _ := IsReadOnlySQL(sampleSelectSQL)
		if !ok {
			b.Fatal("expected read-only select to be allowed")
		}
	}
}

func BenchmarkIsReadOnlyPGSQL_Select(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok, _ := IsReadOnlyPGSQL(sampleSelectSQL)
		if !ok {
			b.Fatal("expected read-only pg select to be allowed")
		}
	}
}

func BenchmarkIsReadOnlyPGSQL_BlockedPrivilegedFunc(b *testing.B) {
	q := "SELECT pg_catalog.pg_terminate_backend(12345)"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok, _ := IsReadOnlyPGSQL(q)
		if ok {
			b.Fatal("expected pg_terminate_backend to be blocked")
		}
	}
}

func BenchmarkCheckMongoCommandReadOnly_Find(b *testing.B) {
	doc := buildBSONDoc(
		bsonString("find", "orders"),
		bsonString("$db", "shop"),
		bsonInt32("limit", 100),
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, _ := CheckMongoCommandReadOnly(doc); !ok {
			b.Fatal("expected mongo find to be allowed")
		}
	}
}

func BenchmarkRedisRESPReader_Reuse(b *testing.B) {
	wire := []byte("*2\r\n$3\r\nGET\r\n$10\r\norder:1001\r\n")
	src := bytes.NewReader(wire)
	br := bufio.NewReaderSize(src, 4096)
	var rr respCmdReader
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.Reset(wire)
		br.Reset(src)
		args, _, err := rr.read(br)
		if err != nil || len(args) != 2 {
			b.Fatalf("unexpected RESP read: err=%v args=%v", err, args)
		}
	}
}
