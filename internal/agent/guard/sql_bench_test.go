package guard

import "testing"

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
