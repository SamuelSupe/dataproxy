package auth

import (
	"testing"
	"time"
)

func BenchmarkTicketManager_Issue(b *testing.B) {
	tm := NewTicketManager("bench-signing-key", 5*time.Minute)
	purpose := map[string]string{"job_id": "sync_01"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tm.Issue("tenant-acme", "pg-prod", 5*time.Minute, purpose); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTicketManager_VerifyJWT(b *testing.B) {
	tm := NewTicketManager("bench-signing-key", 5*time.Minute)
	issued, err := tm.Issue("tenant-acme", "pg-prod", 5*time.Minute, map[string]string{"job_id": "sync_01"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tm.VerifyJWT(issued.JWT); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTicketManager_VerifyMySQLStateless(b *testing.B) {
	tmIssuer := NewTicketManager("cluster-shared-key", 5*time.Minute)
	tmPeer := NewTicketManager("cluster-shared-key", 5*time.Minute)
	issued, err := tmIssuer.Issue("tenant-acme", "mysql-prod", 5*time.Minute, nil)
	if err != nil {
		b.Fatal(err)
	}
	salt := []byte("0123456789abcdefghij")
	scramble := computeMySQLCachingSHA2Scramble(issued.MySQLPassword, salt)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tmPeer.VerifyMySQLNativeScramble(issued.MySQLUser, salt, scramble); err != nil {
			b.Fatal(err)
		}
	}
}
