package auth

import (
	"errors"
	"testing"
	"time"
)

func TestTicketManager(t *testing.T) {
	tm := NewTicketManager("test-signing-key", 5*time.Minute)
	issued, err := tm.Issue("tenant-a", "pg-prod", 2*time.Minute, map[string]string{
		"job_type":     "daily_sync",
		"job_id":       "sync_9921",
		"triggered_by": "报表中心",
	})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	claims, err := tm.VerifyJWT(issued.JWT)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.TenantID != "tenant-a" || claims.ServiceName != "pg-prod" || claims.Purpose["job_id"] != "sync_9921" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Tampered JWT must fail
	if _, err := tm.VerifyJWT(issued.JWT + "x"); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("expected ErrInvalidTicket on tampered JWT, got %v", err)
	}

	// MySQL native scramble verification
	salt := []byte("0123456789abcdefghij")
	goodScramble := computeMySQLNativeScramble(issued.MySQLPassword, salt)
	c2, err := tm.VerifyMySQLNativeScramble(issued.MySQLUser, salt, goodScramble)
	if err != nil || c2.TenantID != "tenant-a" {
		t.Fatalf("VerifyMySQLNativeScramble failed: claims=%+v err=%v", c2, err)
	}
	if _, err := tm.VerifyMySQLNativeScramble(issued.MySQLUser, salt, []byte("wrong")); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("expected ErrInvalidTicket for wrong scramble, got %v", err)
	}
}
