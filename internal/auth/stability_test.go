package auth

import "testing"

func TestCallerACL_SecretRotationRevokesOldBearerSecret(t *testing.T) {
	acl, err := NewCallerACL([]CallerPolicy{
		{
			CallerID:       "etl-worker",
			Secret:         "old-secret-v1",
			AllowedTenants: []string{"*"},
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}

	if id, err := acl.AuthenticateBearer("old-secret-v1"); err != nil || id != "etl-worker" {
		t.Fatalf("expected old-secret-v1 to authenticate before rotation, got id=%q err=%v", id, err)
	}

	// Rotate secret via Upsert.
	if err := acl.Upsert(CallerPolicy{
		CallerID:       "etl-worker",
		Secret:         "new-secret-v2",
		AllowedTenants: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := acl.AuthenticateBearer("old-secret-v1"); err == nil {
		t.Fatal("expected old-secret-v1 to be rejected immediately after secret rotation")
	}
	if id, err := acl.AuthenticateBearer("new-secret-v2"); err != nil || id != "etl-worker" {
		t.Fatalf("expected new-secret-v2 to authenticate after rotation, got id=%q err=%v", id, err)
	}
}
