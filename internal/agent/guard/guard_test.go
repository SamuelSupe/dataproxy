package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsReadOnlySQL(t *testing.T) {
	allowed := []string{
		"SELECT * FROM orders WHERE status = 'DELETE'",
		"  /* comment */ SELECT id, name FROM users LIMIT 10;",
		"-- line comment\nSHOW TABLES",
		"DESCRIBE orders",
		"EXPLAIN SELECT * FROM orders",
		"WITH active AS (SELECT id FROM users) SELECT * FROM active",
		"SET NAMES utf8mb4",
		"SET SESSION TRANSACTION READ ONLY",
		"SET autocommit = 1",
		"USE prod_db",
		"START TRANSACTION READ ONLY",
	}
	for _, q := range allowed {
		if ok, reason := IsReadOnlySQL(q); !ok {
			t.Errorf("expected allowed SQL %q, got blocked: %s", q, reason)
		}
	}

	blocked := []string{
		"DELETE FROM orders WHERE id = 1",
		"DROP TABLE users",
		"UPDATE orders SET amount = 0",
		"INSERT INTO logs VALUES (1)",
		"TRUNCATE TABLE audit_log",
		"ALTER TABLE users ADD COLUMN x INT",
		"SELECT 1; DROP TABLE users",
		"SELECT * FROM users INTO OUTFILE '/tmp/dump.txt'",
		"SELECT * FROM users INTO DUMPFILE '/tmp/dump.bin'",
		"SELECT * FROM orders FOR UPDATE",
		"SELECT * FROM orders LOCK IN SHARE MODE",
		"WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
		"/*!50000 DROP TABLE users */",
		"SET GLOBAL max_connections = 9999",
		"SET SESSION TRANSACTION READ WRITE",
		"CALL dangerous_proc()",
	}
	for _, q := range blocked {
		if ok, _ := IsReadOnlySQL(q); ok {
			t.Errorf("expected BLOCKED SQL %q, but it was allowed", q)
		}
	}
}

func TestResolveSecret(t *testing.T) {
	t.Setenv("DPX_TEST_DB_PASS", "env-secret-123")
	gotEnv, err := ResolveSecret("env:DPX_TEST_DB_PASS")
	if err != nil || gotEnv != "env-secret-123" {
		t.Fatalf("ResolveSecret env failed: got=%q err=%v", gotEnv, err)
	}

	secretFile := filepath.Join(t.TempDir(), "db_pass")
	if err := os.WriteFile(secretFile, []byte("vault-secret-456\n"), 0600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	gotFile, err := ResolveSecret("file:" + secretFile)
	if err != nil || gotFile != "vault-secret-456" {
		t.Fatalf("ResolveSecret file failed: got=%q err=%v", gotFile, err)
	}

	if _, err := ResolveSecret("env:DPX_NON_EXISTENT_VAR_999"); err == nil {
		t.Fatalf("expected error for unset env var")
	}
}

func TestIsReadOnlyPGSQL(t *testing.T) {
	allowed := []string{
		"SELECT now(), current_user",
		"BEGIN READ ONLY",
		"SET client_encoding TO 'UTF8'",
		"SET default_transaction_read_only = on",
		"WITH c AS (SELECT 1) SELECT * FROM c",
	}
	for _, q := range allowed {
		if ok, reason := IsReadOnlyPGSQL(q); !ok {
			t.Errorf("expected PG SQL allowed %q, blocked: %s", q, reason)
		}
	}

	blocked := []string{
		"COPY users TO PROGRAM 'id'",
		"DO $$ BEGIN DELETE FROM users; END $$",
		"SELECT pg_terminate_backend(1234)",
		"SELECT pg_catalog.pg_read_file('/etc/passwd')",
		"BEGIN READ WRITE",
		"SET default_transaction_read_only = off",
		"INSERT INTO t VALUES (1)",
	}
	for _, q := range blocked {
		if ok, _ := IsReadOnlyPGSQL(q); ok {
			t.Errorf("expected PG SQL blocked %q, but was allowed", q)
		}
	}
}

func TestIsReadOnlyRedisCommand(t *testing.T) {
	if ok, _ := IsReadOnlyRedisCommand([]string{"GET", "k1"}); !ok {
		t.Fatalf("expected GET allowed")
	}
	if ok, _ := IsReadOnlyRedisCommand([]string{"HGETALL", "hash1"}); !ok {
		t.Fatalf("expected HGETALL allowed")
	}
	if ok, _ := IsReadOnlyRedisCommand([]string{"CLIENT", "SETINFO", "LIB-NAME", "redis-cli"}); !ok {
		t.Fatalf("expected CLIENT SETINFO allowed")
	}
	for _, cmd := range [][]string{{"SET", "k", "v"}, {"DEL", "k"}, {"FLUSHALL"}, {"EVAL", "return 1", "0"}, {"CONFIG", "SET", "a", "b"}} {
		if ok, _ := IsReadOnlyRedisCommand(cmd); ok {
			t.Fatalf("expected redis cmd %v blocked", cmd)
		}
	}
}

func TestCheckMongoCommandReadOnly(t *testing.T) {
	findDoc := buildBSONDoc(bsonString("find", "orders"), bsonString("$db", "shop"))
	if cmd, ok, _ := CheckMongoCommandReadOnly(findDoc); !ok || cmd != "find" {
		t.Fatalf("expected find allowed, got cmd=%s ok=%v", cmd, ok)
	}

	insertDoc := buildBSONDoc(bsonString("insert", "orders"), bsonString("$db", "shop"))
	if cmd, ok, _ := CheckMongoCommandReadOnly(insertDoc); ok || cmd != "insert" {
		t.Fatalf("expected insert blocked, got cmd=%s ok=%v", cmd, ok)
	}

	// Aggregate with $out write stage must be blocked!
	stageDoc := buildBSONDoc(bsonString("$out", "hacked_collection"))
	pipelineArr := buildBSONDoc(append([]byte{0x03, '0', 0x00}, stageDoc...))
	aggDoc := buildBSONDoc(
		bsonString("aggregate", "orders"),
		append([]byte{0x04, 'p', 'i', 'p', 'e', 'l', 'i', 'n', 'e', 0x00}, pipelineArr...),
		bsonString("$db", "shop"),
	)
	if _, ok, _ := CheckMongoCommandReadOnly(aggDoc); ok {
		t.Fatalf("expected aggregate with $out stage to be blocked")
	}
}
