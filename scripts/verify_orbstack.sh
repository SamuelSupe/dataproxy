#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dataproxy-orbstack.XXXXXX")"
HUB_PID=""
AGENT_PID=""

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo ">>> 脚本异常退出 (rc=$rc)，当前容器状态："
    docker ps -a --filter "name=dpx-live-" --format 'table {{.Names}}\t{{.Status}}' || true
    for c in dpx-live-pg dpx-live-mysql dpx-live-mongo dpx-live-redis; do
      if docker inspect "$c" >/dev/null 2>&1; then
        st=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo "false")
        if [ "$st" != "true" ]; then
          echo "=== EXITED LOGS: $c ==="
          docker logs "$c" 2>&1 | tail -n 25 || true
        fi
      fi
    done
  fi
  echo ""
  echo ">>> 清理测试进程与 OrbStack 临时容器..."
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  docker rm -f dpx-live-pg dpx-live-mysql dpx-live-mongo dpx-live-redis >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo ">>> [1/7] 生成自签 CA/服务端证书，并启动 4 个强制 TLS/SSL 的真实 OrbStack 数据库容器 (PG 16 / MySQL 8.4 / Mongo 8.0 / Redis 7)..."
mkdir -p "$TMP_DIR/certs" "$TMP_DIR/secrets"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TMP_DIR/certs/ca.key" -out "$TMP_DIR/certs/ca.crt" -days 1 \
  -subj "/CN=dpx-live-ca" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TMP_DIR/certs/hub.key" -out "$TMP_DIR/certs/hub.csr" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl x509 -req -in "$TMP_DIR/certs/hub.csr" -CA "$TMP_DIR/certs/ca.crt" -CAkey "$TMP_DIR/certs/ca.key" \
  -CAcreateserial -out "$TMP_DIR/certs/hub.crt" -days 1 -copy_extensions copy 2>/dev/null
cat "$TMP_DIR/certs/hub.crt" "$TMP_DIR/certs/hub.key" > "$TMP_DIR/certs/mongo.pem"
chmod 644 "$TMP_DIR/certs/"*

docker rm -f dpx-live-pg dpx-live-mysql dpx-live-mongo dpx-live-redis >/dev/null 2>&1 || true

# 1) PostgreSQL 16 with SSL enabled (verified via pg_stat_ssl.ssl = 't'!)
docker run -d --name dpx-live-pg \
  -p 127.0.0.1:55432:5432 \
  -v "$TMP_DIR/certs:/certs:ro" \
  -e POSTGRES_USER=tenant_pg_reader \
  -e POSTGRES_PASSWORD='PgRealVaultPass!2026' \
  -e POSTGRES_DB=demo \
  postgres:16-alpine \
  sh -c "cp /certs/hub.crt /tmp/pg.crt && cp /certs/hub.key /tmp/pg.key && chown postgres:postgres /tmp/pg.crt /tmp/pg.key && chmod 600 /tmp/pg.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/pg.crt -c ssl_key_file=/tmp/pg.key" >/dev/null

# 2) MySQL 8.4 with --require-secure-transport=ON (rejects ALL plaintext TCP connections!)
docker run -d --name dpx-live-mysql \
  -p 127.0.0.1:53306:3306 \
  -v "$TMP_DIR/certs:/certs:ro" \
  -e MYSQL_ROOT_PASSWORD='MysqlRootPass!2026' \
  -e MYSQL_DATABASE=demo \
  -e MYSQL_USER=mysql_real_reader \
  -e MYSQL_PASSWORD='MysqlRealVaultPass!2026' \
  mysql:8.4 \
  --require-secure-transport=ON \
  --ssl-ca=/certs/ca.crt \
  --ssl-cert=/certs/hub.crt \
  --ssl-key=/certs/hub.key >/dev/null

# 3) MongoDB 8.0 with --tlsMode requireTLS (TLS-only, rejects plaintext TCP!)
docker run -d --name dpx-live-mongo \
  -p 127.0.0.1:57017:27017 \
  -v "$TMP_DIR/certs:/certs:ro" \
  -e MONGO_INITDB_ROOT_USERNAME=mongo_real_reader \
  -e MONGO_INITDB_ROOT_PASSWORD='MongoRealVaultPass!2026' \
  mongo:8.0 \
  --tlsMode requireTLS \
  --tlsCAFile /certs/ca.crt \
  --tlsCertificateKeyFile /certs/mongo.pem \
  --tlsAllowConnectionsWithoutCertificates >/dev/null

# 4) Redis 7 with --port 0 --tls-port 6379 (TLS-only, zero plaintext port!)
docker run -d --name dpx-live-redis \
  -p 127.0.0.1:56379:6379 \
  -v "$TMP_DIR/certs:/certs:ro" \
  redis:7-alpine redis-server \
  --requirepass 'RedisRealVaultPass!2026' \
  --port 0 --tls-port 6379 \
  --tls-cert-file /certs/hub.crt \
  --tls-key-file /certs/hub.key \
  --tls-ca-cert-file /certs/ca.crt \
  --tls-auth-clients no >/dev/null

echo ">>> [2/7] 等待 4 个强制 TLS 数据库容器就绪并初始化测试数据..."
for i in $(seq 1 40); do
  if docker exec -e PGPASSWORD='PgRealVaultPass!2026' dpx-live-pg psql -h 127.0.0.1 -U tenant_pg_reader -d demo -c "SELECT 1" >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec -e PGPASSWORD='PgRealVaultPass!2026' dpx-live-pg \
  psql -h 127.0.0.1 -U tenant_pg_reader -d demo -c "CREATE TABLE orders(id INT PRIMARY KEY, item TEXT); INSERT INTO orders VALUES (1, 'pg-laptop');" >/dev/null

for i in $(seq 1 40); do
  if docker exec dpx-live-redis redis-cli --tls --cacert /certs/ca.crt -a 'RedisRealVaultPass!2026' PING 2>/dev/null | grep -q PONG; then break; fi
  sleep 1
done
docker exec dpx-live-redis redis-cli --tls --cacert /certs/ca.crt -a 'RedisRealVaultPass!2026' SET order:1001 'redis-laptop' >/dev/null 2>&1

for i in $(seq 1 40); do
  if docker exec dpx-live-mongo mongosh --quiet --tls --tlsCAFile /certs/ca.crt -u mongo_real_reader -p 'MongoRealVaultPass!2026' --authenticationDatabase admin --eval "db.runCommand({ping:1}).ok" 2>/dev/null | grep -q 1; then break; fi
  sleep 1
done
docker exec dpx-live-mongo mongosh --quiet --tls --tlsCAFile /certs/ca.crt -u mongo_real_reader -p 'MongoRealVaultPass!2026' --authenticationDatabase admin demo \
  --eval 'db.orders.insertOne({_id: 1, item: "mongo-laptop"})' >/dev/null

for i in $(seq 1 60); do
  if docker exec dpx-live-mysql mysql --ssl-mode=REQUIRED -h 127.0.0.1 -u mysql_real_reader -p'MysqlRealVaultPass!2026' -e "SELECT 1" >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec dpx-live-mysql mysql --ssl-mode=REQUIRED -h 127.0.0.1 -u mysql_real_reader -p'MysqlRealVaultPass!2026' demo \
  -e "CREATE TABLE orders(id INT PRIMARY KEY, item VARCHAR(64)); INSERT INTO orders VALUES (1, 'mysql-laptop');" >/dev/null 2>&1

echo ">>> 4 个强制 TLS/SSL 真实数据库已就绪并写入种子数据！"

echo ">>> [3/7] 准备本地 Secret 文件并启动 dataproxy-hub & dataproxy-agent..."

printf 'PgRealVaultPass!2026\n' > "$TMP_DIR/secrets/pg_pass"
printf 'MysqlRealVaultPass!2026\n' > "$TMP_DIR/secrets/mysql_pass"
printf 'MongoRealVaultPass!2026\n' > "$TMP_DIR/secrets/mongo_pass"
printf 'RedisRealVaultPass!2026\n' > "$TMP_DIR/secrets/redis_pass"

cat > "$TMP_DIR/hub.yaml" <<EOF
log_level: "warn"
tunnel_wss_addr: "127.0.0.1:48443"
tunnel_wss_path: "/tunnel/v1/connect"
pg_smart_addr: "0.0.0.0:45433"
mysql_smart_addr: "0.0.0.0:43307"
mongo_smart_addr: "0.0.0.0:47018"
redis_smart_addr: "0.0.0.0:46380"
admin_addr: "127.0.0.1:49090"
admin_token: "live-admin-token"
ticket_signing_key: "live-orbstack-ticket-secret"
tunnel_tls:
  cert_file: "$TMP_DIR/certs/hub.crt"
  key_file: "$TMP_DIR/certs/hub.key"
tcp_bindings:
  - id: "orb-pg"
    listen_addr: "0.0.0.0:45432"
    tenant_id: "tenant-orb"
    service_name: "pg-prod"
  - id: "orb-mysql"
    listen_addr: "0.0.0.0:43306"
    tenant_id: "tenant-orb"
    service_name: "mysql-prod"
  - id: "orb-mongo"
    listen_addr: "0.0.0.0:47017"
    tenant_id: "tenant-orb"
    service_name: "mongo-prod"
  - id: "orb-redis"
    listen_addr: "0.0.0.0:46379"
    tenant_id: "tenant-orb"
    service_name: "redis-prod"
EOF

"$ROOT_DIR/bin/dataproxy-hub" -config "$TMP_DIR/hub.yaml" &
HUB_PID=$!
for i in $(seq 1 40); do
  if curl -sf http://127.0.0.1:49090/healthz >/dev/null 2>&1; then break; fi
  sleep 0.2
done

echo ">>> [3.5/7] 通过 15 分钟一次性挂载码执行 dataproxy-agent enroll（零静态 Token，私钥留本机）..."
ENROLL_JSON=$(curl -sf -X POST http://127.0.0.1:49090/api/v1/enrollments \
  -H "Authorization: Bearer live-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"tenant-orb","device_name":"orb-live-dc1","ttl_seconds":900}')
ENROLL_CODE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["enrollment_code"])' <<< "$ENROLL_JSON")
DEVICE_STATE_DIR="$TMP_DIR/device-state"
"$ROOT_DIR/bin/dataproxy-agent" enroll \
  -hub "https://127.0.0.1:48443" \
  -code "$ENROLL_CODE" \
  -state-dir "$DEVICE_STATE_DIR" \
  -ca "$TMP_DIR/certs/ca.crt" \
  -server-name "localhost"

AUDIT_FILE="$TMP_DIR/tenant-audit.jsonl"
write_agent_yaml() {
  local redis_window="$1"
  cat > "$TMP_DIR/agent.yaml" <<EOF
device_state_dir: "$DEVICE_STATE_DIR"
agent_id: "orb-node-01"
log_level: "warn"
max_bandwidth: "20MB/s"
timezone: "UTC"
config_watch_interval: 150ms
health_report_interval: 1s
audit:
  file: "$AUDIT_FILE"
server:
  mode: "wss"
  url: "wss://127.0.0.1:48443/tunnel/v1/connect"
  tls:
    ca_file: "$TMP_DIR/certs/ca.crt"
    server_name: "localhost"
services:
  - name: "pg-prod"
    protocol: "tcp"
    target_addr: "127.0.0.1:55432"
    target_tls:
      enabled: true
      ca_file: "$TMP_DIR/certs/ca.crt"
      server_name: "localhost"
    guard:
      type: "postgres"
      read_only: true
      credential_injection:
        enabled: true
        username: "env:ORB_PG_USER"
        password: "file:$TMP_DIR/secrets/pg_pass"

  - name: "mysql-prod"
    protocol: "tcp"
    target_addr: "127.0.0.1:53306"
    target_tls:
      enabled: true
      ca_file: "$TMP_DIR/certs/ca.crt"
      server_name: "localhost"
    guard:
      type: "mysql"
      read_only: true
      credential_injection:
        enabled: true
        username: "env:ORB_MYSQL_USER"
        password: "file:$TMP_DIR/secrets/mysql_pass"

  - name: "mongo-prod"
    protocol: "tcp"
    target_addr: "127.0.0.1:57017"
    target_tls:
      enabled: true
      ca_file: "$TMP_DIR/certs/ca.crt"
      server_name: "localhost"
    guard:
      type: "mongodb"
      read_only: true
      credential_injection:
        enabled: true
        username: "env:ORB_MONGO_USER"
        password: "file:$TMP_DIR/secrets/mongo_pass"
        auth_source: "admin"

  - name: "redis-prod"
    protocol: "tcp"
    target_addr: "127.0.0.1:56379"
    target_tls:
      enabled: true
      ca_file: "$TMP_DIR/certs/ca.crt"
      server_name: "localhost"
    allowed_windows: $redis_window
    guard:
      type: "redis"
      read_only: true
      credential_injection:
        enabled: true
        password: "file:$TMP_DIR/secrets/redis_pass"
EOF
}
write_agent_yaml "[]"

export ORB_PG_USER="tenant_pg_reader"
export ORB_MYSQL_USER="mysql_real_reader"
export ORB_MONGO_USER="mongo_real_reader"

echo ""
echo ">>> [4/6] 运行 dataproxy-agent doctor 全链路体检（针对 4 个真实容器）..."
"$ROOT_DIR/bin/dataproxy-agent" doctor -config "$TMP_DIR/agent.yaml"

"$ROOT_DIR/bin/dataproxy-agent" -config "$TMP_DIR/agent.yaml" &
AGENT_PID=$!
sleep 0.8

echo ""
echo ">>> [5/6] 模拟中心平台零真实密码穿过隧道访问 4 个真实数据库（读放行 + 写阻断）..."

echo "--- 5.1 PostgreSQL 16 (Split-TLS + SCRAM-SHA-256 本地代填 + 只读拦截) ---"
PG_READ=$(docker exec dpx-live-pg psql "postgresql://dummy_center:wrong_pass@host.docker.internal:45432/demo?sslmode=disable" -tAc "SELECT item FROM orders WHERE id=1;")
PG_SSL_ON=$(docker exec dpx-live-pg psql "postgresql://dummy_center:wrong_pass@host.docker.internal:45432/demo?sslmode=disable" -tAc "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();")
echo "  [READ]  SELECT item => $PG_READ (pg_stat_ssl.ssl=${PG_SSL_ON})"
[ "$PG_READ" = "pg-laptop" ]
[ "$PG_SSL_ON" = "t" ]
PG_WRITE_OUT=$(docker exec dpx-live-pg psql "postgresql://dummy_center:wrong_pass@host.docker.internal:45432/demo?sslmode=disable" -c "DELETE FROM orders;" 2>&1 || true)
echo "  [WRITE] DELETE FROM orders => $PG_WRITE_OUT"
echo "$PG_WRITE_OUT" | grep -q "dataproxy-agent:"
PG_VERIFY=$(docker exec -e PGPASSWORD='PgRealVaultPass!2026' dpx-live-pg psql -U tenant_pg_reader -d demo -tAc "SELECT count(*) FROM orders;")
[ "$PG_VERIFY" = "1" ]
echo "  [OK]    PostgreSQL 16 Split-TLS 实测通过（pg_stat_ssl=t，数据完好 count=${PG_VERIFY}）！"

echo "--- 5.2 MySQL 8.4 (require_secure_transport=ON Split-TLS + caching_sha2_password 本地代填 + 只读拦截) ---"
MYSQL_READ=$(docker exec dpx-live-mysql mysql --ssl-mode=DISABLED -h host.docker.internal -P 43306 -u dummy_center -pwrong_pass -NBe "SELECT item FROM demo.orders WHERE id=1;" 2>/dev/null)
MYSQL_CIPHER=$(docker exec dpx-live-mysql mysql --ssl-mode=DISABLED -h host.docker.internal -P 43306 -u dummy_center -pwrong_pass -NBe "SHOW STATUS LIKE 'Ssl_cipher';" 2>/dev/null | awk '{print $2}')
echo "  [READ]  SELECT item => $MYSQL_READ (Ssl_cipher=${MYSQL_CIPHER})"
[ "$MYSQL_READ" = "mysql-laptop" ]
[ -n "$MYSQL_CIPHER" ]
MYSQL_WRITE_OUT=$(docker exec dpx-live-mysql mysql --ssl-mode=DISABLED -h host.docker.internal -P 43306 -u dummy_center -pwrong_pass -e "DELETE FROM demo.orders;" 2>&1 || true)
echo "  [WRITE] DELETE FROM orders => $MYSQL_WRITE_OUT"
echo "$MYSQL_WRITE_OUT" | grep -q "1290"
MYSQL_VERIFY=$(docker exec dpx-live-mysql mysql --ssl-mode=REQUIRED -h 127.0.0.1 -u mysql_real_reader -p'MysqlRealVaultPass!2026' -NBe "SELECT count(*) FROM demo.orders;" 2>/dev/null)
[ "$MYSQL_VERIFY" = "1" ]
echo "  [OK]    MySQL 8.4 Split-TLS 实测通过（cipher=${MYSQL_CIPHER}，数据完好 count=${MYSQL_VERIFY}）！"

echo "--- 5.3 MongoDB 8.0 (--tlsMode requireTLS + 主动 SCRAM-SHA-256 本地代填 + OP_MSG & \$out 管道只读拦截) ---"
MONGO_READ=$(docker exec dpx-live-mongo mongosh --quiet "mongodb://host.docker.internal:47017/demo?directConnection=true" --eval 'db.orders.findOne({_id:1}).item')
echo "  [READ]  db.orders.findOne => $MONGO_READ"
[ "$MONGO_READ" = "mongo-laptop" ]
MONGO_WRITE_OUT=$(docker exec dpx-live-mongo mongosh --quiet "mongodb://host.docker.internal:47017/demo?directConnection=true" --eval 'db.orders.deleteMany({})' 2>&1 || true)
echo "  [WRITE] db.orders.deleteMany => $(echo "$MONGO_WRITE_OUT" | head -n 1)"
echo "$MONGO_WRITE_OUT" | grep -q "dataproxy-agent:"
MONGO_AGG_OUT=$(docker exec dpx-live-mongo mongosh --quiet "mongodb://host.docker.internal:47017/demo?directConnection=true" --eval 'db.orders.aggregate([{$out: "stolen"}])' 2>&1 || true)
echo "  [WRITE] aggregate(\$out) => $(echo "$MONGO_AGG_OUT" | head -n 1)"
echo "$MONGO_AGG_OUT" | grep -q "dataproxy-agent:"
MONGO_VERIFY=$(docker exec dpx-live-mongo mongosh --quiet --tls --tlsCAFile /certs/ca.crt -u mongo_real_reader -p 'MongoRealVaultPass!2026' --authenticationDatabase admin demo --eval 'db.orders.countDocuments()')
[ "$MONGO_VERIFY" = "1" ]
echo "  [OK]    MongoDB 8.0 requireTLS 实测通过（数据完好 count=${MONGO_VERIFY}）！"

echo "--- 5.4 Redis 7 (--tls-port 6379 TLS-only + 本地 AUTH 代填 + 只读命令白名单拦截) ---"
REDIS_READ=$(docker exec dpx-live-redis redis-cli -h host.docker.internal -p 46379 -a wrong_pass --no-auth-warning GET order:1001)
echo "  [READ]  GET order:1001 => $REDIS_READ"
[ "$REDIS_READ" = "redis-laptop" ]
REDIS_WRITE_OUT=$(docker exec dpx-live-redis redis-cli -h host.docker.internal -p 46379 -a wrong_pass --no-auth-warning SET order:1001 hacked 2>&1 || true)
echo "  [WRITE] SET order:1001 => $REDIS_WRITE_OUT"
echo "$REDIS_WRITE_OUT" | grep -q "dataproxy-agent:"
REDIS_VERIFY=$(docker exec dpx-live-redis redis-cli --tls --cacert /certs/ca.crt -a 'RedisRealVaultPass!2026' --no-auth-warning GET order:1001)
[ "$REDIS_VERIFY" = "redis-laptop" ]
echo "  [OK]    Redis 7 TLS-only 实测通过（数据完好 value=${REDIS_VERIFY}）！"

echo ""
echo ">>> [6/7] 验证「单端口短效单任务票据路由 (防串租户) + 访问事由本地审计 + 时间窗热加载」..."

issue_ticket() {
  local svc="$1"
  curl -sf -X POST http://127.0.0.1:49090/api/v1/tickets \
    -H "Authorization: Bearer live-admin-token" \
    -H "Content-Type: application/json" \
    -d "{\"tenant_id\":\"tenant-orb\",\"service_name\":\"${svc}\",\"ttl_seconds\":300,\"purpose\":{\"job_type\":\"daily_sync\",\"job_id\":\"sync_orb_9921\",\"triggered_by\":\"报表中心-定时任务\"}}"
}

PG_TKT_JSON=$(issue_ticket "pg-prod")
PG_JWT=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["ticket"])' <<< "$PG_TKT_JSON")
PG_SMART_READ=$(docker exec dpx-live-pg psql "postgresql://tenant-orb.pg-prod:${PG_JWT}@host.docker.internal:45433/demo?sslmode=disable" -tAc "SELECT item FROM orders WHERE id=1;")
echo "  [PG Smart Port]    SELECT => $PG_SMART_READ"
[ "$PG_SMART_READ" = "pg-laptop" ]

# 跨租户防串数验证：拿 tenant-orb 的票据尝试路由到 other-tenant 必须被拒绝！
PG_CROSS_OUT=$(docker exec dpx-live-pg psql "postgresql://other-tenant.pg-prod:${PG_JWT}@host.docker.internal:45433/demo?sslmode=disable" -tAc "SELECT 1;" 2>&1 || true)
echo "  [PG Cross-Tenant]  other-tenant => $(echo "$PG_CROSS_OUT" | head -n 1)"
echo "$PG_CROSS_OUT" | grep -q "does not match"

MYSQL_TKT_JSON=$(issue_ticket "mysql-prod")
MYSQL_USER=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["mysql_user"])' <<< "$MYSQL_TKT_JSON")
MYSQL_PASS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["mysql_password"])' <<< "$MYSQL_TKT_JSON")
MYSQL_SMART_READ=$(docker exec dpx-live-mysql mysql --ssl-mode=DISABLED -h host.docker.internal -P 43307 -u "$MYSQL_USER" -p"$MYSQL_PASS" -NBe "SELECT item FROM demo.orders WHERE id=1;" 2>/dev/null)
echo "  [MySQL Smart Port] SELECT => $MYSQL_SMART_READ"
[ "$MYSQL_SMART_READ" = "mysql-laptop" ]

MONGO_TKT_JSON=$(issue_ticket "mongo-prod")
MONGO_JWT=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["ticket"])' <<< "$MONGO_TKT_JSON")
MONGO_SMART_READ=$(docker exec dpx-live-mongo mongosh --quiet "mongodb://tenant-orb.mongo-prod:${MONGO_JWT}@host.docker.internal:47018/demo?authMechanism=PLAIN&authSource=%24external&directConnection=true" --eval 'db.orders.findOne({_id:1}).item')
echo "  [Mongo Smart Port] findOne (SASL PLAIN + JWT) => $MONGO_SMART_READ"
[ "$MONGO_SMART_READ" = "mongo-laptop" ]

MONGO_CROSS_OUT=$(docker exec dpx-live-mongo mongosh --quiet "mongodb://other-tenant.mongo-prod:${MONGO_JWT}@host.docker.internal:47018/demo?authMechanism=PLAIN&authSource=%24external&directConnection=true" --eval 'db.orders.findOne()' 2>&1 || true)
echo "  [Mongo Cross-Tenant] other-tenant => $(echo "$MONGO_CROSS_OUT" | head -n 1)"
echo "$MONGO_CROSS_OUT" | grep -q "does not match"

REDIS_TKT_JSON=$(issue_ticket "redis-prod")
REDIS_JWT=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["ticket"])' <<< "$REDIS_TKT_JSON")
REDIS_SMART_READ=$(docker exec dpx-live-redis redis-cli -h host.docker.internal -p 46380 -a "$REDIS_JWT" --no-auth-warning GET order:1001)
echo "  [Redis Smart Port] GET => $REDIS_SMART_READ"
[ "$REDIS_SMART_READ" = "redis-laptop" ]

# 热加载时间窗拦截验证（不重启 Agent PID，实时修改 agent.yaml 限制窗口！）
CLOSED_WIN=$(python3 -c 'import datetime; h=(datetime.datetime.now(datetime.timezone.utc).hour+3)%24; print(f"[\"{h:02d}:00-{(h+1)%24:02d}:00\"]")')
write_agent_yaml "$CLOSED_WIN"
sleep 0.5
REDIS_WIN_OUT=$(docker exec dpx-live-redis redis-cli -h host.docker.internal -p 46380 -a "$REDIS_JWT" --no-auth-warning GET order:1001 2>&1 || true)
echo "  [HotReload Window] 锁闭窗口后访问 Redis => $REDIS_WIN_OUT"
echo "$REDIS_WIN_OUT" | grep -q "ERR_OUTSIDE_ACCESS_WINDOW"

# 再次热加载放开窗口并验证无重启恢复！
write_agent_yaml "[]"
sleep 0.5
REDIS_RECOVER=$(docker exec dpx-live-redis redis-cli -h host.docker.internal -p 46380 -a "$REDIS_JWT" --no-auth-warning GET order:1001)
echo "  [HotReload Open]   放开窗口后访问 Redis => $REDIS_RECOVER"
[ "$REDIS_RECOVER" = "redis-laptop" ]

# 验证租户本地 JSONL 审计日志完整记录了业务 Purpose 与热加载事件！
grep -q "sync_orb_9921" "$AUDIT_FILE"
grep -q "报表中心-定时任务" "$AUDIT_FILE"
grep -q "ERR_OUTSIDE_ACCESS_WINDOW" "$AUDIT_FILE"
grep -q "config_reloaded" "$AUDIT_FILE"
echo "  [Audit JSONL]      已验证租户本地审计文件完整记录 job_id=sync_orb_9921 / 报表中心-定时任务 / 时间窗阻断 / 配置热加载！"

echo ""
echo ">>> [7/7] 中心端 /api/v1/tenants 实时健康度遥测（脱敏，绝不含内网真实 IP）与 /metrics 核验："
TENANTS_JSON=$(curl -sf -H "Authorization: Bearer live-admin-token" http://127.0.0.1:49090/api/v1/tenants)
echo "$TENANTS_JSON" | grep -q '"service_health"'
echo "$TENANTS_JSON" | grep -q 'MySQL 8.4.13'
echo "$TENANTS_JSON" | grep -q 'PostgreSQL v3'
echo "$TENANTS_JSON" | grep -q 'MongoDB'
! echo "$TENANTS_JSON" | grep -q '55432'
echo "  [Health Telemetry] /api/v1/tenants 已实时收到 4 库脱敏健康状态，且零内网 IP/端口泄漏！"
curl -s http://127.0.0.1:49090/metrics | grep -E "dataproxy_(online_tenants|tcp_bindings|tenant_bytes|tenant_service_healthy)"

echo ""
echo "================ ALL 4 ORBSTACK LIVE DATABASE + SAAS CONNECTOR TESTS PASSED! ================"
