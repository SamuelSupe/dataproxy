# dataproxy — Multi-Tenant Secure Reverse Proxy & Native Protocol Data Connector

<p align="center">
  <strong>English</strong> | <a href="./README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="https://github.com/SamuelSupe/dataproxy/releases"><img src="https://img.shields.io/github/v/release/SamuelSupe/dataproxy" alt="Release"></a>
  <a href="https://github.com/SamuelSupe/dataproxy/actions/workflows/ci.yml"><img src="https://github.com/SamuelSupe/dataproxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/go-1.26+-00ADD8?logo=go" alt="Go">
</p>

`dataproxy` is a **zero-inbound-port, zero-trust reverse tunnel gateway** built for multi-tenant SaaS platforms, AI Agents, and enterprise data pipelines. It consists of a single-binary, zero-CGO tenant connector (**`dataproxy-agent`**) deployed inside each customer's private network and a horizontally scalable central gateway & control plane (**`dataproxy-hub`**).

Enterprise tenants can safely mount internal **MySQL, PostgreSQL, MongoDB, Redis, SQL Server, Oracle, ClickHouse, Apache Doris / StarRocks, HTTP(S), and raw TCP services** exclusively for your central platform to read — **without opening any public inbound firewall ports**, while enforcing **tenant-local L7 read-only guards, zero-exfiltration credential injection, Split-TLS, access time windows, and purpose-based compliance auditing**.

---

## Key Features

### 1. Zero Inbound Ports & High-Throughput Multi-Protocol Tunnels
- **Three Outbound Transport Modes (`wss` / `quic` / `auto` / `tls`)**:
  - **`quic`**: Native QUIC over UDP + TLS 1.3 with QUIC native bidirectional streams (zero Yamux overhead, zero transport Head-of-Line blocking, RFC 9002 `SmoothedRTT` telemetry, enlarged 4–16 MiB stream / 8–32 MiB conn windows).
  - **`auto` (Happy-Eyeballs)**: Gives QUIC a `250ms` head-start and races WSS in parallel (with a 60s negative cache when UDP is blackholed by corporate firewalls, achieving ~258ms seamless fallback), and switches directly to WSS when `proxy_url` / `HTTPS_PROXY` is detected.
  - **`wss` / `tls`**: WebSocket over TLS (port 443) with native corporate `HTTP_PROXY` / `proxy_url` traversal, plus raw mTLS TCP.
- **Multi-Lane Tunnel Pool (`pool_size`) with Control/Data Plane Separation**: When `pool_size >= 2`, `Lane 0` is dedicated to control heartbeats and health probes while `Lanes 1..N-1` multiplex parallel data streams (4 MiB Yamux stream window + 64 KiB pooled zero-copy buffers).
- **Exact-Boundary Binary Framing**: Zero over-reading on stream open handshakes, immediately switching to a raw byte pipe with TCP/QUIC half-close (`CloseWrite`) support — 100% compatible with Server-First protocols like MySQL.

### 2. Tenant-Side Zero-Trust Security Boundary (Pure Go, Zero CGO)
- **Local Zero-Trust Allowlist**: Only explicitly declared logical services are reachable. Real intranet IPs, ports, and database passwords **never leave the tenant network**.
- **Pluggable L7 Read-Only Guards + Local Credential Injection (`env:` / `file:`, K8s Secret & Vault Agent ready)**:
  - **MySQL 8.x / 8.4, Apache Doris & StarRocks (`mysql` / `doris` / `starrocks`)**: Supports local `caching_sha2_password` (RSA-OAEP & TLS cleartext) and `mysql_native_password` injection; zero-allocation lexical guard (`0 allocs/op`) blocks write SQL, multi-statement smuggling, conditional comment bypasses, `INTO OUTFILE`, and `FOR UPDATE` (returns standard MySQL `ERR 1290`).
  - **PostgreSQL 16 (`postgres`)**: Rewrites `StartupMessage` and completes `SCRAM-SHA-256` / MD5 / Cleartext auth locally; intercepts Simple/Extended Queries and `COPY`, blocking writes and privileged functions like `pg_terminate_backend` (returns standard `SQLSTATE 25006`).
  - **MongoDB 8.0 (`mongodb`)**: Pure-Go BSON parser (`6.9 ns/op | 0 allocs/op` fast path) + proactive local `SCRAM-SHA-256` auth; strict read-only command allowlist with deep inspection blocking `$out` and `$merge` aggregation stages.
  - **Redis 7 (`redis`)**: Proactive local `AUTH` / `HELLO` injection + strict read-only command allowlist.
  - **SQL Server (`mssql` / `sqlserver`)**: Pure-Go MS-TDS v7.x guard with `PRELOGIN` probing, `LOGIN7` local UTF-16LE credential injection, `SQL_BATCH` & `RPC_REQUEST` inspection (`sp_executesql` / `sp_prepare` / `sp_prepexec`), blocking writes, `SELECT ... INTO`, `UPDLOCK`, `xp_cmdshell`, and `BULK_LOAD` (returns standard TDS `ERROR 0xAA` + `DONE 0xFD`).
  - **Oracle (`oracle`)**: Pure-Go TNS/TTC guard with `CONNECT` probing (1521 / TCPS 2484) and read-only SQL/PLSQL enforcement blocking DML/DDL, anonymous PL/SQL blocks, and `DBMS_*` / `UTL_FILE` / `UTL_HTTP` packages (returns `ORA-01031`).
  - **ClickHouse (`clickhouse` / `ch`)**: Auto-detects **HTTP(S) (8123/8443)** and **Native TCP (9000/9440)** interfaces; supports local credential injection (`X-ClickHouse-User`/`X-ClickHouse-Key` or `ClientHello` rewrite), injects `readonly=1`, and blocks writes & external SSRF table functions (`url()`, `file()`, `s3()`, etc., returning `Code: 497`).
  - **HTTP / HTTPS**: Enforces `allowed_http_methods` locally (`403 Forbidden`) and supports `inject_headers` to inject tenant-local API tokens/keys without exposing them to the central platform.
- **Tenant-Side Split-TLS (`target_tls`)**: Natively supports SSL-enforced cloud RDS and encrypted intranet services (AWS/Aliyun RDS `rds.force_ssl=1`, MySQL `--require-secure-transport=ON`, MongoDB `--tlsMode requireTLS`, Redis `--tls-port`, Oracle TCPS, and internal HTTPS) via protocol-native STARTTLS or direct TLS — while keeping L7 read-only filtering and local credential injection intact.
- **One-Time 15-Minute Enrollment & Device PKI (`dataproxy-agent enroll`)**: Generates an ECDSA P-256 private key strictly on the tenant host (atomic `fsync` state persistence; private key never leaves disk), exchanges a single-use enrollment code for a short-lived device certificate with automatic rotation, and supports instant per-device revocation (`device_id`).
- **Access Time Windows, Lossless Hot-Reload & Purpose Auditing**: Supports overnight/weekday IANA-timezone access schedules, lossless config hot-reload (`SIGHUP` + file watcher, zero interruption to in-flight queries), and local JSONL + non-blocking async Syslog/SIEM audit logs recording central `Purpose` metadata and W3C `traceparent`.

### 3. Multi-Node HA Hub Cluster, Standard Ingress & Observability
- **Shared MySQL Control Plane (`store_mysql_dsn`) for 3+ Node HA Clusters**:
  - Auto-migrates schema (`dpx_device_ca`, `dpx_devices`, `dpx_enrollments`, `dpx_tenants`, `dpx_bindings`) and converges concurrent cold-booting Hub nodes onto a single shared Device CA (`SaveDeviceCAIfAbsent`).
  - Single-use enrollment codes are atomically consumed via `SELECT ... FOR UPDATE` across any Hub node.
  - **0ms read-through auth** for new enrollments/revocations + background `O(1)` watermark sync (`ClusterWatermark`) that automatically **kicks live sessions on peer Hub nodes** when a device is revoked or a tenant is disabled.
- **Multi-Node Hub Cluster Mesh & Stateless Tickets**: Multi-node Hub clusters transparently forward streams across nodes via `mesh_peers` with an `O(1)` sticky route cache; MySQL smart-router tickets use **100% stateless cross-node HMAC verification**.
- **Single-Port Multi-Tenant Smart DB Ticket Routers (Anti-Cross-Tenant)**: Native `psql`, `mysql`, `mongosh` (SASL PLAIN), `redis-cli`, and standard drivers connect directly to a single hub port per DB type using short-lived, single-tenant job tickets (`POST /api/v1/tickets`).
- **Flexible Central Ingress & HA Scheduling**: Dedicated/dynamic TCP port mapping, single-port `SOCKS5 + HTTP CONNECT` virtual domain proxy, HTTP/WS reverse proxy (`X-Dataproxy-Ticket`), plus instant degraded-replica deprioritization to avoid HA blackhole stalls.
- **Noisy Neighbor Protection & Full Observability**: Bounded-memory per-IP handshake rate limiting (`maxRateLimitEntries = 16384`), per-tenant Hub concurrent stream & session quotas, end-to-end W3C `traceparent` propagation, sanitized health telemetry (`FrameHealthReport`), Prometheus latency histograms (`dataproxy_stream_open_duration_seconds`, `dataproxy_tunnel_rtt_seconds`, `dataproxy_sessions_by_transport`), device cert expiry gauge, and parallel `dataproxy-agent doctor` diagnostics.

---

## Quick Start

### 1. Download Release Binaries, Docker, or Build from Source

Download prebuilt archives from [GitHub Releases](https://github.com/SamuelSupe/dataproxy/releases), or build locally:

```bash
# Build dataproxy-hub and dataproxy-agent
make build

# Generate local self-signed CA and Hub TLS certificates for development
make certs

# Or build minimal multi-stage Docker images
docker build --target hub -t dataproxy-hub:v0.2.0 .
docker build --target agent -t dataproxy-agent:v0.2.0 .
```

Production `systemd` unit templates are included in [deploy/systemd/dataproxy-hub.service](./deploy/systemd/dataproxy-hub.service) and [deploy/systemd/dataproxy-agent.service](./deploy/systemd/dataproxy-agent.service).

### 2. Start `dataproxy-hub`

```bash
./bin/dataproxy-hub -config configs/hub.example.yaml
```

For a 3+ node HA Hub cluster, configure `store_mysql_dsn` (and `mesh_listen_addr` / `mesh_peers`) in [configs/hub.example.yaml](./configs/hub.example.yaml).

### 3. Enroll a Tenant Agent via One-Time Enrollment Code (Recommended)

```bash
# Issue a 15-minute single-use enrollment code on any Hub node
curl -X POST http://127.0.0.1:9090/api/v1/enrollments \
  -H "Authorization: Bearer dpx_admin_change_me" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"tenant-acme","device_name":"dc-node-01","ttl_seconds":900}'

# Enroll on the tenant host (private key stays locally on disk)
./bin/dataproxy-agent enroll \
  -hub https://127.0.0.1:8443 \
  -code enroll_xxx \
  -state-dir ./device-state \
  -ca ./certs/ca.crt
```

### 4. Run Preflight Diagnostics & Start `dataproxy-agent`

```bash
./bin/dataproxy-agent doctor -config configs/agent.example.yaml
./bin/dataproxy-agent -config configs/agent.example.yaml
```

---

## Central Platform Access Examples

### 1. Issue a Short-Lived Job Ticket & Connect Directly via Single-Port DB Routers

```bash
# Issue a job ticket scoped strictly to (tenant_id, service_name) with audit purpose
curl -X POST http://127.0.0.1:9090/api/v1/tickets \
  -H "Authorization: Bearer dpx_admin_change_me" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-acme",
    "service_name": "pg-analytics",
    "ttl_seconds": 300,
    "purpose": {"job_type": "daily_sync", "job_id": "sync_001"}
  }'

# PostgreSQL (zero client modification)
psql "postgresql://tenant-acme.pg-analytics:<JWT>@127.0.0.1:15432/demo?sslmode=disable"

# MySQL (stateless cross-node ticket verification)
mysql --ssl-mode=DISABLED -h 127.0.0.1 -P 13306 -u "<mysql_user>" -p"<mysql_password>"

# MongoDB (SASL PLAIN)
mongosh "mongodb://tenant-acme.mongo-catalog:<JWT>@127.0.0.1:17017/demo?authMechanism=PLAIN&authSource=%24external&directConnection=true"

# Redis
redis-cli -h 127.0.0.1 -p 16379 -a "<JWT>" GET order:1001
```

### 2. HTTP Reverse Proxy (Job Ticket + W3C `traceparent`)

```bash
curl http://127.0.0.1:8080/v1/orders \
  -H "X-Dataproxy-Ticket: <JWT>" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
```

### 3. Unified Single-Port `SOCKS5` / `HTTP CONNECT` Proxy

```bash
curl -x socks5h://data-sync-platform:dpx_caller_platform_secret@127.0.0.1:1080 \
  http://internal-erp.tenant-acme.dataproxy.internal:8000/api/health
```

### 4. Control Plane & Prometheus Metrics

```bash
curl -H "Authorization: Bearer dpx_admin_change_me" http://127.0.0.1:9090/api/v1/tenants
curl http://127.0.0.1:9090/metrics
```

---

## Testing & Verification

```bash
# Static analysis and full unit + E2E test suite with race detector
make vet
make test

# Live end-to-end verification against 4 TLS-enforced Docker/OrbStack databases
# (PostgreSQL 16 ssl=on, MySQL 8.4 require_secure_transport=ON, MongoDB 8.0 requireTLS, Redis 7 TLS-only)
make test-orbstack

# Optional live 3-node Hub cluster E2E against a real MySQL instance
DATAPROXY_TEST_MYSQL_DSN="dataproxy:pass@tcp(127.0.0.1:3306)/dataproxy?parseTime=true" \
  go test -v -race -count=1 ./test/e2e -run TestCluster_SharedMySQLStore_3Node
```

## License

[MIT](./LICENSE)
