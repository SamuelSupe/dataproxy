# dataproxy — 多租户安全反向代理与原生协议数据连接网关

<p align="center">
  <a href="./README.md">English</a> | <strong>简体中文</strong>
</p>

<p align="center">
  <a href="https://github.com/SamuelSupe/dataproxy/releases"><img src="https://img.shields.io/github/v/release/SamuelSupe/dataproxy" alt="Release"></a>
  <a href="https://github.com/SamuelSupe/dataproxy/actions/workflows/ci.yml"><img src="https://github.com/SamuelSupe/dataproxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/go-1.26+-00ADD8?logo=go" alt="Go">
</p>

`dataproxy` 是一套专为多租户 SaaS 平台、AI Agent 与企业级数据平台设计的**零入向开墙、零信任反向隧道网关**，由租户内网部署的单二进制纯 Go 零 CGO 客户端 **`dataproxy-agent`** 和支持水平扩展的中心侧网关与控制面 **`dataproxy-hub`** 组成。

它让企业客户**无需向公网暴露任何入向端口**，即可通过加密出向隧道将内网的 **MySQL / PostgreSQL / MongoDB / Redis / SQL Server / Oracle / ClickHouse / Apache Doris / StarRocks / HTTP(S) / 通用 TCP 服务**安全挂载给中心平台读取，并在租户本地强制执行 **L7 只读拦截、凭据不出域代填、Split-TLS、时间窗访问控制与事由审计**。

---

## 核心特性

### 1. 零入向开墙与高性能多协议出向隧道
- **三模加密出向传输（`wss` / `quic` / `auto` / `tls`）**：
  - **`quic`**：原生 QUIC（UDP + TLS 1.3 + 原生多路流，彻底消除 Yamux 层与传输层队头阻塞，支持 RFC 9002 `SmoothedRTT` 零发包延迟采样及 4~16 MiB 流 / 8~32 MiB 连接大窗口）。
  - **`auto`（Happy-Eyeballs 竞速自适应）**：QUIC 领先 `250ms` 探测，未连上即并行竞速 WSS（遇 UDP 黑洞防火墙约 `258ms` 无感切换 + 60s 负缓存），检测到企业正向代理自动直走 WSS。
  - **`wss` / `tls`**：WebSocket over TLS 443（原生穿透企业出向正向代理 `HTTP_PROXY` / `proxy_url`）与原生 mTLS TCP。
- **多连接并行隧道池（`pool_size`）与控制/数据面分离**：当 `pool_size >= 2` 时，`Lane 0` 专跑控制面心跳与健康探活，`Lane 1..N-1` 专跑数据流多路复用（4 MiB Yamux 窗口 + 64 KiB 零拷贝缓冲池）。
- **精确二进制定长帧协议**：零预读、零吞字节，流建立后无缝切换至支持 TCP/QUIC 半关闭（`CloseWrite`）的原始字节管道，100% 兼容 MySQL 等 Server-First 协议。

### 2. 面向“中心平台专用读取”的租户侧零信任安全边界（全纯 Go 零 CGO）
- **本地零信任白名单**：真实内网 IP/端口与数据库密码**绝不上报给中心**。
- **插件化 L7 协议只读守卫 + 凭据不出域代填（`env:` / `file:`，兼容 K8s Secret / Vault Agent）**：
  - **MySQL 8.x/8.4、Apache Doris 与 StarRocks（`mysql` / `doris` / `starrocks`）**：支持 `caching_sha2_password`（无 TLS RSA-OAEP 及 TLS 明文路径）与 `mysql_native_password` 代填；零分配词法守卫（`0 allocs/op`）拦截写 SQL、多语句注入、条件注释绕过、`INTO OUTFILE` 与 `FOR UPDATE`（返回标准 `ERR 1290`）。
  - **PostgreSQL 16（`postgres`）**：支持 `SCRAM-SHA-256` / MD5 / Cleartext 本地代填；拦截 Simple/Extended Query 与 `COPY` 流及 `pg_terminate_backend` 等危险函数（返回标准 `SQLSTATE 25006`）。
  - **MongoDB 8.0（`mongodb`）**：纯 Go BSON 解析器（`6.9 ns/op | 0 allocs/op` 快路径）+ 主动 `SCRAM-SHA-256` 本地代填；白名单放行只读命令并深度拦截 `aggregate` `$out` / `$merge` 写阶段。
  - **Redis 7（`redis`）**：主动本地 `AUTH` / `HELLO` 代填 + 只读命令白名单拦截。
  - **SQL Server（`mssql` / `sqlserver`）**：纯 Go MS-TDS v7.x 守卫，支持 `PRELOGIN` 无凭据探活、`LOGIN7` UTF-16LE 本地凭据代填、`SQL_BATCH` 与 `RPC_REQUEST`（解析 `sp_executesql` / `sp_prepare` / `sp_prepexec`）深度检查，拦截写语句、`SELECT ... INTO`、`UPDLOCK`、`xp_cmdshell` 与 `BULK_LOAD`（返回标准 TDS `ERROR 0xAA` + `DONE 0xFD`）。
  - **Oracle（`oracle`）**：纯 Go TNS/TTC 守卫，支持 `CONNECT` 无凭据探活（1521 / TCPS 2484）与只读 SQL/PLSQL 拦截，阻断 DML/DDL、匿名 PL/SQL 块及 `DBMS_*` / `UTL_FILE` / `UTL_HTTP` 等危险包（返回 `ORA-01031`）。
  - **ClickHouse（`clickhouse` / `ch`）**：首字节自动识别 **HTTP(S)（8123/8443）** 与 **Native TCP（9000/9440）** 双接口，支持本地凭据代填（`X-ClickHouse-User`/`X-ClickHouse-Key` 或 `ClientHello` 重写）、自动注入 `readonly=1`，拦截写语句及 `url()`/`file()`/`s3()` 等外部表函数 SSRF（返回标准 `Code: 497`）。
  - **HTTP / HTTPS**：按 `allowed_http_methods` 本地拦截写方法并返回 `403`；支持 `inject_headers` 本地代填客户内部平台 Token/API Key。
- **租户内网侧 Split-TLS（`target_tls`）**：支持客户内网强制 SSL 的云 RDS（AWS/阿里云 RDS `rds.force_ssl=1`、MySQL `--require-secure-transport=ON`、MongoDB `--tlsMode requireTLS`、Redis `--tls-port`、Oracle TCPS 及内网 HTTPS），在本地完成 STARTTLS / 直连 TLS 握手并完整保留 L7 只读拦截与凭据代填。
- **一次性 15 分钟挂载码与设备 PKI（`dataproxy-agent enroll`）**：私钥永不出客户主机（`fsync` 原子落盘防轮换掉电损坏），自动签发并后台轮换短期设备证书，支持按 `device_id` 秒级单设备精准吊销。
- **访问时间窗、无损热加载与事由审计**：支持跨午夜/星期级时间窗、`SIGHUP`/文件监听无损热加载（不断开在途查询），并将中心透传的业务 `Purpose` 与 W3C `traceparent` 写入租户本地 JSONL 与异步 Syslog/SIEM。

### 3. 多节点高可用 Hub 集群、全品类标准接入与可观测性
- **多节点 Hub 共享 MySQL 控制面存储（`store_mysql_dsn`）**：
  - 自动迁移控制面表结构（`dpx_device_ca` / `dpx_devices` / `dpx_enrollments` / `dpx_tenants` / `dpx_bindings`），3+ 节点并发冷启动自动收敛至唯一共享 Device CA；
  - 一次性挂载码通过 MySQL `SELECT ... FOR UPDATE` 跨节点原子消费；
  - 新设备注册与吊销在鉴权路径直连 MySQL **0ms 读透**，同时各节点通过 `O(1)` 索引水位轮询（`ClusterWatermark`）实时同步吊销黑名单并**自动踢下线对端节点的活跃隧道**。
- **Hub Cluster Mesh + 跨节点无状态票据**：多节点 Hub 通过 `mesh_peers` + `O(1)` 粘性路由缓存透明跨节点转发；MySQL 单端口票据支持 100% 跨节点无状态 HMAC 验签。
- **四大数据库单端口智能票据路由（Ticket-in-Auth 防串租户）**：中心原生 `psql`、`mysql`、`mongosh`（SASL PLAIN）、`redis-cli` 与各语言驱动零改造直连单个端口，通过短效单任务票据路由并物理防串租户。
- **多形态中心入口与 HA 黑洞快速避让**：支持独立/动态 TCP 端口映射、单端口自识别 `SOCKS5 + HTTP CONNECT` 虚拟域名代理、标准 HTTP/WS 反向代理（`X-Dataproxy-Ticket`），以及异常副本即时降级调度。
- **吵闹邻居隔离与全链路观测**：有界内存每 IP 握手令牌桶限流（防伪造 IP 洪泛）、Hub 侧租户并发流/会话配额、W3C `traceparent` 透传、无侵入脱敏健康度遥测（`FrameHealthReport`）、Prometheus 延迟直方图（`dataproxy_stream_open_duration_seconds`、`dataproxy_tunnel_rtt_seconds`、`dataproxy_sessions_by_transport`）、设备证书到期倒计时指标，以及并发 `dataproxy-agent doctor` 一键全链路体检。

---

## 快速开始

### 1. 下载 Release 预编译包、Docker 构建或源码构建

从 [GitHub Releases](https://github.com/SamuelSupe/dataproxy/releases) 下载对应平台预编译包，或本地构建：

```bash
# 本地源码构建
make build

# 生成本地开发测试用自签 CA / Hub 证书
make certs

# 或构建多阶段最小化 Docker 镜像
docker build --target hub -t dataproxy-hub:v0.2.0 .
docker build --target agent -t dataproxy-agent:v0.2.0 .
```

生产环境 `systemd` 服务模板已提供在 [deploy/systemd/dataproxy-hub.service](./deploy/systemd/dataproxy-hub.service) 与 [deploy/systemd/dataproxy-agent.service](./deploy/systemd/dataproxy-agent.service)。

### 2. 启动中心端 `dataproxy-hub`

```bash
./bin/dataproxy-hub -config configs/hub.example.yaml
```

部署 3+ 节点高可用 Hub 集群时，在 [configs/hub.example.yaml](./configs/hub.example.yaml) 中配置 `store_mysql_dsn`（以及 `mesh_listen_addr` / `mesh_peers`）即可。

### 3. 生成一次性挂载码并在租户主机挂载设备（推荐）

```bash
# 在任意 Hub 节点签发 15 分钟一次性挂载码
curl -X POST http://127.0.0.1:9090/api/v1/enrollments \
  -H "Authorization: Bearer dpx_admin_change_me" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"tenant-acme","device_name":"dc-node-01","ttl_seconds":900}'

# 租户主机执行挂载（本机生成私钥并换取短期设备证书）
./bin/dataproxy-agent enroll \
  -hub https://127.0.0.1:8443 \
  -code enroll_xxx \
  -state-dir ./device-state \
  -ca ./certs/ca.crt
```

### 4. 启动前一键全链路体检与运行 `dataproxy-agent`

```bash
./bin/dataproxy-agent doctor -config configs/agent.example.yaml
./bin/dataproxy-agent -config configs/agent.example.yaml
```

---

## 中心侧访问示例

### 1. 签发短效单任务票据并通过单端口直连数据库

```bash
# 签发绑定单个 (tenant_id, service_name) 的短效票据（附带审计事由）
curl -X POST http://127.0.0.1:9090/api/v1/tickets \
  -H "Authorization: Bearer dpx_admin_change_me" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-acme",
    "service_name": "pg-analytics",
    "ttl_seconds": 300,
    "purpose": {"job_type": "daily_sync", "job_id": "sync_001"}
  }'

# PostgreSQL 单端口直连（零改造）
psql "postgresql://tenant-acme.pg-analytics:<JWT>@127.0.0.1:15432/demo?sslmode=disable"

# MySQL 单端口直连（支持跨节点无状态验票）
mysql --ssl-mode=DISABLED -h 127.0.0.1 -P 13306 -u "<mysql_user>" -p"<mysql_password>"

# MongoDB 单端口直连（SASL PLAIN）
mongosh "mongodb://tenant-acme.mongo-catalog:<JWT>@127.0.0.1:17017/demo?authMechanism=PLAIN&authSource=%24external&directConnection=true"

# Redis 单端口直连
redis-cli -h 127.0.0.1 -p 16379 -a "<JWT>" GET order:1001
```

### 2. HTTP 反向代理（支持短效票据与 W3C `traceparent` 透传）

```bash
curl http://127.0.0.1:8080/v1/orders \
  -H "X-Dataproxy-Ticket: <JWT>" \
  -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
```

### 3. 单端口 `SOCKS5` / `HTTP CONNECT` 虚拟域名寻址

```bash
curl -x socks5h://data-sync-platform:dpx_caller_platform_secret@127.0.0.1:1080 \
  http://internal-erp.tenant-acme.dataproxy.internal:8000/api/health
```

### 4. 控制面观测与 Prometheus 指标

```bash
curl -H "Authorization: Bearer dpx_admin_change_me" http://127.0.0.1:9090/api/v1/tenants
curl http://127.0.0.1:9090/metrics
```

---

## 测试与验证

```bash
# 静态检查与全量竞态测试
make vet
make test

# 启动本地 OrbStack / Docker 4 个真实强制 TLS/SSL 数据库容器进行全链路端到端实测
make test-orbstack

# 可选：针对真实 MySQL 实例运行 3 节点 Hub 集群实时同步与吊销 E2E 测试
DATAPROXY_TEST_MYSQL_DSN="dataproxy:pass@tcp(127.0.0.1:3306)/dataproxy?parseTime=true" \
  go test -v -race -count=1 ./test/e2e -run TestCluster_SharedMySQLStore_3Node
```

## License

[MIT](./LICENSE)
