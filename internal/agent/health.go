package agent

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dataproxy/internal/agent/guard"
	"dataproxy/pkg/protocol"
)

const maxHealthProbeWorkers = 8

// ProbeServicesSanitized runs lightweight non-intrusive probes concurrently (bounded to 8 workers)
// against every whitelisted local service and returns sanitized health statuses in deterministic
// config order suitable for sending to the Hub.
// Crucially, internal target IP addresses and ports are NEVER included in the output.
func ProbeServicesSanitized(services []ServiceConfig) []protocol.ServiceHealthStatus {
	n := len(services)
	if n == 0 {
		return nil
	}
	out := make([]protocol.ServiceHealthStatus, n)
	nowUnix := time.Now().UTC().Unix()

	if n == 1 {
		out[0] = probeOneServiceSanitized(services[0], nowUnix)
		return out
	}

	sem := make(chan struct{}, maxHealthProbeWorkers)
	var wg sync.WaitGroup
	for i := range services {
		wg.Add(1)
		go func(idx int, svc ServiceConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[idx] = probeOneServiceSanitized(svc, nowUnix)
		}(i, services[i])
	}
	wg.Wait()
	return out
}

func probeOneServiceSanitized(svc ServiceConfig, nowUnix int64) protocol.ServiceHealthStatus {
	st := protocol.ServiceHealthStatus{
		Name:          svc.Name,
		Protocol:      svc.Protocol,
		CheckedAtUnix: nowUnix,
	}
	g := svc.EffectiveGuard()
		tlsCfg := svc.targetTLSConfig
		if tlsCfg == nil && svc.TargetTLS != nil && svc.TargetTLS.Enabled {
			tlsCfg, _ = svc.TargetTLS.BuildTLSConfig(svc.TargetAddr)
		}

		if svc.Protocol == protocol.ProtocolTCP {
			switch detectTCPProbeKind(svc, g) {
			case "mysql":
				info, err := guard.ProbeMySQLGreetingTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("MySQL", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					st.ServerVersion = info.ServerVersion
					tlsNote := ""
					if info.TLSHandshakeOK {
						tlsNote = ", TLS已验证"
					}
					st.Message = fmt.Sprintf("正常 (MySQL %s, %s%s)", info.ServerVersion, info.AuthPlugin, tlsNote)
				}

			case "postgres":
				info, err := guard.ProbePostgresTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("PostgreSQL", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					st.ServerVersion = "PostgreSQL v3"
					tlsNote := fmt.Sprintf("SSL=%v", info.SupportsSSL)
					if info.TLSHandshakeOK {
						tlsNote = "TLS已验证"
					}
					st.Message = fmt.Sprintf("正常 (PostgreSQL v3, %s)", tlsNote)
				}

			case "mongodb":
				info, err := guard.ProbeMongoDBTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("MongoDB", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					role := "Primary/Standalone"
					if info.IsSecondary {
						role = "Secondary"
					}
					st.ServerVersion = fmt.Sprintf("wire-v%d", info.MaxWireVersion)
					tlsNote := ""
					if tlsCfg != nil {
						tlsNote = ", TLS已验证"
					}
					st.Message = fmt.Sprintf("正常 (MongoDB %s, wire v%d%s)", role, info.MaxWireVersion, tlsNote)
				}

			case "redis":
				info, err := guard.ProbeRedisTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("Redis", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					st.ServerVersion = "RESP"
					tlsNote := ""
					if tlsCfg != nil {
						tlsNote = ", TLS已验证"
					}
					st.Message = fmt.Sprintf("正常 (Redis, 需认证=%v%s)", info.AuthRequired, tlsNote)
				}

			case "mssql":
				info, err := guard.ProbeMSSQLTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("SQL Server", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					st.ServerVersion = info.ServerVersion
					st.Message = fmt.Sprintf("正常 (SQL Server TDS %s)", info.ServerVersion)
				}

			case "oracle":
				info, err := guard.ProbeOracleTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("Oracle", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					st.ServerVersion = fmt.Sprintf("TNS-v%d", info.TNSVersion)
					st.Message = fmt.Sprintf("正常 (Oracle TNS v%d)", info.TNSVersion)
				}

			case "clickhouse":
				info, err := guard.ProbeClickHouseTLS(svc.TargetAddr, 2*time.Second, tlsCfg)
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("ClickHouse", err)
				} else {
					st.Healthy = true
					st.LatencyMs = info.Latency.Milliseconds()
					st.ServerVersion = info.Interface
					st.Message = fmt.Sprintf("正常 (ClickHouse %s, %s)", info.Interface, info.Detail)
				}

			default:
				start := time.Now()
				var c net.Conn
				var err error
				if tlsCfg != nil {
					c, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", svc.TargetAddr, tlsCfg.Clone())
				} else {
					c, err = net.DialTimeout("tcp", svc.TargetAddr, 2*time.Second)
				}
				if err != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError("TCP", err)
				} else {
					_ = c.Close()
					st.Healthy = true
					st.LatencyMs = time.Since(start).Milliseconds()
					if tlsCfg != nil {
						st.Message = "正常 (TLS 端口握手成功)"
					} else {
						st.Message = "正常 (TCP 端口可达)"
					}
				}
			}
		} else {
			start := time.Now()
			scheme := "http"
			tr := &http.Transport{DisableKeepAlives: true}
			if tlsCfg != nil {
				scheme = "https"
				tr.TLSClientConfig = tlsCfg.Clone()
			}
			httpCli := &http.Client{Timeout: 2 * time.Second, Transport: tr}
			resp, err := httpCli.Head(scheme + "://" + svc.TargetAddr + "/")
			tr.CloseIdleConnections()
			if err != nil {
				// Fallback to TCP/TLS reachability if HEAD / is rejected.
				var c net.Conn
				var dialErr error
				if tlsCfg != nil {
					c, dialErr = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", svc.TargetAddr, tlsCfg.Clone())
				} else {
					c, dialErr = net.DialTimeout("tcp", svc.TargetAddr, 2*time.Second)
				}
				if dialErr != nil {
					st.Healthy = false
					st.Message = sanitizeProbeError(strings.ToUpper(scheme), dialErr)
				} else {
					_ = c.Close()
					st.Healthy = true
					st.LatencyMs = time.Since(start).Milliseconds()
					st.Message = fmt.Sprintf("正常 (%s 连通，HEAD / 未开启)", strings.ToUpper(scheme))
				}
			} else {
				_ = resp.Body.Close()
				st.Healthy = true
				st.LatencyMs = time.Since(start).Milliseconds()
				st.Message = fmt.Sprintf("正常 (%s %d)", strings.ToUpper(scheme), resp.StatusCode)
			}
		}
	return st
}

// sanitizeProbeError converts low-level Go dial/protocol errors into actionable Chinese
// diagnostics while stripping internal IP addresses and port numbers.
func sanitizeProbeError(kind string, err error) string {
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "connection refused"):
		return fmt.Sprintf("异常（本地 %s 服务拒绝连接，请检查目标服务是否运行及监听配置）", kind)
	case strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "deadline exceeded"):
		return fmt.Sprintf("异常（连接本地 %s 服务超时，请检查客户内网防火墙或安全组）", kind)
	case strings.Contains(lower, "not allowed to connect"):
		return fmt.Sprintf("异常（%s 拒绝当前 Agent 主机接入，请检查数据库 Host 访问授权）", kind)
	case strings.Contains(lower, "x509:") || strings.Contains(lower, "tls:") || strings.Contains(lower, "unknown authority") || strings.Contains(lower, "certificate"):
		return fmt.Sprintf("异常（本地 %s TLS 证书校验失败，请检查 target_tls.ca_file 与 server_name）", kind)
	case strings.Contains(lower, "no such host"):
		return fmt.Sprintf("异常（本地 %s 目标域名无法解析，请检查客户内网 DNS）", kind)
	default:
		return fmt.Sprintf("异常（本地 %s 协议探活失败，请在客户端运行 dataproxy-agent doctor 查看详情）", kind)
	}
}
