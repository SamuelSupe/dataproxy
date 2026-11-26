package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"dataproxy/internal/agent/guard"
	"dataproxy/internal/transport"
	"dataproxy/pkg/protocol"

	"github.com/hashicorp/yamux"
)

// CheckStatus represents the outcome of a single diagnostic item.
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusWarn CheckStatus = "WARN"
	StatusFail CheckStatus = "FAIL"
)

// CheckResult holds the detailed result and actionable Chinese remediation advice.
type CheckResult struct {
	Name    string
	Status  CheckStatus
	Detail  string
	Advice  string
	Latency time.Duration
}

// DoctorReport aggregates all preflight diagnostic checks for dataproxy-agent.
type DoctorReport struct {
	Checks []CheckResult
}

// AllPassed reports whether there are zero failed checks.
func (r *DoctorReport) AllPassed() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

// Format writes a human-readable Chinese diagnostic report to w.
func (r *DoctorReport) Format(w io.Writer) {
	fmt.Fprintln(w, "================ dataproxy-agent 全链路体检报告 ================")
	passCnt, warnCnt, failCnt := 0, 0, 0
	for i, c := range r.Checks {
		switch c.Status {
		case StatusPass:
			passCnt++
		case StatusWarn:
			warnCnt++
		case StatusFail:
			failCnt++
		}
		lat := ""
		if c.Latency > 0 {
			lat = fmt.Sprintf(" (%s)", c.Latency.Round(time.Millisecond))
		}
		fmt.Fprintf(w, "[%d] [%s] %s%s\n", i+1, c.Status, c.Name, lat)
		fmt.Fprintf(w, "    详情: %s\n", c.Detail)
		if c.Advice != "" {
			fmt.Fprintf(w, "    建议: %s\n", c.Advice)
		}
	}
	fmt.Fprintln(w, "----------------------------------------------------------------")
	fmt.Fprintf(w, "汇总: 通过 %d 项 | 警告 %d 项 | 失败 %d 项\n", passCnt, warnCnt, failCnt)
	fmt.Fprintln(w, "================================================================")
}

// RunDoctor executes a fast end-to-end preflight check covering:
// 1. Config & security policy summary
// 2. Local credential sources (env:/file:) preflight
// 3. Proxy / outbound network / TLS trust / Hub registration handshake
// 4. Every whitelisted local service (TCP reachability + MySQL v10 greeting / HTTP probe)
func RunDoctor(ctx context.Context, cfg *Config) *DoctorReport {
	report := &DoctorReport{}

	// 1. Configuration & policy validation.
	if err := cfg.NormalizeAndValidate(); err != nil {
		report.Checks = append(report.Checks, CheckResult{
			Name:   "配置文件与安全策略校验",
			Status: StatusFail,
			Detail: err.Error(),
			Advice: "请检查 agent.yaml 中的 tenant_id、token、server.url 及 services 列表格式。",
		})
		return report
	}

	bwDesc := "不限速"
	if cfg.MaxBandwidth != "" {
		bwDesc = cfg.MaxBandwidth
	}
	report.Checks = append(report.Checks, CheckResult{
		Name:   "配置文件与安全策略校验",
		Status: StatusPass,
		Detail: fmt.Sprintf("租户=%s, 节点=%s, 模式=%s, 白名单服务数=%d, 全局带宽上限=%s",
			cfg.TenantID, cfg.AgentID, cfg.Server.Mode, len(cfg.Services), bwDesc),
	})

	// 2. Proxy environment & local credential sources check.
	report.Checks = append(report.Checks, checkProxyConfig(cfg))
	for i := range cfg.Services {
		svc := &cfg.Services[i]
		if g := svc.EffectiveGuard(); g != nil && g.CredentialInjection != nil && g.CredentialInjection.Enabled {
			report.Checks = append(report.Checks, checkLocalCredentials(*svc, g))
		}
	}

	// 3. Outbound tunnel dial + TLS trust + Hub registration handshake.
	report.Checks = append(report.Checks, checkHubTunnelHandshake(ctx, cfg))

	// 4. Local whitelisted service connectivity & protocol probing (bounded parallel, deterministic order).
	if len(cfg.Services) == 1 {
		report.Checks = append(report.Checks, checkLocalService(cfg.Services[0]))
	} else if len(cfg.Services) > 1 {
		svcChecks := make([]CheckResult, len(cfg.Services))
		sem := make(chan struct{}, maxHealthProbeWorkers)
		var wg sync.WaitGroup
		for i, svc := range cfg.Services {
			wg.Add(1)
			go func(idx int, s ServiceConfig) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				svcChecks[idx] = checkLocalService(s)
			}(i, svc)
		}
		wg.Wait()
		report.Checks = append(report.Checks, svcChecks...)
	}

	return report
}

func checkProxyConfig(cfg *Config) CheckResult {
	proxyStr := cfg.Server.ProxyURL
	source := "配置文件 server.proxy_url"
	if proxyStr == "" {
		for _, envKey := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := os.Getenv(envKey); v != "" {
				proxyStr = v
				source = "环境变量 " + envKey
				break
			}
		}
	}
	if proxyStr == "" {
		return CheckResult{
			Name:   "企业正向代理环境检测",
			Status: StatusPass,
			Detail: "未配置出向正向代理，将直接发起出向连接",
		}
	}
	u, err := url.Parse(proxyStr)
	if err != nil || u.Host == "" {
		return CheckResult{
			Name:   "企业正向代理环境检测",
			Status: StatusFail,
			Detail: fmt.Sprintf("检测到 %s=%q，但代理 URL 格式非法", source, proxyStr),
			Advice: "请确认代理格式为 http://host:port 或 http://user:pass@host:port。",
		}
	}
	start := time.Now()
	c, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		return CheckResult{
			Name:    "企业正向代理环境检测",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("无法连接正向代理 %s (%s): %v", u.Host, source, err),
			Advice:  "请确认企业正向代理地址、端口是否正确以及当前主机是否被允许访问该代理。",
			Latency: time.Since(start),
		}
	}
	_ = c.Close()
	return CheckResult{
		Name:    "企业正向代理环境检测",
		Status:  StatusPass,
		Detail:  fmt.Sprintf("正向代理 %s (%s) TCP 连通正常", u.Host, source),
		Latency: time.Since(start),
	}
}

func checkLocalCredentials(svc ServiceConfig, g *ProtocolGuardConfig) CheckResult {
	inj := g.CredentialInjection
	user, errU := guard.ResolveSecret(inj.Username)
	pass, errP := guard.ResolveSecret(inj.Password)
	if errU != nil || errP != nil {
		errMsg := ""
		if errU != nil {
			errMsg += "username: " + errU.Error() + "; "
		}
		if errP != nil {
			errMsg += "password: " + errP.Error()
		}
		return CheckResult{
			Name:   fmt.Sprintf("本地凭据代填源预检 [%s (%s)]", svc.Name, g.Type),
			Status: StatusFail,
			Detail: errMsg,
			Advice: "请检查对应的环境变量是否已导出，或 file:/path 密钥文件是否存在且当前用户具备读权限（如 Vault Agent / K8s Secret 挂载路径）。",
		}
	}
	passState := "已加载(非空)"
	if pass == "" {
		passState = "为空密码"
	}
	return CheckResult{
		Name:   fmt.Sprintf("本地凭据代填源预检 [%s (%s)]", svc.Name, g.Type),
		Status: StatusPass,
		Detail: fmt.Sprintf("已从本地安全读取 %s 用户名 %q 与密码（%s），中心端不可见", g.Type, user, passState),
	}
}

func checkHubTunnelHandshake(ctx context.Context, cfg *Config) CheckResult {
	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := transport.DialTunnel(dialCtx, transport.DialConfig{
		Mode:        cfg.Server.Mode,
		URL:         cfg.Server.URL,
		ProxyURL:    cfg.Server.ProxyURL,
		DialTimeout: 5 * time.Second,
		TLS:         cfg.Server.TLS,
	})
	if err != nil {
		advice := "请检查中心 Hub 地址是否可达、防火墙是否放行 443/目标出向端口；若企业内网需走代理，请配置 server.proxy_url。"
		var unknownAuth x509.UnknownAuthorityError
		if errors.As(err, &unknownAuth) || strings.Contains(err.Error(), "unknown authority") || strings.Contains(err.Error(), "x509:") {
			advice = "检测到 TLS 证书校验失败：可能是自签 CA 未信任，或企业出口防火墙启用了 HTTPS 中间人解密代理。请将中心 CA 或企业根证书配置到 server.tls.ca_file。"
		}
		return CheckResult{
			Name:    "中心隧道出向连通与 TLS 证书校验",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("连接 %s (%s) 失败: %v", cfg.Server.URL, cfg.Server.Mode, err),
			Advice:  advice,
			Latency: time.Since(start),
		}
	}
	defer func() { _ = conn.Close() }()

	mux, err := yamux.Client(conn, transport.DefaultYamuxConfig())
	if err != nil {
		return CheckResult{
			Name:    "中心隧道出向连通与注册握手",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("Yamux 初始化失败: %v", err),
			Advice:  "请确认链路中间的七层网关（如 Nginx/ALB）已正确开启 WebSocket Upgrade 转发。",
			Latency: time.Since(start),
		}
	}
	defer func() { _ = mux.Close() }()

	ctrl, err := mux.OpenStream()
	if err != nil {
		return CheckResult{
			Name:    "中心隧道出向连通与注册握手",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("打开控制流失败: %v", err),
			Latency: time.Since(start),
		}
	}
	defer func() { _ = ctrl.Close() }()

	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteFrame(ctrl, protocol.FrameRegisterReq, protocol.RegisterRequest{
		Version:  protocol.CurrentVersion,
		TenantID: cfg.TenantID,
		AgentID:  cfg.AgentID + "-doctor",
		DeviceID: cfg.DeviceID,
		Token:    cfg.Token,
		Services: cfg.Announcements(),
	}); err != nil {
		return CheckResult{
			Name:    "中心隧道出向连通与注册握手",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("发送注册帧失败: %v", err),
			Latency: time.Since(start),
		}
	}
	var resp protocol.RegisterResponse
	if err := protocol.ReadTypedFrame(ctrl, protocol.FrameRegisterResp, &resp); err != nil {
		return CheckResult{
			Name:    "中心隧道出向连通与注册握手",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("读取中心注册响应失败: %v", err),
			Latency: time.Since(start),
		}
	}
	if !resp.OK {
		return CheckResult{
			Name:    "中心隧道出向连通与注册握手",
			Status:  StatusFail,
			Detail:  fmt.Sprintf("中心端拒绝鉴权 [%s]: %s", resp.Code, resp.Message),
			Advice:  "请核对 agent.yaml 中的 tenant_id、token 是否与中心一致；若中心启用了 require_mtls，请确认客户端证书 CN 或 SPIFFE SAN 与 tenant_id 匹配。",
			Latency: time.Since(start),
		}
	}

	// Cleanly drain the temporary doctor session.
	_ = protocol.WriteFrame(ctrl, protocol.FrameDrain, protocol.DrainMessage{Reason: "doctor_check_complete"})
	return CheckResult{
		Name:    "中心隧道出向连通、TLS 校验与注册握手",
		Status:  StatusPass,
		Detail:  fmt.Sprintf("成功接入 %s (%s)，中心签发测试会话 %s，心跳间隔 %ds", cfg.Server.URL, cfg.Server.Mode, resp.SessionID, resp.HeartbeatIntervalSec),
		Latency: time.Since(start),
	}
}

func checkLocalService(svc ServiceConfig) CheckResult {
	name := fmt.Sprintf("本地白名单服务体检 [%s -> %s (%s)]", svc.Name, svc.TargetAddr, svc.Protocol)
	g := svc.EffectiveGuard()
	policyStr := formatGuardPolicies(svc, g)

	tlsCfg, tlsErr := svc.TargetTLS.BuildTLSConfig(svc.TargetAddr)
	if tlsErr != nil {
		return CheckResult{
			Name:   name,
			Status: StatusFail,
			Detail: fmt.Sprintf("target_tls 配置加载失败: %v", tlsErr),
			Advice: "请检查 target_tls.ca_file / cert_file / key_file 路径是否存在且 PEM 格式有效。",
		}
	}

	if svc.Protocol == protocol.ProtocolTCP {
		switch detectTCPProbeKind(svc, g) {
		case "mysql":
			info, err := guard.ProbeMySQLGreetingTLS(svc.TargetAddr, 3*time.Second, tlsCfg)
			if err != nil {
				advice := "请确认目标 MySQL 正在运行、端口正确，且未因 bind-address=127.0.0.1 导致跨机无法访问。"
				lowerErr := strings.ToLower(err.Error())
				if strings.Contains(lowerErr, "not allowed to connect") {
					advice = "MySQL 已连通但拒绝了当前 Agent 主机 IP！请在 MySQL 中授权该 Agent 所在内网 IP（例如 CREATE USER 'reader'@'10.0.%.%'）。"
				} else if strings.Contains(lowerErr, "tls") || strings.Contains(lowerErr, "x509") || strings.Contains(lowerErr, "ssl") {
					advice = "MySQL Split-TLS 握手失败！请检查 target_tls.ca_file（云 RDS 根证书）与 server_name 是否与数据库证书匹配，并确认 MySQL 已开启 SSL。"
				}
				return CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("MySQL 首包/TLS 握手探测失败: %v", err), Advice: advice}
			}
			tlsNote := fmt.Sprintf("SSL=%v", info.SupportsSSL)
			if info.TLSHandshakeOK {
				tlsNote = "Split-TLS握手成功"
			}
			return CheckResult{
				Name:    name,
				Status:  StatusPass,
				Detail:  fmt.Sprintf("MySQL v%d 首包识别成功: Server=%s, AuthPlugin=%s, %s%s", info.ProtocolVersion, info.ServerVersion, info.AuthPlugin, tlsNote, policyStr),
				Latency: info.Latency,
			}

		case "postgres":
			info, err := guard.ProbePostgresTLS(svc.TargetAddr, 3*time.Second, tlsCfg)
			if err != nil {
				advice := "请确认 PostgreSQL 已启动、listen_addresses 已监听内网网卡，且 pg_hba.conf 允许当前 Agent 主机接入。"
				lowerErr := strings.ToLower(err.Error())
				if strings.Contains(lowerErr, "tls") || strings.Contains(lowerErr, "x509") || strings.Contains(lowerErr, "ssl") {
					advice = "PostgreSQL Split-TLS 握手失败！请确认目标库已开启 ssl=on，并核对 target_tls.ca_file 与 server_name。"
				}
				return CheckResult{
					Name:   name,
					Status: StatusFail,
					Detail: fmt.Sprintf("PostgreSQL SSLRequest/TLS 协议探测失败: %v", err),
					Advice: advice,
				}
			}
			tlsNote := fmt.Sprintf("SSL支持=%v", info.SupportsSSL)
			if info.TLSHandshakeOK {
				tlsNote = "Split-TLS握手成功"
			}
			return CheckResult{
				Name:    name,
				Status:  StatusPass,
				Detail:  fmt.Sprintf("PostgreSQL v3 协议识别成功: %s%s", tlsNote, policyStr),
				Latency: info.Latency,
			}

		case "mongodb":
			info, err := guard.ProbeMongoDBTLS(svc.TargetAddr, 3*time.Second, tlsCfg)
			if err != nil {
				advice := "请确认 MongoDB 已启动且 net.bindIp 已允许当前 Agent 所在 IP 访问。"
				if tlsCfg != nil {
					advice = "MongoDB TLS 探测失败！请确认 MongoDB 已启用 TLS，并核对 target_tls.ca_file 与 server_name。"
				}
				return CheckResult{
					Name:   name,
					Status: StatusFail,
					Detail: fmt.Sprintf("MongoDB OP_MSG {hello:1} 探测失败: %v", err),
					Advice: advice,
				}
			}
			role := "Standalone/Primary"
			if info.IsSecondary {
				role = "Secondary"
			}
			rsNote := ""
			if info.SetName != "" {
				rsNote = fmt.Sprintf(", ReplicaSet=%s（中心直连请加 ?directConnection=true）", info.SetName)
			}
			tlsNote := ""
			if tlsCfg != nil {
				tlsNote = ", TLS握手成功"
			}
			return CheckResult{
				Name:    name,
				Status:  StatusPass,
				Detail:  fmt.Sprintf("MongoDB OP_MSG 识别成功: WireVersion=%d, Role=%s%s%s%s", info.MaxWireVersion, role, rsNote, tlsNote, policyStr),
				Latency: info.Latency,
			}

		case "redis":
			info, err := guard.ProbeRedisTLS(svc.TargetAddr, 3*time.Second, tlsCfg)
			if err != nil {
				advice := "请确认 Redis 已启动且未因 protected-mode/bind 127.0.0.1 拒绝连接。"
				if tlsCfg != nil {
					advice = "Redis TLS 探测失败！请确认 Redis 已开启 --tls-port，并核对 target_tls.ca_file / cert_file / server_name。"
				}
				return CheckResult{
					Name:   name,
					Status: StatusFail,
					Detail: fmt.Sprintf("Redis RESP PING 探测失败: %v", err),
					Advice: advice,
				}
			}
			tlsNote := ""
			if tlsCfg != nil {
				tlsNote = ", TLS握手成功"
			}
			return CheckResult{
				Name:    name,
				Status:  StatusPass,
				Detail:  fmt.Sprintf("Redis RESP 识别成功: 需密码认证=%v, 响应=%q%s%s", info.AuthRequired, info.Reply, tlsNote, policyStr),
				Latency: info.Latency,
			}
		}
	}

	// Generic TCP / HTTP (or HTTPS via target_tls) local reachability check.
	start := time.Now()
	var conn net.Conn
	var err error
	if tlsCfg != nil {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", svc.TargetAddr, tlsCfg.Clone())
	} else {
		conn, err = net.DialTimeout("tcp", svc.TargetAddr, 3*time.Second)
	}
	if err != nil {
		advice := "请检查目标内网服务是否已启动、本机防火墙/安全组是否放行 Agent 访问该端口。"
		if tlsCfg != nil {
			advice = "目标 TLS 握手失败，请检查 target_tls.ca_file 与 server_name 配置是否正确。"
		}
		return CheckResult{
			Name:    name,
			Status:  StatusFail,
			Detail:  fmt.Sprintf("本地建连失败: %v", err),
			Advice:  advice,
			Latency: time.Since(start),
		}
	}
	_ = conn.Close()

	if svc.Protocol == protocol.ProtocolHTTP {
		scheme := "http"
		httpCli := &http.Client{Timeout: 3 * time.Second}
		if tlsCfg != nil {
			scheme = "https"
			httpCli.Transport = &http.Transport{TLSClientConfig: tlsCfg.Clone()}
		}
		resp, err := httpCli.Head(scheme + "://" + svc.TargetAddr + "/")
		if err != nil {
			return CheckResult{
				Name:    name,
				Status:  StatusWarn,
				Detail:  fmt.Sprintf("%s 建连成功，但 HEAD / 探测返回异常: %v", strings.ToUpper(scheme), err),
				Advice:  "如果目标内部平台仅支持特定路径，请按实际接口路径验证。",
				Latency: time.Since(start),
			}
		}
		_ = resp.Body.Close()
		methodNote := "不限 HTTP 方法"
		if len(svc.AllowedHTTPMethods) > 0 {
			methodNote = "仅允许方法=" + strings.Join(svc.AllowedHTTPMethods, ",")
		}
		if tlsCfg != nil {
			methodNote += ", 目标Split-TLS=开启"
		}
		return CheckResult{
			Name:    name,
			Status:  StatusPass,
			Detail:  fmt.Sprintf("%s 目标存活 (HEAD / -> %d) | 策略: %s", strings.ToUpper(scheme), resp.StatusCode, methodNote),
			Latency: time.Since(start),
		}
	}

	okDetail := "本地 TCP 端口握手连通正常"
	if tlsCfg != nil {
		okDetail = "本地 TLS 端口握手连通正常"
	}
	return CheckResult{
		Name:    name,
		Status:  StatusPass,
		Detail:  okDetail + policyStr,
		Latency: time.Since(start),
	}
}

func formatGuardPolicies(svc ServiceConfig, g *ProtocolGuardConfig) string {
	var policies []string
	if svc.TargetTLS != nil && svc.TargetTLS.Enabled {
		policies = append(policies, "目标Split-TLS=开启")
	}
	if g != nil && g.ReadOnly {
		policies = append(policies, "本地只读拦截=开启")
	}
	if g != nil && g.CredentialInjection != nil && g.CredentialInjection.Enabled {
		policies = append(policies, "本地凭据代填=开启")
	}
	if svc.MaxBandwidth != "" {
		policies = append(policies, "带宽上限="+svc.MaxBandwidth)
	}
	if len(policies) == 0 {
		return ""
	}
	return " | 策略: " + strings.Join(policies, ", ")
}

func detectTCPProbeKind(svc ServiceConfig, g *ProtocolGuardConfig) string {
	if g != nil && g.Type != "" {
		return g.Type
	}
	lowerName := strings.ToLower(svc.Name)
	_, port, _ := net.SplitHostPort(svc.TargetAddr)
	switch {
	case strings.Contains(lowerName, "mysql") || port == "3306" || port == "3307":
		return "mysql"
	case strings.Contains(lowerName, "postgres") || strings.Contains(lowerName, "pg") || port == "5432":
		return "postgres"
	case strings.Contains(lowerName, "mongo") || port == "27017":
		return "mongodb"
	case strings.Contains(lowerName, "redis") || port == "6379":
		return "redis"
	default:
		return "tcp"
	}
}
