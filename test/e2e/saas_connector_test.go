package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/auth"
	"dataproxy/internal/hub"
	"dataproxy/internal/transport"
)

func TestSaaSConnector_Tickets_PurposeAudit_TimeWindow_HotReload(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := generateTestCerts(t)

	// Two tenant internal HTTP platforms: erp-v1 (initially exposed) and erp-v2 (added via hot-reload!).
	erpV1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(hub.HeaderTicket) != "" {
			http.Error(w, "leaked ticket header", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, "v1:%s", r.URL.Path)
	}))
	defer erpV1.Close()

	erpV2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "v2:%s", r.URL.Path)
	}))
	defer erpV2.Close()

	auditFile := filepath.Join(t.TempDir(), "tenant-audit.jsonl")

	hubCfg := &hub.Config{
		TunnelWSSAddr:    "127.0.0.1:0",
		HTTPAddr:         "127.0.0.1:0",
		AdminAddr:        "127.0.0.1:0",
		AdminToken:       "admin-secret",
		TicketSigningKey: "hub-ticket-hmac-key",
		TunnelTLS: transport.TLSOptions{
			CertFile: certs.ServerCertFile,
			KeyFile:  certs.ServerKeyFile,
		},
		Tenants: []auth.TenantRecord{
			{TenantID: "tenant-saas", TokenHash: "tok-saas"},
		},
	}
	srv, err := hub.NewServer(hubCfg, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("hub Start: %v", err)
	}
	defer srv.Close()

	// Write agent.yaml to temp file so we test REAL file-watch Hot Reload!
	agentCfgPath := filepath.Join(t.TempDir(), "agent.yaml")
	writeAgentYAML := func(allowedWindows string, includeV2 bool) {
		v2Block := ""
		if includeV2 {
			v2Block = fmt.Sprintf(`
  - name: "erp-v2"
    protocol: "http"
    target_addr: %q
`, strings.TrimPrefix(erpV2.URL, "http://"))
		}
		yamlStr := fmt.Sprintf(`tenant_id: "tenant-saas"
agent_id: "saas-node-01"
token: "tok-saas"
timezone: "UTC"
allowed_windows: %s
config_watch_interval: 100ms
audit:
  file: %q
server:
  mode: "wss"
  url: "wss://%s/tunnel/v1/connect"
  tls:
    ca_file: %q
    server_name: "localhost"
services:
  - name: "erp-v1"
    protocol: "http"
    target_addr: %q
    allowed_http_methods: ["GET"]
%s`, allowedWindows, auditFile, srv.WSSAddr(), certs.CAFile, strings.TrimPrefix(erpV1.URL, "http://"), v2Block)
		if err := os.WriteFile(agentCfgPath, []byte(yamlStr), 0600); err != nil {
			t.Fatalf("write agent.yaml: %v", err)
		}
	}

	// Pick a 1-minute window guaranteed to be OUTSIDE current UTC time (current hour + 3h).
	nowUTC := time.Now().UTC()
	closedStart := (nowUTC.Hour() + 3) % 24
	closedEnd := (closedStart + 1) % 24
	closedWindowYAML := fmt.Sprintf(`["%02d:00-%02d:00"]`, closedStart, closedEnd)

	// Start Agent initially restricted to a CLOSED time window, exposing only erp-v1.
	writeAgentYAML(closedWindowYAML, false)
	cfg, err := agent.LoadConfig(agentCfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cli, err := agent.NewClient(cfg, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	cli.SetConfigPath(agentCfgPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cli.Run(ctx) }()
	select {
	case <-cli.Ready():
	case <-time.After(5 * time.Second):
		t.Fatalf("agent failed to register")
	}

	httpCli := &http.Client{Timeout: 5 * time.Second}
	issueTicket := func(service string, purpose map[string]string) auth.IssuedTicket {
		payload, _ := json.Marshal(map[string]any{
			"tenant_id":    "tenant-saas",
			"service_name": service,
			"ttl_seconds":  300,
			"purpose":      purpose,
		})
		req, _ := http.NewRequest("POST", "http://"+srv.AdminAddr()+"/api/v1/tickets", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer admin-secret")
		resp, err := httpCli.Do(req)
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("issue ticket failed: err=%v resp=%v", err, resp)
		}
		defer func() { _ = resp.Body.Close() }()
		var tkt auth.IssuedTicket
		if err := json.NewDecoder(resp.Body).Decode(&tkt); err != nil {
			t.Fatalf("decode ticket: %v", err)
		}
		return tkt
	}

	// 1. Access OUTSIDE allowed_windows MUST be rejected with ERR_OUTSIDE_ACCESS_WINDOW while agent remains online!
	tktV1 := issueTicket("erp-v1", map[string]string{
		"job_type":     "daily_sync",
		"job_id":       "sync_9921",
		"triggered_by": "报表中心-定时任务",
	})
	reqBlocked, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/orders", nil)
	reqBlocked.Header.Set(hub.HeaderTicket, tktV1.JWT)
	respBlocked, err := httpCli.Do(reqBlocked)
	if err != nil {
		t.Fatalf("request during closed window error: %v", err)
	}
	blockedBody, _ := io.ReadAll(respBlocked.Body)
	_ = respBlocked.Body.Close()
	if respBlocked.StatusCode != http.StatusForbidden || !strings.Contains(string(blockedBody), "ERR_OUTSIDE_ACCESS_WINDOW") {
		t.Fatalf("expected 403 ERR_OUTSIDE_ACCESS_WINDOW, got status=%d body=%q", respBlocked.StatusCode, string(blockedBody))
	}

	// 2. Hot-reload agent.yaml on disk: open access window AND add brand-new service "erp-v2" without restarting Agent!
	writeAgentYAML("[]", true)

	// Wait briefly for the 100ms config watcher to hot-reload and push FrameServiceUpdate to Hub.
	deadline := time.Now().Add(3 * time.Second)
	var v2Ready bool
	for time.Now().Before(deadline) {
		snaps := srv.Registry().Snapshot()
		if len(snaps) == 1 && len(snaps[0].Sessions) == 1 && len(snaps[0].Sessions[0].Services) == 2 {
			v2Ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !v2Ready {
		t.Fatalf("hub did not receive FrameServiceUpdate after agent.yaml hot-reload")
	}

	// 3. Access erp-v1 and newly hot-reloaded erp-v2 using Job Tickets!
	reqV1, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/orders", nil)
	reqV1.Header.Set(hub.HeaderTicket, tktV1.JWT)
	respV1, err := httpCli.Do(reqV1)
	if err != nil {
		t.Fatalf("GET erp-v1 after hot-reload failed: %v", err)
	}
	b1, _ := io.ReadAll(respV1.Body)
	_ = respV1.Body.Close()
	if respV1.StatusCode != http.StatusOK || string(b1) != "v1:/orders" {
		t.Fatalf("unexpected erp-v1 response: status=%d body=%q", respV1.StatusCode, string(b1))
	}

	tktV2 := issueTicket("erp-v2", map[string]string{
		"job_type": "realtime_bi",
		"job_id":   "bi_771",
	})
	reqV2, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/metrics", nil)
	reqV2.Header.Set(hub.HeaderTicket, tktV2.JWT)
	respV2, err := httpCli.Do(reqV2)
	if err != nil {
		t.Fatalf("GET hot-reloaded erp-v2 failed: %v", err)
	}
	b2, _ := io.ReadAll(respV2.Body)
	_ = respV2.Body.Close()
	if respV2.StatusCode != http.StatusOK || string(b2) != "v2:/metrics" {
		t.Fatalf("unexpected erp-v2 response: status=%d body=%q", respV2.StatusCode, string(b2))
	}

	// 4. Verify tenant-local JSONL audit file recorded business Purpose ("sync_9921", "报表中心-定时任务"),
	//    window rejection, config_reloaded, and stream_opened/closed!
	auditBytes, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("read tenant audit JSONL: %v", err)
	}
	auditText := string(auditBytes)
	for _, want := range []string{
		`"ERR_OUTSIDE_ACCESS_WINDOW"`,
		`"config_reloaded"`,
		`"sync_9921"`,
		`"报表中心-定时任务"`,
		`"bi_771"`,
		`"erp-v2"`,
	} {
		if !strings.Contains(auditText, want) {
			t.Fatalf("tenant local audit file missing %s:\n%s", want, auditText)
		}
	}
}
