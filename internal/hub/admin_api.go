package hub

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dataproxy/internal/auth"
)

var metricsBufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

// AdminAPI provides runtime management and observability endpoints for dataproxy-hub.
type AdminAPI struct {
	token      string
	tenantAuth *auth.TenantAuthenticator
	tickets    *auth.TicketManager
	devices    *auth.DeviceManager
	registry   *Registry
	portMapper *PortMapper
	metrics    *Metrics
	mux        *http.ServeMux
}

// NewAdminAPI constructs the control plane HTTP handler.
func NewAdminAPI(
	adminToken string,
	tenantAuth *auth.TenantAuthenticator,
	tickets *auth.TicketManager,
	devices *auth.DeviceManager,
	registry *Registry,
	portMapper *PortMapper,
) *AdminAPI {
	api := &AdminAPI{
		token:      strings.TrimSpace(adminToken),
		tenantAuth: tenantAuth,
		tickets:    tickets,
		devices:    devices,
		registry:   registry,
		portMapper: portMapper,
		mux:        http.NewServeMux(),
	}

	api.mux.HandleFunc("GET /healthz", api.handleHealthz)
	api.mux.HandleFunc("GET /metrics", api.handleMetrics)
	api.mux.HandleFunc("GET /api/v1/tenants", api.requireAuth(api.handleListTenants))
	api.mux.HandleFunc("POST /api/v1/tenants", api.requireAuth(api.handleUpsertTenant))
	api.mux.HandleFunc("DELETE /api/v1/tenants/{tenant_id}", api.requireAuth(api.handleDeleteTenant))
	api.mux.HandleFunc("POST /api/v1/tickets", api.requireAuth(api.handleIssueTicket))
	api.mux.HandleFunc("POST /api/v1/enrollments", api.requireAuth(api.handleCreateEnrollment))
	api.mux.HandleFunc("GET /api/v1/devices", api.requireAuth(api.handleListDevices))
	api.mux.HandleFunc("POST /api/v1/devices/{device_id}/revoke", api.requireAuth(api.handleRevokeDevice))
	api.mux.HandleFunc("GET /api/v1/bindings/tcp", api.requireAuth(api.handleListBindings))
	api.mux.HandleFunc("POST /api/v1/bindings/tcp", api.requireAuth(api.handleCreateBinding))
	api.mux.HandleFunc("DELETE /api/v1/bindings/tcp/{id}", api.requireAuth(api.handleDeleteBinding))
	return api
}

// SetMetrics attaches Prometheus histograms and operational counters to the Admin API.
func (a *AdminAPI) SetMetrics(m *Metrics) {
	a.metrics = m
}

// ServeHTTP dispatches control plane requests.
func (a *AdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *AdminAPI) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.token != "" {
			got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (a *AdminAPI) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *AdminAPI) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	buf := metricsBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= 256*1024 {
			buf.Reset()
			metricsBufPool.Put(buf)
		}
	}()

	snaps := a.registry.Snapshot()
	bindings := a.portMapper.List()

	fmt.Fprintf(buf, "# HELP dataproxy_online_tenants Number of tenants with at least one connected agent.\n")
	fmt.Fprintf(buf, "# TYPE dataproxy_online_tenants gauge\n")
	fmt.Fprintf(buf, "dataproxy_online_tenants %d\n", len(snaps))

	fmt.Fprintf(buf, "# HELP dataproxy_rejected_streams_total Total streams rejected by tenant agents.\n")
	fmt.Fprintf(buf, "# TYPE dataproxy_rejected_streams_total counter\n")
	fmt.Fprintf(buf, "dataproxy_rejected_streams_total %d\n", a.registry.RejectedStreams())

	fmt.Fprintf(buf, "# HELP dataproxy_tcp_bindings Active TCP port bindings on the hub.\n")
	fmt.Fprintf(buf, "# TYPE dataproxy_tcp_bindings gauge\n")
	fmt.Fprintf(buf, "dataproxy_tcp_bindings %d\n", len(bindings))

	transportCounts := make(map[string]int, 4)
	fmt.Fprintf(buf, "# HELP dataproxy_tenant_active_streams Currently active streams per tenant.\n")
	fmt.Fprintf(buf, "# TYPE dataproxy_tenant_active_streams gauge\n")
	for _, ts := range snaps {
		var active, inBytes, outBytes int64
		for _, s := range ts.Sessions {
			active += s.ActiveStreams
			inBytes += s.BytesIn
			outBytes += s.BytesOut
			transportCounts[s.Transport]++
		}
		fmt.Fprintf(buf, "dataproxy_tenant_active_streams{tenant_id=%q} %d\n", ts.TenantID, active)
		fmt.Fprintf(buf, "dataproxy_tenant_bytes_in_total{tenant_id=%q} %d\n", ts.TenantID, inBytes)
		fmt.Fprintf(buf, "dataproxy_tenant_bytes_out_total{tenant_id=%q} %d\n", ts.TenantID, outBytes)
		for _, s := range ts.Sessions {
			for _, h := range s.ServiceHealth {
				val := 0
				if h.Healthy {
					val = 1
				}
				fmt.Fprintf(buf, "dataproxy_tenant_service_healthy{tenant_id=%q,agent_id=%q,service=%q} %d\n",
					ts.TenantID, s.AgentID, h.Name, val)
			}
		}
	}

	if len(transportCounts) > 0 {
		tNames := make([]string, 0, len(transportCounts))
		for k := range transportCounts {
			tNames = append(tNames, k)
		}
		sort.Strings(tNames)
		fmt.Fprintf(buf, "# HELP dataproxy_sessions_by_transport Connected agent sessions grouped by transport protocol (wss/quic/tls).\n")
		fmt.Fprintf(buf, "# TYPE dataproxy_sessions_by_transport gauge\n")
		for _, tr := range tNames {
			fmt.Fprintf(buf, "dataproxy_sessions_by_transport{transport=%q} %d\n", tr, transportCounts[tr])
		}
	}

	if a.metrics != nil {
		fmt.Fprintf(buf, "# HELP dataproxy_mesh_forwarded_streams_total Total streams forwarded across Hub cluster mesh peers.\n")
		fmt.Fprintf(buf, "# TYPE dataproxy_mesh_forwarded_streams_total counter\n")
		fmt.Fprintf(buf, "dataproxy_mesh_forwarded_streams_total %d\n", a.metrics.MeshForwardedStreams.Load())

		fmt.Fprintf(buf, "# HELP dataproxy_quota_rejected_streams_total Total streams rejected by Hub per-tenant concurrency quota.\n")
		fmt.Fprintf(buf, "# TYPE dataproxy_quota_rejected_streams_total counter\n")
		fmt.Fprintf(buf, "dataproxy_quota_rejected_streams_total %d\n", a.metrics.QuotaRejectedStreams.Load())

		fmt.Fprintf(buf, "# HELP dataproxy_rate_limited_handshakes_total Total tunnel handshake/enroll requests rejected by per-IP rate limiter.\n")
		fmt.Fprintf(buf, "# TYPE dataproxy_rate_limited_handshakes_total counter\n")
		fmt.Fprintf(buf, "dataproxy_rate_limited_handshakes_total %d\n", a.metrics.RateLimitedHandshakes.Load())

		a.metrics.StreamOpenDuration.WritePrometheus(buf, "dataproxy_stream_open_duration_seconds", "End-to-end latency to open a stream to a tenant agent.")
		a.metrics.TunnelRTT.WritePrometheus(buf, "dataproxy_tunnel_rtt_seconds", "Measured tunnel heartbeat round-trip time (Yamux ping / QUIC RFC 9002 SmoothedRTT).")
	}

	if a.devices != nil {
		devs := a.devices.ListDevices()
		if len(devs) > 0 {
			now := time.Now().UTC()
			fmt.Fprintf(buf, "# HELP dataproxy_device_cert_expiry_seconds Seconds remaining until enrolled device certificate expires.\n")
			fmt.Fprintf(buf, "# TYPE dataproxy_device_cert_expiry_seconds gauge\n")
			for _, d := range devs {
				if d.Revoked {
					continue
				}
				rem := d.CertExpiresAt.Sub(now).Seconds()
				fmt.Fprintf(buf, "dataproxy_device_cert_expiry_seconds{tenant_id=%q,device_id=%q} %.0f\n",
					d.TenantID, d.DeviceID, rem)
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	_, _ = w.Write(buf.Bytes())
}

func (a *AdminAPI) handleListTenants(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"configured_tenants": a.tenantAuth.ListTenantIDs(),
		"online_tenants":     a.registry.Snapshot(),
	})
}

type upsertTenantReq struct {
	TenantID    string `json:"tenant_id"`
	Token       string `json:"token"`
	Disabled    bool   `json:"disabled"`
	RequireMTLS bool   `json:"require_mtls"`
}

const maxAdminBodyBytes = 1 << 20 // 1 MiB cap for admin JSON control-plane requests

func decodeLimitedJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

func (a *AdminAPI) handleUpsertTenant(w http.ResponseWriter, r *http.Request) {
	var req upsertTenantReq
	if err := decodeLimitedJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized json body"})
		return
	}
	err := a.tenantAuth.Upsert(auth.TenantRecord{
		TenantID:   req.TenantID,
		TokenHash:  req.Token,
		Disabled:   req.Disabled,
		RequireTLS: req.RequireMTLS,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Disabled {
		a.registry.CloseTenantSessions(req.TenantID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "tenant_id": req.TenantID})
}

func (a *AdminAPI) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	tid := r.PathValue("tenant_id")
	existed := a.tenantAuth.Delete(tid)
	closed := a.registry.CloseTenantSessions(tid)
	if !existed && closed == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "deleted",
		"tenant_id":       tid,
		"closed_sessions": closed,
	})
}

func (a *AdminAPI) handleListBindings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"bindings": a.portMapper.List(),
	})
}

type createBindingReq struct {
	ID           string   `json:"id"`
	ListenAddr   string   `json:"listen_addr"`
	TenantID     string   `json:"tenant_id"`
	ServiceName  string   `json:"service_name"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
	TTLSeconds   int      `json:"ttl_seconds"`
}

func (a *AdminAPI) handleCreateBinding(w http.ResponseWriter, r *http.Request) {
	var req createBindingReq
	if err := decodeLimitedJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized json body"})
		return
	}
	info, err := a.portMapper.Add(TCPBindingSpec{
		ID:           req.ID,
		ListenAddr:   req.ListenAddr,
		TenantID:     req.TenantID,
		ServiceName:  req.ServiceName,
		AllowedCIDRs: req.AllowedCIDRs,
		TTL:          time.Duration(req.TTLSeconds) * time.Second,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *AdminAPI) handleDeleteBinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !a.portMapper.Remove(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "binding not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

type issueTicketReq struct {
	TenantID    string            `json:"tenant_id"`
	ServiceName string            `json:"service_name"`
	TTLSeconds  int               `json:"ttl_seconds"`
	Purpose     map[string]string `json:"purpose"`
}

func (a *AdminAPI) handleIssueTicket(w http.ResponseWriter, r *http.Request) {
	if a.tickets == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ticket manager not enabled"})
		return
	}
	var req issueTicketReq
	if err := decodeLimitedJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized json body"})
		return
	}
	issued, err := a.tickets.Issue(req.TenantID, req.ServiceName, time.Duration(req.TTLSeconds)*time.Second, req.Purpose)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, issued)
}

type createEnrollmentReq struct {
	TenantID   string `json:"tenant_id"`
	DeviceName string `json:"device_name"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func (a *AdminAPI) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	if a.devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device manager not enabled"})
		return
	}
	var req createEnrollmentReq
	if err := decodeLimitedJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized json body"})
		return
	}
	info, err := a.devices.CreateEnrollment(req.TenantID, req.DeviceName, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (a *AdminAPI) handleListDevices(w http.ResponseWriter, _ *http.Request) {
	if a.devices == nil {
		writeJSON(w, http.StatusOK, map[string]any{"devices": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": a.devices.ListDevices()})
}

func (a *AdminAPI) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if a.devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device manager not enabled"})
		return
	}
	deviceID := r.PathValue("device_id")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeLimitedJSON(w, r, &req)
	rec, err := a.devices.RevokeDevice(deviceID, req.Reason)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	closed := a.registry.CloseDeviceSessions(deviceID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "revoked",
		"device":          rec,
		"closed_sessions": closed,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
