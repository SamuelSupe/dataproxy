package protocol

const (
	CurrentVersion = "v1"

	ProtocolTCP  = "tcp"
	ProtocolHTTP = "http"
)

// Error codes returned in RegisterResponse and StreamOpenResponse.
const (
	CodeAuthFailed       = "ERR_AUTH_FAILED"
	CodeDeviceRevoked    = "ERR_DEVICE_REVOKED"
	CodeForbiddenService = "ERR_FORBIDDEN_SERVICE"
	CodeProtocolMismatch = "ERR_PROTOCOL_MISMATCH"
	CodeRateLimited      = "ERR_RATE_LIMITED"
	CodeOutsideWindow    = "ERR_OUTSIDE_ACCESS_WINDOW"
	CodeDialFailed       = "ERR_DIAL_FAILED"
	CodeBadRequest       = "ERR_BAD_REQUEST"
)

// ServiceAnnouncement describes a logical service exposed by an agent.
// Notice that internal IP addresses / ports are intentionally omitted so
// tenant intranet topology is never leaked to the central hub.
type ServiceAnnouncement struct {
	Name        string `json:"name"`
	Protocol    string `json:"protocol"` // "tcp" or "http"
	Description string `json:"description,omitempty"`
}

// RegisterRequest is sent by the agent on Control Stream #1 immediately after yamux setup.
type RegisterRequest struct {
	Version  string                `json:"version"`
	TenantID string                `json:"tenant_id"`
	AgentID  string                `json:"agent_id"`
	DeviceID string                `json:"device_id,omitempty"`  // Bound to enrolled device certificate when using one-time enrollment
	PoolLane int                   `json:"pool_lane,omitempty"`  // Lane index when pool_size > 1 (0 = control+data, 1..N = parallel data lanes)
	Role     string                `json:"role,omitempty"`       // "all" (default), "control", or "data"
	Token    string                `json:"token"`
	Services []ServiceAnnouncement `json:"services"`
	Labels   map[string]string     `json:"labels,omitempty"`
}

// RegisterResponse is returned by the hub on Control Stream #1.
type RegisterResponse struct {
	OK                   bool   `json:"ok"`
	Code                 string `json:"code,omitempty"`
	Message              string `json:"message,omitempty"`
	SessionID            string `json:"session_id,omitempty"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec,omitempty"`
}

// PingMessage is sent periodically over the control stream to measure RTT and liveness.
type PingMessage struct {
	SentAtUnixNano int64 `json:"sent_at_unix_nano"`
}

// PongMessage echoes PingMessage.
type PongMessage struct {
	SentAtUnixNano int64 `json:"sent_at_unix_nano"`
}

// DrainMessage informs the hub that the agent is shutting down gracefully and
// should stop receiving new data streams while existing streams complete.
type DrainMessage struct {
	Reason string `json:"reason,omitempty"`
}

// ServiceUpdateMessage is sent over the control stream when the tenant agent
// hot-reloads agent.yaml so the hub updates its routing catalog without dropping the tunnel.
type ServiceUpdateMessage struct {
	Services []ServiceAnnouncement `json:"services"`
}

// ServiceHealthStatus reports sanitized local target health from the tenant agent to the hub.
// Crucially, internal IP addresses and credentials are NEVER included.
type ServiceHealthStatus struct {
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	Healthy       bool   `json:"healthy"`
	LatencyMs     int64  `json:"latency_ms"`
	ServerVersion string `json:"server_version,omitempty"`
	Message       string `json:"message,omitempty"`
	CheckedAtUnix int64  `json:"checked_at_unix"`
}

// HealthReportMessage is sent periodically over the control stream so central SaaS dashboards
// can show real-time tenant DB/API reachability without SSHing into customer hosts.
type HealthReportMessage struct {
	Services []ServiceHealthStatus `json:"services"`
}

// StreamOpenRequest is sent by the hub as the first frame of a new yamux data stream.
type StreamOpenRequest struct {
	TraceID        string            `json:"trace_id"`
	Traceparent    string            `json:"traceparent,omitempty"` // W3C Trace Context (00-<32hex>-<16hex>-01)
	ServiceName    string            `json:"service_name"`
	Protocol       string            `json:"protocol"` // "tcp" or "http"
	CallerIdentity string            `json:"caller_identity,omitempty"`
	TicketID       string            `json:"ticket_id,omitempty"`
	Purpose        map[string]string `json:"purpose,omitempty"` // Structured job lineage (job_type, job_id, triggered_by...)
}

// StreamOpenResponse is returned by the agent on the data stream.
// If OK is true, the stream immediately transitions to raw protocol byte passthrough.
type StreamOpenResponse struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
