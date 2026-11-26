package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditConfig configures tenant-local structured audit logging (JSONL file & optional Syslog/SIEM).
type AuditConfig struct {
	File       string `yaml:"file"`        // Optional local JSONL audit log path
	SyslogAddr string `yaml:"syslog_addr"` // Optional "udp://host:514" or "tcp://host:514"
}

// AuditEvent is a single structured tenant compliance audit record containing
// central platform business purpose (job_type, job_id, triggered_by) and traffic metrics.
type AuditEvent struct {
	Timestamp    time.Time         `json:"timestamp"`
	Event        string            `json:"event"`
	TenantID     string            `json:"tenant_id"`
	AgentID      string            `json:"agent_id"`
	TraceID      string            `json:"trace_id,omitempty"`
	Traceparent  string            `json:"traceparent,omitempty"`
	TicketID     string            `json:"ticket_id,omitempty"`
	Caller       string            `json:"caller,omitempty"`
	Purpose      map[string]string `json:"purpose,omitempty"`
	Service      string            `json:"service,omitempty"`
	Protocol     string            `json:"protocol,omitempty"`
	Action       string            `json:"action,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	BytesFromHub int64             `json:"bytes_from_hub,omitempty"`
	BytesToHub   int64             `json:"bytes_to_hub,omitempty"`
	DurationMs   int64             `json:"duration_ms,omitempty"`
}

// AuditLogger writes structured audit records concurrently to slog, an optional local JSONL file,
// and an optional remote tenant SIEM/Syslog endpoint via a non-blocking bounded async queue
// so an unreachable SIEM server can NEVER stall the data plane hot path.
type AuditLogger struct {
	tenantID string
	agentID  string
	logger   *slog.Logger

	fileMu sync.Mutex
	file   *os.File

	syslogNet     string
	syslogAddr    string
	syslogCh      chan string
	syslogStopCh  chan struct{}
	syslogWG      sync.WaitGroup
	droppedSyslog atomic.Int64
	closeOnce     sync.Once
}

// NewAuditLogger constructs an AuditLogger from cfg.
func NewAuditLogger(tenantID, agentID string, cfg AuditConfig, logger *slog.Logger) (*AuditLogger, error) {
	if logger == nil {
		logger = slog.Default()
	}
	al := &AuditLogger{
		tenantID: tenantID,
		agentID:  agentID,
		logger:   logger,
	}

	if path := strings.TrimSpace(cfg.File); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, fmt.Errorf("create audit log dir: %w", err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("open audit file %q: %w", path, err)
		}
		al.file = f
	}

	if rawSyslog := strings.TrimSpace(cfg.SyslogAddr); rawSyslog != "" {
		switch {
		case strings.HasPrefix(rawSyslog, "tcp://"):
			al.syslogNet = "tcp"
			al.syslogAddr = strings.TrimPrefix(rawSyslog, "tcp://")
		case strings.HasPrefix(rawSyslog, "udp://"):
			al.syslogNet = "udp"
			al.syslogAddr = strings.TrimPrefix(rawSyslog, "udp://")
		default:
			al.syslogNet = "udp"
			al.syslogAddr = rawSyslog
		}
		al.syslogCh = make(chan string, 2048)
		al.syslogStopCh = make(chan struct{})
		al.syslogWG.Add(1)
		go al.syslogWorker()
	}
	return al, nil
}

// DroppedSyslog returns how many syslog messages were dropped due to SIEM backpressure.
func (al *AuditLogger) DroppedSyslog() int64 {
	if al == nil {
		return 0
	}
	return al.droppedSyslog.Load()
}

// Record emits an audit event to slog, JSONL file, and non-blocking async Syslog queue.
func (al *AuditLogger) Record(ev AuditEvent) {
	if al == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.TenantID = al.tenantID
	ev.AgentID = al.agentID

	attrs := make([]any, 0, 18)
	attrs = append(attrs,
		"audit_event", ev.Event,
		"trace_id", ev.TraceID,
		"ticket_id", ev.TicketID,
		"service", ev.Service,
		"caller", ev.Caller,
	)
	if ev.Traceparent != "" {
		attrs = append(attrs, "traceparent", ev.Traceparent)
	}
	if len(ev.Purpose) > 0 {
		attrs = append(attrs, "purpose", ev.Purpose)
	}
	if ev.Action != "" {
		attrs = append(attrs, "action", ev.Action)
	}
	if ev.Reason != "" {
		attrs = append(attrs, "reason", ev.Reason)
	}
	if ev.BytesToHub > 0 || ev.BytesFromHub > 0 {
		attrs = append(attrs, "bytes_from_hub", ev.BytesFromHub, "bytes_to_hub", ev.BytesToHub, "duration_ms", ev.DurationMs)
	}

	if strings.Contains(ev.Event, "blocked") || strings.Contains(ev.Event, "rejected") {
		al.logger.Warn("AUDIT", attrs...)
	} else {
		al.logger.Info("AUDIT", attrs...)
	}

	if al.file == nil && al.syslogCh == nil {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}

	if al.file != nil {
		al.fileMu.Lock()
		if al.file != nil {
			_, _ = al.file.Write(append(line, '\n'))
		}
		al.fileMu.Unlock()
	}

	if al.syslogCh != nil {
		// RFC 5424 lightweight structured syslog line (<134> = local0.info)
		msg := fmt.Sprintf("<134>1 %s %s dataproxy-agent - %s - %s\n",
			ev.Timestamp.Format(time.RFC3339), al.agentID, ev.Event, string(line))
		select {
		case al.syslogCh <- msg:
		default:
			al.droppedSyslog.Add(1)
		}
	}
}

func (al *AuditLogger) syslogWorker() {
	defer al.syslogWG.Done()
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	send := func(msg string) {
		if conn == nil {
			c, err := net.DialTimeout(al.syslogNet, al.syslogAddr, 1*time.Second)
			if err != nil {
				al.droppedSyslog.Add(1)
				return
			}
			conn = c
		}
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := conn.Write([]byte(msg)); err != nil {
			_ = conn.Close()
			conn = nil
			al.droppedSyslog.Add(1)
		}
	}

	for {
		select {
		case msg := <-al.syslogCh:
			send(msg)
		case <-al.syslogStopCh:
			// Best-effort quick drain of remaining queued messages without blocking shutdown.
			for i := 0; i < 64; i++ {
				select {
				case msg := <-al.syslogCh:
					send(msg)
				default:
					return
				}
			}
			return
		}
	}
}

// Close flushes and closes any open local audit file and stops the async syslog worker.
func (al *AuditLogger) Close() {
	if al == nil {
		return
	}
	al.closeOnce.Do(func() {
		if al.syslogStopCh != nil {
			close(al.syslogStopCh)
			al.syslogWG.Wait()
		}
		al.fileMu.Lock()
		if al.file != nil {
			_ = al.file.Close()
			al.file = nil
		}
		al.fileMu.Unlock()
	})
}
