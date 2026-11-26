package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"dataproxy/internal/auth"
	"dataproxy/internal/store"
	"dataproxy/internal/transport"
)

// Server orchestrates all dataproxy-hub listeners and lifecycle management.
type Server struct {
	cfg          *Config
	logger       *slog.Logger
	st           store.Store
	metrics      *Metrics
	mesh         *MeshPeer
	tenantAuth   *auth.TenantAuthenticator
	callerACL    *auth.CallerACL
	tickets      *auth.TicketManager
	devices      *auth.DeviceManager
	registry     *Registry
	tunnelServer *TunnelServer
	portMapper   *PortMapper
	proxyIngress *ProxyIngress
	httpIngress  *HTTPIngress
	smartDB      *SmartDBIngress
	adminAPI     *AdminAPI

	wssLn        net.Listener
	wssSrv       *http.Server
	rawTLSLn     net.Listener
	meshLn       net.Listener
	proxyLn      net.Listener
	httpLn       net.Listener
	httpSrv      *http.Server
	pgSmartLn    net.Listener
	mysqlSmartLn net.Listener
	mongoSmartLn net.Listener
	redisSmartLn net.Listener
	adminLn      net.Listener
	adminSrv     *http.Server
	wg           sync.WaitGroup
	closeOnce    sync.Once
}

// NewServer constructs a hub server from cfg.
func NewServer(cfg *Config, logger *slog.Logger) (*Server, error) {
	cfg.Normalize()
	if logger == nil {
		logger = slog.Default()
	}

	var st store.Store
	if cfg.StateFile != "" {
		fs, err := store.NewFileStore(cfg.StateFile)
		if err != nil {
			return nil, fmt.Errorf("init hub state store: %w", err)
		}
		st = fs
	}

	tenantAuth, err := auth.NewTenantAuthenticatorWithStore(cfg.Tenants, st)
	if err != nil {
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}
	callerACL, err := auth.NewCallerACL(cfg.Callers, cfg.AllowUnauthenticatedCallers)
	if err != nil {
		if st != nil {
			_ = st.Close()
		}
		return nil, err
	}
	tickets := auth.NewTicketManager(cfg.TicketSigningKey, cfg.TicketDefaultTTL)
	devices, err := auth.NewDeviceManager(cfg.DeviceCACertFile, cfg.DeviceCAKeyFile, cfg.DeviceCertTTL, cfg.EnrollmentTTL, st)
	if err != nil {
		if st != nil {
			_ = st.Close()
		}
		return nil, fmt.Errorf("init device PKI: %w", err)
	}

	metrics := NewMetrics()
	registry := NewRegistry(cfg.StreamOpenTimeout)
	registry.SetMetrics(metrics)
	registry.SetQuotas(cfg.MaxStreamsPerTenant, cfg.MaxSessionsPerTenant)

	var mesh *MeshPeer
	if cfg.MeshListenAddr != "" || len(cfg.MeshPeers) > 0 {
		mesh = NewMeshPeer(cfg.NodeID, cfg.MeshSecret, cfg.MeshPeers, registry, metrics, logger)
		registry.SetMesh(mesh)
	}

	tunnelSrv := NewTunnelServer(tenantAuth, devices, registry, cfg.HeartbeatInterval, logger)
	tunnelSrv.SetMetrics(metrics)
	if cfg.HandshakeRateLimitPerMin > 0 {
		tunnelSrv.SetRateLimiter(NewIPRateLimiter(cfg.HandshakeRateLimitPerMin, cfg.HandshakeBurst))
	}

	portMapper := NewPortMapperWithStore(registry, st, logger)
	proxyIng := NewProxyIngress(registry, callerACL, cfg.VirtualDomainSuffix, logger)
	httpIng := NewHTTPIngress(registry, callerACL, tickets, cfg.VirtualDomainSuffix, logger)
	smartDB := NewSmartDBIngress(registry, tickets, logger)
	adminAPI := NewAdminAPI(cfg.AdminToken, tenantAuth, tickets, devices, registry, portMapper)
	adminAPI.SetMetrics(metrics)

	return &Server{
		cfg:          cfg,
		logger:       logger.With("component", "hub"),
		st:           st,
		metrics:      metrics,
		mesh:         mesh,
		tenantAuth:   tenantAuth,
		callerACL:    callerACL,
		tickets:      tickets,
		devices:      devices,
		registry:     registry,
		tunnelServer: tunnelSrv,
		portMapper:   portMapper,
		proxyIngress: proxyIng,
		httpIngress:  httpIng,
		smartDB:      smartDB,
		adminAPI:     adminAPI,
	}, nil
}

// Metrics returns the hub's Prometheus metrics collector.
func (s *Server) Metrics() *Metrics { return s.metrics }

// MeshAddr returns the bound address of the Hub-to-Hub cluster mesh listener, if enabled.
func (s *Server) MeshAddr() string {
	if s.meshLn == nil {
		return ""
	}
	return s.meshLn.Addr().String()
}

// Devices returns the hub's device enrollment & PKI manager.
func (s *Server) Devices() *auth.DeviceManager { return s.devices }

// Tickets returns the hub's short-lived job ticket manager.
func (s *Server) Tickets() *auth.TicketManager { return s.tickets }

// MongoSmartAddr returns the bound address of the single-port MongoDB ticket router.
func (s *Server) MongoSmartAddr() string {
	if s.mongoSmartLn == nil {
		return ""
	}
	return s.mongoSmartLn.Addr().String()
}

// PGSmartAddr returns the bound address of the single-port PostgreSQL ticket router.
func (s *Server) PGSmartAddr() string {
	if s.pgSmartLn == nil {
		return ""
	}
	return s.pgSmartLn.Addr().String()
}

// MySQLSmartAddr returns the bound address of the single-port MySQL ticket router.
func (s *Server) MySQLSmartAddr() string {
	if s.mysqlSmartLn == nil {
		return ""
	}
	return s.mysqlSmartLn.Addr().String()
}

// RedisSmartAddr returns the bound address of the single-port Redis ticket router.
func (s *Server) RedisSmartAddr() string {
	if s.redisSmartLn == nil {
		return ""
	}
	return s.redisSmartLn.Addr().String()
}

// Registry returns the multi-tenant session registry.
func (s *Server) Registry() *Registry { return s.registry }

// PortMapper returns the TCP port mapping manager.
func (s *Server) PortMapper() *PortMapper { return s.portMapper }

// WSSAddr returns the bound address of the WSS tunnel listener, if enabled.
func (s *Server) WSSAddr() string {
	if s.wssLn == nil {
		return ""
	}
	return s.wssLn.Addr().String()
}

// RawTLSAddr returns the bound address of the raw TLS/TCP tunnel listener, if enabled.
func (s *Server) RawTLSAddr() string {
	if s.rawTLSLn == nil {
		return ""
	}
	return s.rawTLSLn.Addr().String()
}

// ProxyAddr returns the bound address of the unified SOCKS5/HTTP CONNECT listener, if enabled.
func (s *Server) ProxyAddr() string {
	if s.proxyLn == nil {
		return ""
	}
	return s.proxyLn.Addr().String()
}

// HTTPAddr returns the bound address of the HTTP reverse proxy listener, if enabled.
func (s *Server) HTTPAddr() string {
	if s.httpLn == nil {
		return ""
	}
	return s.httpLn.Addr().String()
}

// AdminAddr returns the bound address of the Admin API listener, if enabled.
func (s *Server) AdminAddr() string {
	if s.adminLn == nil {
		return ""
	}
	return s.adminLn.Addr().String()
}

// Start binds all configured listeners and begins serving in background goroutines.
func (s *Server) Start() error {
	tlsCfg, err := transport.BuildServerTLSConfig(s.cfg.TunnelTLS)
	if err != nil {
		return fmt.Errorf("build tunnel tls config: %w", err)
	}
	// Trust device certificates signed by our DeviceManager CA on mTLS connections.
	if tlsCfg != nil && s.devices != nil && s.devices.CACert() != nil {
		if tlsCfg.ClientCAs == nil {
			tlsCfg.ClientCAs = x509.NewCertPool()
		}
		tlsCfg.ClientCAs.AddCert(s.devices.CACert())
		if tlsCfg.ClientAuth == tls.NoClientCert {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	// 1. WSS / WS Tunnel Listener (+ Device Enrollment & Certificate Renewal endpoints on same HTTPS port!).
	if s.cfg.TunnelWSSAddr != "" {
		rawLn, err := net.Listen("tcp", s.cfg.TunnelWSSAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen tunnel_wss_addr %s: %w", s.cfg.TunnelWSSAddr, err)
		}
		if tlsCfg != nil {
			s.wssLn = tls.NewListener(rawLn, tlsCfg)
		} else {
			s.wssLn = rawLn
		}
		mux := http.NewServeMux()
		mux.HandleFunc(s.cfg.TunnelWSSPath, s.tunnelServer.HandleWebSocket)
		mux.HandleFunc("/tunnel/v1/enroll", s.tunnelServer.HandleDeviceEnroll)
		mux.HandleFunc("/tunnel/v1/renew", s.tunnelServer.HandleDeviceRenew)
		s.wssSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 15 * time.Second}
		s.logger.Info("tunnel WSS listener started", "addr", s.wssLn.Addr().String(), "path", s.cfg.TunnelWSSPath, "tls", tlsCfg != nil)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.wssSrv.Serve(s.wssLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("tunnel WSS server stopped", "error", err)
			}
		}()
	}

	// 2. Optional raw mTLS / TLS TCP Tunnel Listener.
	if s.cfg.TunnelTLSAddr != "" {
		rawLn, err := net.Listen("tcp", s.cfg.TunnelTLSAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen tunnel_tls_addr %s: %w", s.cfg.TunnelTLSAddr, err)
		}
		transportName := "tcp"
		if tlsCfg != nil {
			s.rawTLSLn = tls.NewListener(rawLn, tlsCfg)
			transportName = "tls"
		} else {
			s.rawTLSLn = rawLn
		}
		s.logger.Info("tunnel raw listener started", "addr", s.rawTLSLn.Addr().String(), "transport", transportName)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.tunnelServer.ServeRawListener(s.rawTLSLn, transportName); err != nil {
				s.logger.Error("tunnel raw listener stopped", "error", err)
			}
		}()
	}

	// 3. Unified SOCKS5 + HTTP CONNECT Proxy Listener.
	if s.cfg.ProxyAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.ProxyAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen proxy_addr %s: %w", s.cfg.ProxyAddr, err)
		}
		s.proxyLn = ln
		s.logger.Info("unified SOCKS5/CONNECT proxy started", "addr", ln.Addr().String(), "suffix", s.cfg.VirtualDomainSuffix)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.proxyIngress.Serve(ln); err != nil {
				s.logger.Error("proxy ingress stopped", "error", err)
			}
		}()
	}

	// 4. Standard HTTP Reverse Proxy Listener.
	if s.cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen http_addr %s: %w", s.cfg.HTTPAddr, err)
		}
		s.httpLn = ln
		s.httpSrv = &http.Server{Handler: s.httpIngress, ReadHeaderTimeout: 30 * time.Second}
		s.logger.Info("HTTP reverse proxy ingress started", "addr", ln.Addr().String(), "suffix", s.cfg.VirtualDomainSuffix)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("HTTP ingress stopped", "error", err)
			}
		}()
	}

	// 5. Single-Port Smart Multi-Tenant DB Ticket Routers (PostgreSQL / MySQL / Redis).
	if s.cfg.PGSmartAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.PGSmartAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen pg_smart_addr %s: %w", s.cfg.PGSmartAddr, err)
		}
		s.pgSmartLn = ln
		s.logger.Info("single-port PostgreSQL ticket router started", "addr", ln.Addr().String())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.smartDB.ServePostgres(ln)
		}()
	}
	if s.cfg.MySQLSmartAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.MySQLSmartAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen mysql_smart_addr %s: %w", s.cfg.MySQLSmartAddr, err)
		}
		s.mysqlSmartLn = ln
		s.logger.Info("single-port MySQL ticket router started", "addr", ln.Addr().String())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.smartDB.ServeMySQL(ln)
		}()
	}
	if s.cfg.MongoSmartAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.MongoSmartAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen mongo_smart_addr %s: %w", s.cfg.MongoSmartAddr, err)
		}
		s.mongoSmartLn = ln
		s.logger.Info("single-port MongoDB ticket router started", "addr", ln.Addr().String())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.smartDB.ServeMongo(ln)
		}()
	}
	if s.cfg.RedisSmartAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.RedisSmartAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen redis_smart_addr %s: %w", s.cfg.RedisSmartAddr, err)
		}
		s.redisSmartLn = ln
		s.logger.Info("single-port Redis ticket router started", "addr", ln.Addr().String())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.smartDB.ServeRedis(ln)
		}()
	}

	// 6. Optional Hub-to-Hub Cluster Mesh Peer Forwarding Listener.
	if s.cfg.MeshListenAddr != "" && s.mesh != nil {
		ln, err := net.Listen("tcp", s.cfg.MeshListenAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen mesh_listen_addr %s: %w", s.cfg.MeshListenAddr, err)
		}
		s.meshLn = ln
		s.logger.Info("hub cluster mesh listener started", "addr", ln.Addr().String(), "node_id", s.cfg.NodeID, "peers", len(s.cfg.MeshPeers))
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.mesh.Serve(ln); err != nil {
				s.logger.Error("hub cluster mesh listener stopped", "error", err)
			}
		}()
	}

	// 7. Control Plane Admin API Listener.
	if s.cfg.AdminAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.AdminAddr)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen admin_addr %s: %w", s.cfg.AdminAddr, err)
		}
		s.adminLn = ln
		s.adminSrv = &http.Server{Handler: s.adminAPI, ReadHeaderTimeout: 15 * time.Second}
		s.logger.Info("admin API listener started", "addr", ln.Addr().String())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.adminSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("admin API stopped", "error", err)
			}
		}()
	}

	// 8. Start initial static TCP port bindings & restore persisted dynamic bindings.
	for _, spec := range s.cfg.TCPBindings {
		if _, err := s.portMapper.AddStatic(spec); err != nil {
			s.Close()
			return fmt.Errorf("init tcp binding %s: %w", spec.ListenAddr, err)
		}
	}
	s.portMapper.RestorePersisted()

	return nil
}

// Close gracefully stops all hub listeners and active bindings.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.portMapper.Close()
		if s.adminSrv != nil {
			_ = s.adminSrv.Shutdown(ctx)
		}
		if s.meshLn != nil {
			_ = s.meshLn.Close()
		}
		if s.httpSrv != nil {
			_ = s.httpSrv.Shutdown(ctx)
		}
		if s.proxyLn != nil {
			_ = s.proxyLn.Close()
		}
		if s.pgSmartLn != nil {
			_ = s.pgSmartLn.Close()
		}
		if s.mysqlSmartLn != nil {
			_ = s.mysqlSmartLn.Close()
		}
		if s.mongoSmartLn != nil {
			_ = s.mongoSmartLn.Close()
		}
		if s.redisSmartLn != nil {
			_ = s.redisSmartLn.Close()
		}
		if s.rawTLSLn != nil {
			_ = s.rawTLSLn.Close()
		}
		if s.wssSrv != nil {
			_ = s.wssSrv.Shutdown(ctx)
		}
		s.registry.CloseAll()
		s.wg.Wait()
		if s.st != nil {
			_ = s.st.Close()
		}
	})
}
