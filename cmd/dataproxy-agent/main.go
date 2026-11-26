package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dataproxy/internal/agent"
	"dataproxy/internal/transport"
)

var version = "dev"

func main() {
	// Support subcommands: "dataproxy-agent doctor ..." and "dataproxy-agent enroll ..."
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			runDoctorCommand(os.Args[2:])
			return
		case "enroll":
			runEnrollCommand(os.Args[2:])
			return
		}
	}

	cfgPath := flag.String("config", "configs/agent.example.yaml", "path to agent YAML config file")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("dataproxy-agent %s\n", version)
		return
	}

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.LogLevel)
	client, err := agent.NewClient(cfg, logger)
	if err != nil {
		logger.Error("failed initializing agent", "error", err)
		os.Exit(1)
	}
	client.SetConfigPath(*cfgPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for SIGHUP to trigger immediate lossless config hot-reload.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighupCh:
				logger.Info("received SIGHUP, hot-reloading agent config", "path", *cfgPath)
				if err := client.ReloadFromFile(*cfgPath); err != nil {
					logger.Error("SIGHUP hot-reload failed; keeping previous config", "error", err)
				}
			}
		}
	}()

	if err := client.Run(ctx); err != nil {
		logger.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
}

func runDoctorCommand(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/agent.example.yaml", "path to agent YAML config file")
	_ = fs.Parse(args)

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	report := agent.RunDoctor(context.Background(), cfg)
	report.Format(os.Stdout)
	if !report.AllPassed() {
		os.Exit(1)
	}
}

func runEnrollCommand(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	hubURL := fs.String("hub", "", "central hub HTTPS/WSS URL (e.g. https://hub.example.com:8443)")
	code := fs.String("code", "", "one-time 15-minute enrollment code (enroll_...)")
	stateDir := fs.String("state-dir", "./device-state", "local directory to store private key and signed device cert")
	caFile := fs.String("ca", "", "optional hub TLS server CA file")
	serverName := fs.String("server-name", "", "optional TLS server name override")
	insecure := fs.Bool("insecure", false, "skip TLS verification (dev only)")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := agent.EnrollDevice(ctx, agent.EnrollOptions{
		HubBaseURL: *hubURL,
		Code:       *code,
		StateDir:   *stateDir,
		TLS: transport.TLSOptions{
			CAFile:             *caFile,
			ServerName:         *serverName,
			InsecureSkipVerify: *insecure,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 设备挂载注册失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("================ dataproxy-agent 设备挂载成功 ================")
	fmt.Printf("  租户 ID     : %s\n", st.TenantID)
	fmt.Printf("  设备 ID     : %s\n", st.DeviceID)
	fmt.Printf("  证书序列号  : %s\n", st.CertSerial)
	fmt.Printf("  证书有效期至: %s\n", st.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  本地状态目录: %s（私钥仅保存在本机，永不出域）\n", *stateDir)
	fmt.Printf("  使用方式    : 在 agent.yaml 中配置 device_state_dir: %q 即可启动\n", *stateDir)
	fmt.Println("==============================================================")
}

func buildLogger(levelStr string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
