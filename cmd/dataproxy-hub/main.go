package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"dataproxy/internal/hub"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "configs/hub.example.yaml", "path to hub YAML config file")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("dataproxy-hub %s\n", version)
		return
	}

	cfg, err := hub.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.LogLevel)
	srv, err := hub.NewServer(cfg, logger)
	if err != nil {
		logger.Error("failed initializing hub", "error", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		logger.Error("failed starting hub", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("received signal, shutting down hub", "signal", sig.String())
	srv.Close()
	logger.Info("hub stopped cleanly")
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
