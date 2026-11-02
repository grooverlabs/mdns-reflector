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
)

// exitConfig is EX_CONFIG; the systemd unit does not restart on it.
const exitConfig = 78

func setupLogger(level string) {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove timestamp — journald provides it
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(handler))
}

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config %s: %v\n", *configPath, err)
		return exitConfig
	}
	setupLogger(cfg.LogLevel)

	reflector, err := NewReflector(cfg)
	if err != nil {
		slog.Error("Invalid config", "error", err)
		return exitConfig
	}
	for i, rule := range cfg.Rules {
		slog.Info("Rule loaded",
			"rule", i,
			"from", rule.From,
			"to", rule.To,
			"types", rule.Types,
			"allowed_ips", len(rule.Filter.AllowedIPs),
			"allowed_services", len(rule.Filter.AllowedServices),
			"stateful", rule.isStateful(),
		)
	}

	if err := reflector.Start(); err != nil {
		slog.Error("Error starting reflector", "error", err)
		return 1
	}
	slog.Info("mDNS Reflector started", "interfaces", len(cfg.Interfaces))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := reflector.Run(ctx); err != nil {
		slog.Error("Reflector stopped", "error", err)
		return 1
	}
	slog.Info("Shutting down")
	return 0
}
