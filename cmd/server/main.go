package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"github.com/kelvins-io/Intranet-penetration/internal/server"
)

func main() {
	cfgPath := flag.String("config", "configs/server.yaml", "path to server config")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("init server", "err", err)
		os.Exit(1)
	}
	log.Info("server starting",
		"listen", cfg.Listen,
		"http_gateway", cfg.HTTPGateway,
		"https_gateway", cfg.HTTPSGateway,
		"public_host", cfg.PublicHost,
		"dashboard", "http://127.0.0.1"+normalizePort(cfg.HTTPGateway)+"/dashboard/",
	)
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func normalizePort(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return addr
	}
	return ":" + addr
}
