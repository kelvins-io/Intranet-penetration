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
	cfgPath := flag.String("config", "configs/control.yaml", "path to control config")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	cfg.Role = config.RoleControl
	if cfg.APIListen == "" {
		cfg.APIListen = ":8090"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("init control", "err", err)
		os.Exit(1)
	}
	log.Info("control starting", "api_listen", cfg.APIListen, "region", cfg.Region)
	if err := srv.Run(ctx); err != nil {
		log.Error("control stopped", "err", err)
		os.Exit(1)
	}
}
