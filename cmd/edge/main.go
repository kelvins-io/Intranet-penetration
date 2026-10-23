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
	cfgPath := flag.String("config", "configs/edge.yaml", "path to edge config")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	cfg.Role = config.RoleEdge

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("init edge", "err", err)
		os.Exit(1)
	}
	log.Info("edge starting",
		"edge_id", cfg.EdgeID,
		"listen", cfg.Listen,
		"http_gateway", cfg.HTTPGateway,
		"control_url", cfg.ControlURL,
	)
	if err := srv.Run(ctx); err != nil {
		log.Error("edge stopped", "err", err)
		os.Exit(1)
	}
}
