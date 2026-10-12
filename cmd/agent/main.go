package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelvins-io/Intranet-penetration/internal/agent"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
)

func main() {
	cfgPath := flag.String("config", "configs/agent.yaml", "path to agent config")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadAgent(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := agent.New(cfg, log)
	log.Info("agent starting", "server", cfg.ServerAddr, "agent_id", cfg.AgentID, "tunnels", len(cfg.Tunnels))
	if err := a.Run(ctx); err != nil && err != context.Canceled {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
