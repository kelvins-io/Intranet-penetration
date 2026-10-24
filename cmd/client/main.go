package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelvins-io/Intranet-penetration/internal/client"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
)

func main() {
	cfgPath := flag.String("config", "configs/client.yaml", "client config path")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cl := client.New(cfg, log)

	var sysProxy *client.SystemProxy
	if cfg.SystemProxy && (cfg.Mode == "socks" || cfg.Mode == "both") {
		sysProxy = client.NewSystemProxy(cfg.SOCKSListen)
		if err := sysProxy.Enable(); err != nil {
			log.Warn("system proxy enable", "err", err)
		} else {
			log.Info("system proxy enabled", "socks", cfg.SOCKSListen)
			defer func() {
				if err := sysProxy.Disable(); err != nil {
					log.Warn("system proxy disable", "err", err)
				} else {
					log.Info("system proxy restored")
				}
			}()
		}
	}

	errCh := make(chan error, 4)
	go func() { errCh <- cl.Run(ctx) }()

	if cfg.Mode == "socks" || cfg.Mode == "both" {
		go func() { errCh <- cl.ServeSOCKS5(ctx, cfg.SOCKSListen) }()
	}
	if cfg.Mode == "tun" || cfg.Mode == "both" {
		tun := client.NewTunEngine(cl)
		go func() {
			errCh <- tun.Start(ctx)
		}()
	}
	if cfg.PanelListen != "" && cfg.PanelListen != "-" {
		panel := client.NewPanel(cl, cfg.PanelListen, sysProxy)
		go func() { errCh <- panel.Start(ctx) }()
	}

	select {
	case <-ctx.Done():
		log.Info("client shutting down")
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			log.Error("client stopped", "err", err)
			os.Exit(1)
		}
	}
}
