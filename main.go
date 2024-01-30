package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/jacobweinstock/tink-stack/cmd"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		// Start the KCP server with embedded etcd
		kcp := cmd.KCPP{
			Context:    ctx,
			DataDir:    "",
			PluginFile: "/home/tink/repos/jacobweinstock/tink-stack/plugin/kcp",
		}
		return kcp.Do()
	})

	// Start the Tinkerbell controller
	g.Go(func() error {
		time.Sleep(time.Second * 20)
		tinkController := cmd.TinkController{
			Logger:               defaultLogger("info"),
			Kubeconfig:           "admin.kubeconfig",
			EnableLeaderElection: false,
			MetricsAddr:          ":8080",
			ProbeAddr:            ":8081",
		}
		return tinkController.Start(ctx)
	})

	// Start the Tinkerbell Server
	g.Go(func() error {
		tinkServer := cmd.TinkServer{}
		return tinkServer.Start(ctx)
	})

	// Start Rufio
	g.Go(func() error {
		rufio := cmd.Rufio{}
		return rufio.Start(ctx)
	})

	// Start Hegel
	g.Go(func() error {
		hegel := cmd.Hegel{}
		return hegel.Start(ctx)
	})

	// Start Smee
	g.Go(func() error {
		smee := cmd.Smee{}
		return smee.Start(ctx)
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}

// defaultLogger is zap logr implementation.
func defaultLogger(level string) logr.Logger {
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout"}
	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}
	zapLogger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}

	return zapr.NewLogger(zapLogger)
}
