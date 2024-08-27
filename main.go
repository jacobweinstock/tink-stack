package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/jacobweinstock/tink-stack/hegel"
	"github.com/jacobweinstock/tink-stack/rufio"
	smee "github.com/jacobweinstock/tink-stack/smee/cmd"
	"github.com/jacobweinstock/tink-stack/tink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Config struct {
	// LogLevel is the log level for the application.
	LogLevel       string           `json:"log_level,omitempty"`
	Kubeconfig     string           `json:"kubeconfig,omitempty"`
	Namespace      string           `json:"namespace,omitempty"`
	PublicIPv4     string           `json:"public_ipv4,omitempty"`
	TinkController tink.Controller  `json:"tink_controller,omitempty"`
	TinkServer     tink.Server      `json:"tink_server,omitempty"`
	Rufio          rufio.Controller `json:"rufio,omitempty"`
	Hegel          hegel.Server     `json:"hegel,omitempty"`
	Smee           *smee.Service    `json:"smee,omitempty"`
}

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()

	c := &Config{
		Smee: &smee.Service{},
	}
	fs := flag.NewFlagSet("tinkerbell", flag.ExitOnError)
	cli := newCLI(c, fs)
	cli.Parse(os.Args[1:])

	logger := defaultLogger(c.LogLevel)

	g, ctx := errgroup.WithContext(ctx)
	// TODO(jacobweinstock): add a wait for the kcp server to be ready. Is there a way to do this in the plugin?

	// install CRDs

	// Start the Tink controller
	g.Go(func() error {
		c.TinkController.Logger = logger.WithName("tink-controller")
		c.TinkController.Kubeconfig = c.Kubeconfig
		return c.TinkController.Start(ctx)
	})

	// Start the Tink Server
	g.Go(func() error {
		c.TinkServer.Logger = logger.WithName("tink-server")
		c.TinkServer.KubeconfigPath = c.Kubeconfig
		c.TinkServer.KubeNamespace = c.Namespace
		return c.TinkServer.Start(ctx)
	})

	// Start Rufio
	g.Go(func() error {
		r := rufio.Controller{}
		return r.Start(ctx)
	})

	// Start Hegel
	g.Go(func() error {
		c.Hegel.Logger = logger.WithName("hegel")
		c.Hegel.KubernetesKubeconfig = c.Kubeconfig
		c.Hegel.KubernetesNamespace = c.Namespace
		c.Hegel.Backend = "kubernetes"
		ctrl.SetLogger(c.Hegel.Logger)
		klog.SetLogger(c.Hegel.Logger)
		return c.Hegel.Start(ctx)
	})

	// Start Smee
	g.Go(func() error {
		kernelArgs := []string{
			c.Smee.IpxeHTTPScript.ExtraKernelArgs,
			"tink_worker_image=quay.io/tinkerbell/tink-worker:v0.10.0",
			"console=tty1",
			"console=tty2",
			"console=ttyAMA0,115200",
			"console=ttyAMA1,115200",
			"console=ttyS0,115200",
			"console=ttyS1,115200",
		}
		c.Smee.IpxeHTTPScript.ExtraKernelArgs = strings.Join(kernelArgs, " ")
		c.Smee.Backends.Kubernetes.ConfigFilePath = c.Kubeconfig
		c.Smee.Backends.Kubernetes.Namespace = c.Namespace
		c.Smee.Backends.Kubernetes.Enabled = true
		return c.Smee.Start(ctx, logger.WithName("smee"))
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
