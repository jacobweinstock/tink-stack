package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jacobweinstock/tink-stack/cmd"
	"github.com/jacobweinstock/tink-stack/hegel"
	"github.com/jacobweinstock/tink-stack/rufio"
	"github.com/jacobweinstock/tink-stack/smee"
	"github.com/jacobweinstock/tink-stack/tink"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
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
	Smee           *smee.Config     `json:"smee,omitempty"`
}

func main() {

	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()

	c := &Config{
		Smee: &smee.Config{},
	}
	fs := ff.NewFlagSet("tinkerbell")
	cli := newCLI(c, fs)
	if err := cli.Parse(os.Args[1:], ff.WithEnvVarPrefix("TINKERBELL")); err != nil {
		if !errors.Is(err, ff.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, ffhelp.Command(cli))
		os.Exit(1)
	}

	logger := cmd.DefaultLogger(c.LogLevel)

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
			"tink_worker_image=quay.io/tinkerbell/tink-worker:v0.12.1",
			//			"tink_worker_image=127.0.0.1/embedded/tink-worker:v0.10.0",
			"console=tty1",
			"console=tty2",
			"console=ttyAMA0,115200",
			"console=ttyAMA1,115200",
			"console=ttyS0,115200",
			"console=ttyS1,115200",
		}
		c.Smee.IPXE.HTTPScriptServer.ExtraKernelArgs = kernelArgs
		c.Smee.Backend = nil
		return c.Smee.Start(ctx, logger.WithName("smee"))
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}
