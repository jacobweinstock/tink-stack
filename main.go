package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/jacobweinstock/tink-stack/cmd"
	"github.com/jacobweinstock/tink-stack/cmd/flag/config"
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
	Global         *config.GlobalConfig `json:"global,inline"`
	OTEL           otel                 `json:"otel,omitempty"`
	TinkController tink.Controller      `json:"tink_controller,omitempty"`
	TinkServer     tink.Server          `json:"tink_server,omitempty"`
	Rufio          rufio.Controller     `json:"rufio,omitempty"`
	Hegel          hegel.Server         `json:"hegel,omitempty"`
	Smee           *smee.Config         `json:"smee,omitempty"`
}

type otel struct {
	Endpoint string `json:"otel_endpoint,omitempty"`
	Insecure bool   `json:"otel_insecure,omitempty"`
}

type backend string

const (
	backendKube backend = "kube"
	backendFile backend = "file"
	backendNoop backend = "noop"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()

	c := &Config{
		Smee: &smee.Config{
			DHCP: smee.DHCP{
				Mode: smee.DHCPModeProxy,
			},
		},
		Global: &config.GlobalConfig{
			TrustedProxies: []netip.Prefix{
				netip.MustParsePrefix("8.8.8.8/32"),
			},
		},
	}
	fs := ff.NewFlagSet("tinkerbell")
	cli := newCLI(c, fs)
	if err := cli.Parse(os.Args[1:], ff.WithEnvVarPrefix("TINKERBELL")); err != nil {
		fmt.Fprintln(os.Stderr, ffhelp.Command(cli))
		if !errors.Is(err, ff.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}

		os.Exit(1)
	}

	logger := cmd.DefaultLogger(c.Global.LogLevel)
	logger.Info("debugging", "c.Smee.DHCP.Enabled", c.Smee.DHCP.Enabled)
	logger.Info("debugging", "c.Smee.DHCP.TFTPPort", c.Smee.DHCP.TFTPPort)
	logger.Info("debugging", "c.Smee.DHCP.IPForPacket", c.Smee.DHCP.IPForPacket)
	logger.Info("debugging", "c.Smee.DHCP.Mode", c.Smee.DHCP.Mode)
	logger.Info("debugging", "c.Global.TrustedProxies", c.Global.TrustedProxies)
	logger.Info("debugging", "c.Global.PublicIP", c.Global.PublicIP)
	return

	g, ctx := errgroup.WithContext(ctx)
	// TODO(jacobweinstock): add a wait for the kcp server to be ready. Is there a way to do this in the plugin?

	// install CRDs

	// Start the Tink controller
	g.Go(func() error {
		c.TinkController.Logger = logger.WithName("tink-controller")
		c.TinkController.Kubeconfig = c.Global.BackendKubeConfig
		if err := c.TinkController.Start(ctx); err != nil {
			return fmt.Errorf("tink controller failed: %w", err)
		}
		return nil
	})

	// Start the Tink Server
	g.Go(func() error {
		c.TinkServer.Logger = logger.WithName("tink-server")
		c.TinkServer.KubeconfigPath = c.Global.BackendKubeConfig
		c.TinkServer.KubeNamespace = c.Global.BackendKubeNamespace
		if err := c.TinkServer.Start(ctx); err != nil {
			return fmt.Errorf("tink server failed: %w", err)
		}
		return nil
	})

	// Start Rufio
	g.Go(func() error {
		r := rufio.Controller{}
		if err := r.Start(ctx); err != nil {
			return fmt.Errorf("rufio failed: %w", err)
		}
		return nil
	})

	// Start Hegel
	g.Go(func() error {
		c.Hegel.Logger = logger.WithName("hegel")
		c.Hegel.KubernetesKubeconfig = c.Global.BackendKubeConfig
		c.Hegel.KubernetesNamespace = c.Global.BackendKubeNamespace
		c.Hegel.Backend = "kubernetes"
		ctrl.SetLogger(c.Hegel.Logger)
		klog.SetLogger(c.Hegel.Logger)
		if err := c.Hegel.Start(ctx); err != nil {
			return fmt.Errorf("hegel failed: %w", err)
		}
		return nil
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
		if err := c.Smee.Start(ctx, logger.WithName("smee")); err != nil {
			return fmt.Errorf("smee failed: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}
