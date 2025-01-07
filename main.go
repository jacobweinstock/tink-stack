package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jacobweinstock/tink-stack/backend/kube"
	"github.com/jacobweinstock/tink-stack/cmd"
	"github.com/jacobweinstock/tink-stack/cmd/flag/config"
	"github.com/jacobweinstock/tink-stack/hegel"
	"github.com/jacobweinstock/tink-stack/rufio"
	"github.com/jacobweinstock/tink-stack/smee"
	"github.com/jacobweinstock/tink-stack/tink"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
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

type backendType string

const (
	backendKube backendType = "kube"
	backendFile backendType = "file"
	backendNoop backendType = "noop"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()

	c := &Config{
		Global: &config.GlobalConfig{
			LogLevel: "info",
			Backend:  "kube",
			TrustedProxies: []netip.Prefix{
				netip.MustParsePrefix("8.8.8.8/32"),
			},
			PublicIP:             detectPublicIPv4(),
			BackendKubeNamespace: "tink",
			BackendKubeConfig:    "/root/.kube/config",
		},
		Smee: &smee.Config{
			DHCP: smee.DHCP{
				Enabled:       true,
				Mode:          smee.DHCPModeReservation,
				BindAddr:      netip.MustParseAddrPort("0.0.0.0:67"),
				BindInterface: "",
				IPForPacket:   detectPublicIPv4(),
				SyslogIP:      detectPublicIPv4(),
				TFTPIP:        detectPublicIPv4(),
				IPXEHTTPBinaryURL: &url.URL{
					Scheme: "http",
					Host:   detectPublicIPv4().String() + ":8080",
					Path:   "/ipxe/",
				},
				IPXEHTTPScript: smee.IPXEHTTPScript{
					URL: &url.URL{
						Scheme: "http",
						Host:   detectPublicIPv4().String() + ":8080",
						Path:   "/auto.ipxe",
					},
					InjectMacAddress: true,
				},
				TFTPPort: 69},
			IPXE: smee.IPXE{
				EmbeddedScriptPatch: "",
				HTTPBinaryServer: smee.IPXEHTTPBinaryServer{
					Enabled: true,
				},
				HTTPScriptServer: smee.IPXEHTTPScriptServer{
					Enabled:    true,
					BindAddr:   detectPublicIPv4(),
					BindPort:   8080,
					Retries:    0,
					RetryDelay: 0,
					OSIEURL: &url.URL{
						Scheme: "http",
						Host:   "192.168.2.114:8080",
					},
					TrustedProxies:  []string{},
					ExtraKernelArgs: []string{},
				},
			},
			ISO: smee.ISO{
				Enabled:           true,
				UpstreamURL:       &url.URL{},
				PatchMagicString:  "",
				StaticIPAMEnabled: false,
			},
			OTEL: smee.OTEL{
				Endpoint:         "",
				InsecureEndpoint: false,
			},
			Syslog: smee.Syslog{
				BindAddr: detectPublicIPv4(),
				BindPort: 514,
				Enabled:  true,
			},
			TFTP: smee.TFTP{
				BindAddr:  detectPublicIPv4(),
				BindPort:  69,
				BlockSize: 512,
				Timeout:   time.Minute,
				Enabled:   true,
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
	c.Smee.Logger = logger.WithName("smee")
	g, ctx := errgroup.WithContext(ctx)

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
		c.Hegel.Debug = true
		ctrl.SetLogger(c.Hegel.Logger)
		klog.SetLogger(c.Hegel.Logger)
		if err := c.Hegel.Start(ctx); err != nil {
			return fmt.Errorf("hegel failed: %w", err)
		}
		return nil
	})

	kc, err := kube.NewFileRestConfig(c.Global.BackendKubeConfig, c.Global.BackendKubeNamespace)
	if err != nil {
		panic(err)
	}
	bk, err := kube.NewBackend(kc)
	if err != nil {
		panic(err)
	}
	g.Go(func() error {
		return bk.Start(ctx)
	})

	logger.Info("debugging", "context", ctx.Err(), "c.Smee.DHCP.Enabled", c.Smee.DHCP.Enabled)
	logger.V(2).Info("debugging with V(2)", "c.Smee.DHCP.Enabled", c.Smee.DHCP.Enabled)

	// Start Smee
	g.Go(func() error {
		kernelArgs := []string{
			"tink_worker_image=quay.io/tinkerbell/tink-worker:v0.12.1",
			fmt.Sprintf("grpc_authority=%s:42113", detectPublicIPv4().String()),
			"tinkerbell_tls=false",
			"console=tty1",
			"console=tty2",
			"console=ttyAMA0,115200",
			"console=ttyAMA1,115200",
			"console=ttyS0,115200",
			"console=ttyS1,115200",
		}
		c.Smee.IPXE.HTTPScriptServer.ExtraKernelArgs = kernelArgs
		c.Smee.Backend = bk
		if err := c.Smee.Start(ctx, logger.WithName("smee")); err != nil {
			return fmt.Errorf("smee failed: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
}

// ipByInterface returns the first IPv4 address on the named network interface.
func ipByInterface(name string) netip.Addr {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ipNet.IP.To4() != nil {
			return netip.AddrFrom4([4]byte(ipNet.IP.To4()))
		}
	}

	return netip.Addr{}
}

func detectPublicIPv4() netip.Addr {
	if netint := os.Getenv("SMEE_PUBLIC_IP_INTERFACE"); netint != "" {
		if ip := ipByInterface(netint); ip.String() != "" {
			return ip
		}
	}
	ipDgw, err := autoDetectPublicIpv4WithDefaultGateway()
	if err == nil {
		return ipDgw
	}

	ip, err := autoDetectPublicIPv4()
	if err != nil {
		return netip.Addr{}
	}

	return ip
}

func autoDetectPublicIPv4() (netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unable to auto-detect public IPv4: %w", err)
	}
	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ip.IP.To4()
		if v4 == nil || !v4.IsGlobalUnicast() {
			continue
		}

		return netip.AddrFrom4([4]byte(v4.To4())), nil
	}

	return netip.Addr{}, errors.New("unable to auto-detect public IPv4")
}

// autoDetectPublicIpv4WithDefaultGateway finds the network interface with a default gateway
// and returns the first net.IP address of the first interface that has a default gateway.
func autoDetectPublicIpv4WithDefaultGateway() (netip.Addr, error) {
	// Get the list of routes from netlink
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to list routes: %v", err)
	}

	// Find the route with a default gateway (Dst == nil)
	for _, route := range routes {
		if route.Dst == nil && route.Gw != nil {
			// Get the interface associated with this route
			iface, err := net.InterfaceByIndex(route.LinkIndex)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("failed to get interface by index: %v", err)
			}

			// Get the addresses assigned to this interface
			addrs, err := iface.Addrs()
			if err != nil {
				return netip.Addr{}, fmt.Errorf("failed to get addresses for interface %v: %v", iface.Name, err)
			}

			// Return the first valid IP address found
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						return netip.AddrFrom4([4]byte(ipNet.IP.To4())), nil
					}
				}
			}
		}
	}

	return netip.Addr{}, fmt.Errorf("no default gateway found")
}
