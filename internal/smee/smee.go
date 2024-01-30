package smee

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/jacobweinstock/tink-stack/internal/smee/backend/kube"
	"github.com/jacobweinstock/tink-stack/internal/smee/dhcp/handler"
	"github.com/jacobweinstock/tink-stack/internal/smee/dhcp/handler/proxy"
	"github.com/jacobweinstock/tink-stack/internal/smee/dhcp/handler/reservation"
	"github.com/jacobweinstock/tink-stack/internal/smee/dhcp/server"
	"github.com/jacobweinstock/tink-stack/internal/smee/ipxe/http"
	"github.com/jacobweinstock/tink-stack/internal/smee/ipxe/script"
	"github.com/jacobweinstock/tink-stack/internal/smee/metric"
	"github.com/jacobweinstock/tink-stack/internal/smee/syslog"
	"github.com/pkg/errors"
	"github.com/tinkerbell/ipxedust"
	"github.com/tinkerbell/ipxedust/ihttp"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	// GitRev is the git revision of the build. It is set by the Makefile.
	GitRev = "unknown (use make)"

	startTime = time.Now()
)

type Service struct {
	Syslog         SyslogConfig
	Tftp           Tftp
	IpxeHTTPBinary IpxeHTTPBinary
	IpxeHTTPScript IpxeHTTPScript
	Dhcp           DhcpConfig

	// loglevel is the log level for smee.
	LogLevel string
	Backends DhcpBackends
	Logger   logr.Logger
}

type SyslogConfig struct {
	Enabled  bool
	BindAddr string
}

type Tftp struct {
	BindAddr        string
	BlockSize       int
	Enabled         bool
	IpxeScriptPatch string
	Timeout         time.Duration
}

type IpxeHTTPBinary struct {
	Enabled bool
}

type IpxeHTTPScript struct {
	Enabled                       bool
	BindAddr                      string
	ExtraKernelArgs               string
	HookURL                       string
	TinkServer                    string
	TinkServerUseTLS              bool
	TrustedProxies                string
	DisableDiscoverTrustedProxies bool
}

type DhcpConfig struct {
	Enabled           bool
	Mode              string
	BindAddr          string
	BindInterface     string
	IpForPacket       string
	SyslogIP          string
	TftpIP            string
	HttpIpxeBinaryURL string
	HttpIpxeScript    HttpIpxeScript
}

type HttpIpxeScript struct {
	Url string
	// injectMacAddress will prepend the hardware mac address to the ipxe script URL file name.
	// For example: http://1.2.3.4/my/loc/auto.ipxe -> http://1.2.3.4/my/loc/40:15:ff:89:cc:0e/auto.ipxe
	// Setting this to false is useful when you are not using the auto.ipxe script in Smee.
	InjectMacAddress bool
}

type DhcpBackends struct {
	Kubernetes Kube
}

type Kube struct {
	// ConfigFilePath is the path to a kubernetes config file (kubeconfig).
	ConfigFilePath string
	// APIURL is the Kubernetes API URL.
	APIURL string
	// Namespace is an override for the Namespace the kubernetes client will watch.
	// The default is the Namespace the pod is running in.
	Namespace string
	Enabled   bool
}
type File struct {
	// FilePath is the path to a JSON FilePath containing hardware data.
	FilePath string
	Enabled  bool
}

func (s Service) Start(ctx context.Context) error {
	metric.Init()

	log := s.Logger
	g, ctx := errgroup.WithContext(ctx)
	// syslog
	if s.Syslog.Enabled {
		log.Info("starting syslog server", "bind_addr", s.Syslog.BindAddr)
		g.Go(func() error {
			if err := syslog.StartReceiver(ctx, log, s.Syslog.BindAddr, 1); err != nil {
				log.Error(err, "syslog server failure")
				return err
			}
			<-ctx.Done()
			log.Info("syslog server stopped")
			return nil
		})
	}

	// tftp
	if s.Tftp.Enabled {
		tftpServer := &ipxedust.Server{
			Log:                  log.WithValues("service", "github.com/tinkerbell/smee").WithName("github.com/tinkerbell/ipxedust"),
			HTTP:                 ipxedust.ServerSpec{Disabled: true}, // disabled because below we use the http handlerfunc instead.
			EnableTFTPSinglePort: true,
		}
		tftpServer.EnableTFTPSinglePort = true
		if ip, err := netip.ParseAddrPort(s.Tftp.BindAddr); err == nil {
			tftpServer.TFTP = ipxedust.ServerSpec{
				Disabled:  false,
				Addr:      ip,
				Timeout:   s.Tftp.Timeout,
				Patch:     []byte(s.Tftp.IpxeScriptPatch),
				BlockSize: s.Tftp.BlockSize,
			}
			// start the ipxe binary tftp server
			log.Info("starting tftp server", "bind_addr", s.Tftp.BindAddr)
			g.Go(func() error {
				return tftpServer.ListenAndServe(ctx)
			})
		} else {
			log.Error(err, "invalid bind address")
			panic(fmt.Errorf("invalid bind address: %w", err))
		}
	}

	handlers := http.HandlerMapping{}
	// http ipxe binaries
	if s.IpxeHTTPBinary.Enabled {
		// serve ipxe binaries from the "/ipxe/" URI.
		handlers["/ipxe/"] = ihttp.Handler{
			Log:   log.WithValues("service", "github.com/tinkerbell/smee").WithName("github.com/tinkerbell/ipxedust"),
			Patch: []byte(s.Tftp.IpxeScriptPatch),
		}.Handle
	}

	// http ipxe script
	if s.IpxeHTTPScript.Enabled {
		var br handler.BackendReader
		b, err := s.Backends.Kubernetes.backend(ctx)
		if err != nil {
			panic(fmt.Errorf("failed to run kubernetes backend: %w", err))
		}
		br = b

		jh := script.Handler{
			Logger:             log,
			Backend:            br,
			OSIEURL:            s.IpxeHTTPScript.HookURL,
			ExtraKernelParams:  strings.Split(s.IpxeHTTPScript.ExtraKernelArgs, " "),
			PublicSyslogFQDN:   s.Dhcp.SyslogIP,
			TinkServerTLS:      s.IpxeHTTPScript.TinkServerUseTLS,
			TinkServerGRPCAddr: s.IpxeHTTPScript.TinkServer,
		}
		// serve ipxe script from the "/" URI.
		handlers["/"] = jh.HandlerFunc()
	}

	if len(handlers) > 0 {
		// start the http server for ipxe binaries and scripts
		tp := parseTrustedProxies(s.IpxeHTTPScript.TrustedProxies)
		httpServer := &http.Config{
			GitRev:         GitRev,
			StartTime:      startTime,
			Logger:         log,
			TrustedProxies: tp,
		}
		log.Info("serving http", "addr", s.IpxeHTTPScript.BindAddr, "trusted_proxies", tp)
		g.Go(func() error {
			return httpServer.ServeHTTP(ctx, s.IpxeHTTPScript.BindAddr, handlers)
		})
	}

	// dhcp serving
	if s.Dhcp.Enabled {
		dh, err := s.dhcpHandler(ctx, log)
		if err != nil {
			log.Error(err, "failed to create dhcp listener")
			panic(fmt.Errorf("failed to create dhcp listener: %w", err))
		}
		log.Info("starting dhcp server", "bind_addr", s.Dhcp.BindAddr)
		g.Go(func() error {
			bindAddr, err := netip.ParseAddrPort(s.Dhcp.BindAddr)
			if err != nil {
				panic(fmt.Errorf("invalid tftp address for DHCP server: %w", err))
			}
			conn, err := server4.NewIPv4UDPConn(s.Dhcp.BindInterface, net.UDPAddrFromAddrPort(bindAddr))
			if err != nil {
				panic(err)
			}
			defer conn.Close()
			ds := &server.DHCP{Logger: log, Conn: conn, Handlers: []server.Handler{dh}}

			return ds.Serve(ctx)
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Error(err, "failed running all Smee services")
		panic(err)
	}
	return nil
}

func (c *Service) dhcpHandler(ctx context.Context, log logr.Logger) (server.Handler, error) {
	// 1. create the handler
	// 2. create the backend
	// 3. add the backend to the handler
	pktIP, err := netip.ParseAddr(c.Dhcp.IpForPacket)
	if err != nil {
		return nil, fmt.Errorf("invalid bind address: %w", err)
	}
	tftpIP, err := netip.ParseAddrPort(c.Dhcp.TftpIP)
	if err != nil {
		return nil, fmt.Errorf("invalid tftp address for DHCP server: %w", err)
	}
	httpBinaryURL, err := url.Parse(c.Dhcp.HttpIpxeBinaryURL)
	if err != nil || httpBinaryURL == nil {
		return nil, fmt.Errorf("invalid http ipxe binary url: %w", err)
	}
	httpScriptURL, err := url.Parse(c.Dhcp.HttpIpxeScript.Url)
	if err != nil || httpScriptURL == nil {
		return nil, fmt.Errorf("invalid http ipxe script url: %w", err)
	}
	ipxeScript := func(d *dhcpv4.DHCPv4) *url.URL {
		return httpScriptURL
	}
	if c.Dhcp.HttpIpxeScript.InjectMacAddress {
		ipxeScript = func(d *dhcpv4.DHCPv4) *url.URL {
			u := *httpScriptURL
			p := path.Base(u.Path)
			u.Path = path.Join(path.Dir(u.Path), d.ClientHWAddr.String(), p)
			return &u
		}
	}
	var backend handler.BackendReader
	b, err := c.Backends.Kubernetes.backend(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes backend: %w", err)
	}
	backend = b
	switch c.Dhcp.Mode {
	case "reservation":
		syslogIP, err := netip.ParseAddr(c.Dhcp.SyslogIP)
		if err != nil {
			return nil, fmt.Errorf("invalid syslog address: %w", err)
		}
		dh := &reservation.Handler{
			Backend: backend,
			IPAddr:  pktIP,
			Log:     log,
			Netboot: reservation.Netboot{
				IPXEBinServerTFTP: tftpIP,
				IPXEBinServerHTTP: httpBinaryURL,
				IPXEScriptURL:     ipxeScript,
				Enabled:           true,
			},
			OTELEnabled: true,
			SyslogAddr:  syslogIP,
		}
		return dh, nil
	case "proxy":
		dh := &proxy.Handler{
			Backend: backend,
			IPAddr:  pktIP,
			Log:     log,
			Netboot: proxy.Netboot{
				IPXEBinServerTFTP: tftpIP,
				IPXEBinServerHTTP: httpBinaryURL,
				IPXEScriptURL:     ipxeScript,
				Enabled:           true,
			},
			OTELEnabled: true,
		}
		return dh, nil
	}

	return nil, errors.New("invalid dhcp mode")
}

func parseTrustedProxies(trustedProxies string) (result []string) {
	for _, cidr := range strings.Split(trustedProxies, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			// Its not a cidr, but maybe its an IP
			if ip := net.ParseIP(cidr); ip != nil {
				if ip.To4() != nil {
					cidr += "/32"
				} else {
					cidr += "/128"
				}
			} else {
				// not an IP, panic
				panic("invalid ip cidr in TRUSTED_PROXIES cidr=" + cidr)
			}
		}
		result = append(result, cidr)
	}

	return result
}

func (k *Kube) backend(ctx context.Context) (handler.BackendReader, error) {
	config, err := k.getClient()
	if err != nil {
		return nil, err
	}

	kb, err := kube.NewBackend(config)
	if err != nil {
		return nil, err
	}

	go func() {
		err = kb.Start(ctx)
		if err != nil {
			panic(err)
		}
	}()

	return kb, nil
}

func (k *Kube) getClient() (*rest.Config, error) {
	ccfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{
			ExplicitPath: k.ConfigFilePath,
		},
		&clientcmd.ConfigOverrides{
			ClusterInfo: clientcmdapi.Cluster{
				Server: k.APIURL,
			},
			Context: clientcmdapi.Context{
				Namespace: k.Namespace,
			},
		},
	)

	config, err := ccfg.ClientConfig()
	if err != nil {
		return nil, err
	}

	return config, nil
}
