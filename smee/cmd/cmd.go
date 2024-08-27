package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/jacobweinstock/tink-stack/smee/dhcp/handler"
	"github.com/jacobweinstock/tink-stack/smee/dhcp/handler/proxy"
	"github.com/jacobweinstock/tink-stack/smee/dhcp/handler/reservation"
	"github.com/jacobweinstock/tink-stack/smee/dhcp/server"
	"github.com/jacobweinstock/tink-stack/smee/ipxe/http"
	"github.com/jacobweinstock/tink-stack/smee/ipxe/script"
	"github.com/jacobweinstock/tink-stack/smee/metric"
	"github.com/jacobweinstock/tink-stack/smee/otel"
	"github.com/jacobweinstock/tink-stack/smee/syslog"
	"github.com/tinkerbell/ipxedust"
	"github.com/tinkerbell/ipxedust/ihttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

var (
	// GitRev is the git revision of the build. It is set by the Makefile.
	GitRev = "unknown (use make)"

	startTime = time.Now()
)

const (
	name                         = "smee"
	dhcpModeProxy       DhcpMode = "proxy"
	dhcpModeReservation DhcpMode = "reservation"
	dhcpModeAutoProxy   DhcpMode = "auto-proxy"
)

type Service struct {
	Syslog         syslogConfig
	Tftp           tftp
	IpxeHTTPBinary ipxeHTTPBinary
	IpxeHTTPScript ipxeHTTPScript
	DHCP           dhcpConfig

	// loglevel is the log level for smee.
	LogLevel string
	Backends dhcpBackends
	Otel     otelConfig
}

type syslogConfig struct {
	Enabled  bool
	BindAddr string
	BindPort int
}

type tftp struct {
	BindAddr        string
	BindPort        int
	BlockSize       int
	Enabled         bool
	IpxeScriptPatch string
	Timeout         time.Duration
}

type ipxeHTTPBinary struct {
	Enabled bool
}

type ipxeHTTPScript struct {
	Enabled               bool
	BindAddr              string
	BindPort              int
	ExtraKernelArgs       string
	HookURL               string
	TinkServer            string
	TinkServerUseTLS      bool
	TinkServerInsecureTLS bool
	TrustedProxies        string
	Retries               int
	RetryDelay            int
}

type DhcpMode string

type dhcpConfig struct {
	Enabled           bool
	Mode              string
	BindAddr          string
	BindInterface     string
	IpForPacket       string
	SyslogIP          string
	TftpIP            string
	TftpPort          int
	HttpIpxeBinaryURL urlBuilder
	HttpIpxeScript    httpIpxeScript
	HttpIpxeScriptURL string
}

type urlBuilder struct {
	Scheme string
	Host   string
	Port   int
	Path   string
}

type httpIpxeScript struct {
	urlBuilder
	// InjectMacAddress will prepend the hardware mac address to the ipxe script URL file name.
	// For example: http://1.2.3.4/my/loc/auto.ipxe -> http://1.2.3.4/my/loc/40:15:ff:89:cc:0e/auto.ipxe
	// Setting this to false is useful when you are not using the auto.ipxe script in Smee.
	InjectMacAddress bool
}

type dhcpBackends struct {
	File       File
	Kubernetes Kube
	Noop       Noop
}

type otelConfig struct {
	Endpoint string
	Insecure bool
}

func (s *Service) Start(ctx context.Context, log logr.Logger) error {
	cfg := s

	log.Info("starting", "version", GitRev)

	oCfg := otel.Config{
		Servicename: "smee",
		Endpoint:    cfg.Otel.Endpoint,
		Insecure:    cfg.Otel.Insecure,
		Logger:      log,
	}
	ctx, otelShutdown, err := otel.Init(ctx, oCfg)
	if err != nil {
		log.Error(err, "failed to initialize OpenTelemetry")
		return err
	}
	defer otelShutdown()
	metric.Init()

	g, ctx := errgroup.WithContext(ctx)
	// syslog
	if cfg.Syslog.Enabled {
		addr := fmt.Sprintf("%s:%d", cfg.Syslog.BindAddr, cfg.Syslog.BindPort)
		log.Info("starting syslog server", "bind_addr", addr)
		g.Go(func() error {
			if err := syslog.StartReceiver(ctx, log, addr, 1); err != nil {
				log.Error(err, "syslog server failure")
				return err
			}
			<-ctx.Done()
			log.Info("syslog server stopped")
			return nil
		})
	}

	// tftp
	if cfg.Tftp.Enabled {
		tftpServer := &ipxedust.Server{
			Log:                  log.WithValues("service", "github.com/tinkerbell/smee").WithName("github.com/tinkerbell/ipxedust"),
			HTTP:                 ipxedust.ServerSpec{Disabled: true}, // disabled because below we use the http handlerfunc instead.
			EnableTFTPSinglePort: true,
		}
		tftpServer.EnableTFTPSinglePort = true
		addr := fmt.Sprintf("%s:%d", cfg.Tftp.BindAddr, cfg.Tftp.BindPort)
		if ip, err := netip.ParseAddrPort(addr); err == nil {
			tftpServer.TFTP = ipxedust.ServerSpec{
				Disabled:  false,
				Addr:      ip,
				Timeout:   cfg.Tftp.Timeout,
				Patch:     []byte(cfg.Tftp.IpxeScriptPatch),
				BlockSize: cfg.Tftp.BlockSize,
			}
			// start the ipxe binary tftp server
			log.Info("starting tftp server", "bind_addr", addr)
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
	if cfg.IpxeHTTPBinary.Enabled {
		// serve ipxe binaries from the "/ipxe/" URI.
		handlers["/ipxe/"] = ihttp.Handler{
			Log:   log.WithValues("service", "github.com/tinkerbell/smee").WithName("github.com/tinkerbell/ipxedust"),
			Patch: []byte(cfg.Tftp.IpxeScriptPatch),
		}.Handle
	}

	// http ipxe script
	if cfg.IpxeHTTPScript.Enabled {
		br, err := cfg.backend(ctx, log)
		if err != nil {
			panic(fmt.Errorf("failed to create backend: %w", err))
		}
		jh := script.Handler{
			Logger:                log,
			Backend:               br,
			OSIEURL:               cfg.IpxeHTTPScript.HookURL,
			ExtraKernelParams:     strings.Split(cfg.IpxeHTTPScript.ExtraKernelArgs, " "),
			PublicSyslogFQDN:      cfg.DHCP.SyslogIP,
			TinkServerTLS:         cfg.IpxeHTTPScript.TinkServerUseTLS,
			TinkServerInsecureTLS: cfg.IpxeHTTPScript.TinkServerInsecureTLS,
			TinkServerGRPCAddr:    cfg.IpxeHTTPScript.TinkServer,
			IPXEScriptRetries:     cfg.IpxeHTTPScript.Retries,
			IPXEScriptRetryDelay:  cfg.IpxeHTTPScript.RetryDelay,
			StaticIPXEEnabled:     (DhcpMode(cfg.DHCP.Mode) == dhcpModeAutoProxy),
		}

		// serve ipxe script from the "/" URI.
		handlers["/"] = jh.HandlerFunc()
	}

	if len(handlers) > 0 {
		// start the http server for ipxe binaries and scripts
		tp := parseTrustedProxies(cfg.IpxeHTTPScript.TrustedProxies)
		httpServer := &http.Config{
			GitRev:         GitRev,
			StartTime:      startTime,
			Logger:         log,
			TrustedProxies: tp,
		}
		bindAddr := fmt.Sprintf("%s:%d", cfg.IpxeHTTPScript.BindAddr, cfg.IpxeHTTPScript.BindPort)
		log.Info("serving http", "addr", bindAddr, "trusted_proxies", tp)
		g.Go(func() error {
			return httpServer.ServeHTTP(ctx, bindAddr, handlers)
		})
	}

	// dhcp serving
	if cfg.DHCP.Enabled {
		dh, err := cfg.dhcpHandler(ctx, log)
		if err != nil {
			log.Error(err, "failed to create dhcp listener")
			panic(fmt.Errorf("failed to create dhcp listener: %w", err))
		}
		log.Info("starting dhcp server", "bind_addr", cfg.DHCP.BindAddr)
		g.Go(func() error {
			bindAddr, err := netip.ParseAddrPort(cfg.DHCP.BindAddr)
			if err != nil {
				panic(fmt.Errorf("invalid tftp address for DHCP server: %w", err))
			}
			conn, err := server4.NewIPv4UDPConn(cfg.DHCP.BindInterface, net.UDPAddrFromAddrPort(bindAddr))
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
		return err
	}
	log.Info("smee is shutting down")
	return nil
}

func numTrue(b ...bool) int {
	n := 0
	for _, v := range b {
		if v {
			n++
		}
	}
	return n
}

func (c *Service) backend(ctx context.Context, log logr.Logger) (handler.BackendReader, error) {
	if c.Backends.File.Enabled || c.Backends.Noop.Enabled {
		// the kubernetes backend is enabled by default so we disable it
		// if another backend is enabled so that users don't have to explicitly
		// set the CLI flag to disable it when using another backend.
		c.Backends.Kubernetes.Enabled = false
	}
	var be handler.BackendReader
	switch {
	case numTrue(c.Backends.File.Enabled, c.Backends.Kubernetes.Enabled, c.Backends.Noop.Enabled) > 1:
		return nil, errors.New("only one backend can be enabled at a time")
	case c.Backends.Noop.Enabled:
		if c.DHCP.Mode != string(dhcpModeAutoProxy) {
			return nil, errors.New("noop backend can only be used with --dhcp-mode=auto-proxy")
		}
		be = c.Backends.Noop.backend()
	case c.Backends.File.Enabled:
		b, err := c.Backends.File.backend(ctx, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create file backend: %w", err)
		}
		be = b
	default: // default backend is kubernetes
		b, err := c.Backends.Kubernetes.backend(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes backend: %w", err)
		}
		be = b
	}

	return be, nil
}

func (c *Service) dhcpHandler(ctx context.Context, log logr.Logger) (server.Handler, error) {
	// 1. create the handler
	// 2. create the backend
	// 3. add the backend to the handler
	pktIP, err := netip.ParseAddr(c.DHCP.IpForPacket)
	if err != nil {
		return nil, fmt.Errorf("invalid bind address: %w", err)
	}
	tftpIP, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", c.DHCP.TftpIP, c.DHCP.TftpPort))
	if err != nil {
		return nil, fmt.Errorf("invalid tftp address for DHCP server: %w", err)
	}
	httpBinaryURL := &url.URL{
		Scheme: c.DHCP.HttpIpxeBinaryURL.Scheme,
		Host:   fmt.Sprintf("%s:%d", c.DHCP.HttpIpxeBinaryURL.Host, c.DHCP.HttpIpxeBinaryURL.Port),
		Path:   c.DHCP.HttpIpxeBinaryURL.Path,
	}
	if _, err := url.Parse(httpBinaryURL.String()); err != nil {
		return nil, fmt.Errorf("invalid http ipxe binary url: %w", err)
	}

	var httpScriptURL *url.URL
	if c.DHCP.HttpIpxeScriptURL != "" {
		httpScriptURL, err = url.Parse(c.DHCP.HttpIpxeScriptURL)
		if err != nil {
			return nil, fmt.Errorf("invalid http ipxe script url: %w", err)
		}
	} else {
		httpScriptURL = &url.URL{
			Scheme: c.DHCP.HttpIpxeScript.Scheme,
			Host: func() string {
				switch c.DHCP.HttpIpxeScript.Scheme {
				case "http":
					if c.DHCP.HttpIpxeScript.Port == 80 {
						return c.DHCP.HttpIpxeScript.Host
					}
				case "https":
					if c.DHCP.HttpIpxeScript.Port == 443 {
						return c.DHCP.HttpIpxeScript.Host
					}
				}
				return fmt.Sprintf("%s:%d", c.DHCP.HttpIpxeScript.Host, c.DHCP.HttpIpxeScript.Port)
			}(),
			Path: c.DHCP.HttpIpxeScript.Path,
		}
	}

	if _, err := url.Parse(httpScriptURL.String()); err != nil {
		return nil, fmt.Errorf("invalid http ipxe script url: %w", err)
	}
	ipxeScript := func(d *dhcpv4.DHCPv4) *url.URL {
		return httpScriptURL
	}
	if c.DHCP.HttpIpxeScript.InjectMacAddress {
		ipxeScript = func(d *dhcpv4.DHCPv4) *url.URL {
			u := *httpScriptURL
			p := path.Base(u.Path)
			u.Path = path.Join(path.Dir(u.Path), d.ClientHWAddr.String(), p)
			return &u
		}
	}
	backend, err := c.backend(ctx, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}

	switch DhcpMode(c.DHCP.Mode) {
	case dhcpModeReservation:
		syslogIP, err := netip.ParseAddr(c.DHCP.SyslogIP)
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
	case dhcpModeProxy:
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
			OTELEnabled:      true,
			AutoProxyEnabled: false,
		}
		return dh, nil
	case dhcpModeAutoProxy:
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
			OTELEnabled:      true,
			AutoProxyEnabled: true,
		}
		return dh, nil
	}

	return nil, errors.New("invalid dhcp mode")
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

func (d DhcpMode) String() string {
	return string(d)
}
