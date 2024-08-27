package cmd

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"

	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/vishvananda/netlink"
)

// customUsageFunc is a custom UsageFunc used for all commands.
func customUsageFunc(c *ffcli.Command) string {
	var b strings.Builder

	if c.LongHelp != "" {
		fmt.Fprintf(&b, "%s\n\n", c.LongHelp)
	}

	fmt.Fprintf(&b, "USAGE\n")
	if c.ShortUsage != "" {
		fmt.Fprintf(&b, "  %s\n", c.ShortUsage)
	} else {
		fmt.Fprintf(&b, "  %s\n", c.Name)
	}
	fmt.Fprintf(&b, "\n")

	if len(c.Subcommands) > 0 {
		fmt.Fprintf(&b, "SUBCOMMANDS\n")
		tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
		for _, subcommand := range c.Subcommands {
			fmt.Fprintf(tw, "  %s\t%s\n", subcommand.Name, subcommand.ShortHelp)
		}
		tw.Flush()
		fmt.Fprintf(&b, "\n")
	}

	if countFlags(c.FlagSet) > 0 {
		fmt.Fprintf(&b, "FLAGS\n")
		tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
		type flagUsage struct {
			name         string
			usage        string
			defaultValue string
		}
		flags := []flagUsage{}
		c.FlagSet.VisitAll(func(f *flag.Flag) {
			f1 := flagUsage{name: f.Name, usage: f.Usage, defaultValue: f.DefValue}
			flags = append(flags, f1)
		})

		sort.SliceStable(flags, func(i, j int) bool {
			// sort by the service name between the brackets "[]" found in the usage string.
			r := regexp.MustCompile(`^\[(.*?)\]`)
			return r.FindString(flags[i].usage) < r.FindString(flags[j].usage)
		})
		for _, elem := range flags {
			if elem.defaultValue != "" {
				fmt.Fprintf(tw, "  -%s\t%s (default %q)\n", elem.name, elem.usage, elem.defaultValue)
			} else {
				fmt.Fprintf(tw, "  -%s\t%s\n", elem.name, elem.usage)
			}
		}
		tw.Flush()
		fmt.Fprintf(&b, "\n")
	}

	return strings.TrimSpace(b.String()) + "\n"
}

func countFlags(fs *flag.FlagSet) (n int) {
	fs.VisitAll(func(*flag.Flag) { n++ })

	return n
}

func syslogFlags(c *Service, fs *flag.FlagSet) {
	fs.BoolVar(&c.Syslog.Enabled, "syslog-enabled", true, "[syslog] enable Syslog server(receiver)")
	fs.StringVar(&c.Syslog.BindAddr, "syslog-addr", detectPublicIPv4(), "[syslog] local IP to listen on for Syslog messages")
	fs.IntVar(&c.Syslog.BindPort, "syslog-port", 514, "[syslog] local port to listen on for Syslog messages")
}

func tftpFlags(c *Service, fs *flag.FlagSet) {
	fs.BoolVar(&c.Tftp.Enabled, "tftp-enabled", true, "[tftp] enable iPXE TFTP binary server)")
	fs.StringVar(&c.Tftp.BindAddr, "tftp-addr", detectPublicIPv4(), "[tftp] local IP to listen on for iPXE TFTP binary requests")
	fs.IntVar(&c.Tftp.BindPort, "tftp-port", 69, "[tftp] local port to listen on for iPXE TFTP binary requests")
	fs.DurationVar(&c.Tftp.Timeout, "tftp-timeout", time.Second*5, "[tftp] iPXE TFTP binary server requests timeout")
	fs.StringVar(&c.Tftp.IpxeScriptPatch, "ipxe-script-patch", "", "[tftp/http] iPXE script fragment to patch into served iPXE binaries served via TFTP or HTTP")
	fs.IntVar(&c.Tftp.BlockSize, "tftp-block-size", 512, "[tftp] TFTP block size a value between 512 (the default block size for TFTP) and 65456 (the max size a UDP packet payload can be)")
}

func ipxeHTTPBinaryFlags(c *Service, fs *flag.FlagSet) {
	fs.BoolVar(&c.IpxeHTTPBinary.Enabled, "http-ipxe-binary-enabled", true, "[http] enable iPXE HTTP binary server")
}

func ipxeHTTPScriptFlags(c *Service, fs *flag.FlagSet) {
	fs.BoolVar(&c.IpxeHTTPScript.Enabled, "http-ipxe-script-enabled", true, "[http] enable iPXE HTTP script server")
	fs.StringVar(&c.IpxeHTTPScript.BindAddr, "http-addr", detectPublicIPv4(), "[http] local IP to listen on for iPXE HTTP script requests")
	fs.IntVar(&c.IpxeHTTPScript.BindPort, "http-port", 8080, "[http] local port to listen on for iPXE HTTP script requests")
	fs.StringVar(&c.IpxeHTTPScript.ExtraKernelArgs, "extra-kernel-args", "", "[http] extra set of kernel args (k=v k=v) that are appended to the kernel cmdline iPXE script")
	fs.StringVar(&c.IpxeHTTPScript.TrustedProxies, "trusted-proxies", "", "[http] comma separated list of trusted proxies in CIDR notation")
	fs.StringVar(&c.IpxeHTTPScript.HookURL, "osie-url", "", "[http] URL where OSIE (HookOS) images are located")
	fs.StringVar(&c.IpxeHTTPScript.TinkServer, "tink-server", "", "[http] IP:Port for the Tink server")
	fs.BoolVar(&c.IpxeHTTPScript.TinkServerUseTLS, "tink-server-tls", false, "[http] use TLS for Tink server")
	fs.BoolVar(&c.IpxeHTTPScript.TinkServerInsecureTLS, "tink-server-insecure-tls", false, "[http] use insecure TLS for Tink server")
	fs.IntVar(&c.IpxeHTTPScript.Retries, "ipxe-script-retries", 0, "[http] number of retries to attempt when fetching kernel and initrd files in the iPXE script")
	fs.IntVar(&c.IpxeHTTPScript.RetryDelay, "ipxe-script-retry-delay", 2, "[http] delay (in seconds) between retries when fetching kernel and initrd files in the iPXE script")
}

func dhcpFlags(c *Service, fs *flag.FlagSet) {
	fs.BoolVar(&c.DHCP.Enabled, "dhcp-enabled", true, "[dhcp] enable DHCP server")
	fs.StringVar(&c.DHCP.Mode, "dhcp-mode", dhcpModeReservation.String(), fmt.Sprintf("[dhcp] DHCP mode (%s, %s, %s)", dhcpModeReservation, dhcpModeProxy, dhcpModeAutoProxy))
	fs.StringVar(&c.DHCP.BindAddr, "dhcp-addr", "0.0.0.0:67", "[dhcp] local IP:Port to listen on for DHCP requests")
	fs.StringVar(&c.DHCP.BindInterface, "dhcp-iface", "", "[dhcp] interface to bind to for DHCP requests")
	fs.StringVar(&c.DHCP.IpForPacket, "dhcp-ip-for-packet", detectPublicIPv4(), "[dhcp] IP address to use in DHCP packets (opt 54, etc)")
	fs.StringVar(&c.DHCP.SyslogIP, "dhcp-syslog-ip", detectPublicIPv4(), "[dhcp] Syslog server IP address to use in DHCP packets (opt 7)")
	fs.StringVar(&c.DHCP.TftpIP, "dhcp-tftp-ip", detectPublicIPv4(), "[dhcp] TFTP server IP address to use in DHCP packets (opt 66, etc)")
	fs.IntVar(&c.DHCP.TftpPort, "dhcp-tftp-port", 69, "[dhcp] TFTP server port to use in DHCP packets (opt 66, etc)")
	fs.StringVar(&c.DHCP.HttpIpxeBinaryURL.Scheme, "dhcp-http-ipxe-binary-scheme", "http", "[dhcp] HTTP iPXE binaries scheme to use in DHCP packets")
	fs.StringVar(&c.DHCP.HttpIpxeBinaryURL.Host, "dhcp-http-ipxe-binary-host", detectPublicIPv4(), "[dhcp] HTTP iPXE binaries host or IP to use in DHCP packets")
	fs.IntVar(&c.DHCP.HttpIpxeBinaryURL.Port, "dhcp-http-ipxe-binary-port", 8080, "[dhcp] HTTP iPXE binaries port to use in DHCP packets")
	fs.StringVar(&c.DHCP.HttpIpxeBinaryURL.Path, "dhcp-http-ipxe-binary-path", "/ipxe/", "[dhcp] HTTP iPXE binaries path to use in DHCP packets")
	fs.StringVar(&c.DHCP.HttpIpxeScript.Scheme, "dhcp-http-ipxe-script-scheme", "http", "[dhcp] HTTP iPXE script scheme to use in DHCP packets")
	fs.StringVar(&c.DHCP.HttpIpxeScript.Host, "dhcp-http-ipxe-script-host", detectPublicIPv4(), "[dhcp] HTTP iPXE script host or IP to use in DHCP packets")
	fs.IntVar(&c.DHCP.HttpIpxeScript.Port, "dhcp-http-ipxe-script-port", 8080, "[dhcp] HTTP iPXE script port to use in DHCP packets")
	fs.StringVar(&c.DHCP.HttpIpxeScript.Path, "dhcp-http-ipxe-script-path", "/auto.ipxe", "[dhcp] HTTP iPXE script path to use in DHCP packets")
	fs.StringVar(&c.DHCP.HttpIpxeScriptURL, "dhcp-http-ipxe-script-url", "", "[dhcp] HTTP iPXE script URL to use in DHCP packets, this overrides the flags for dhcp-http-ipxe-script-{scheme, host, port, path}")
	fs.BoolVar(&c.DHCP.HttpIpxeScript.InjectMacAddress, "dhcp-http-ipxe-script-prepend-mac", true, "[dhcp] prepend the hardware MAC address to iPXE script URL base, http://1.2.3.4/auto.ipxe -> http://1.2.3.4/40:15:ff:89:cc:0e/auto.ipxe")
}

func backendFlags(c *Service, fs *flag.FlagSet) {
	fs.BoolVar(&c.Backends.File.Enabled, "backend-file-enabled", false, "[backend] enable the file backend for DHCP and the HTTP iPXE script")
	fs.StringVar(&c.Backends.File.FilePath, "backend-file-path", "", "[backend] the hardware yaml file path for the file backend")
	fs.BoolVar(&c.Backends.Kubernetes.Enabled, "backend-kube-enabled", true, "[backend] enable the kubernetes backend for DHCP and the HTTP iPXE script")
	fs.StringVar(&c.Backends.Kubernetes.ConfigFilePath, "backend-kube-config", "", "[backend] the Kubernetes config file location, kube backend only")
	fs.StringVar(&c.Backends.Kubernetes.APIURL, "backend-kube-api", "", "[backend] the Kubernetes API URL, used for in-cluster client construction, kube backend only")
	fs.StringVar(&c.Backends.Kubernetes.Namespace, "backend-kube-namespace", "", "[backend] an optional Kubernetes namespace override to query hardware data from, kube backend only")
	fs.BoolVar(&c.Backends.Noop.Enabled, "backend-noop-enabled", false, "[backend] enable the noop backend for DHCP and the HTTP iPXE script")
}

func otelFlags(c *Service, fs *flag.FlagSet) {
	fs.StringVar(&c.Otel.Endpoint, "otel-endpoint", "", "[otel] OpenTelemetry collector endpoint")
	fs.BoolVar(&c.Otel.Insecure, "otel-insecure", true, "[otel] OpenTelemetry collector insecure")
}

func SetFlags(c *Service, fs *flag.FlagSet) {
	//fs.StringVar(&c.logLevel, "log-level", "info", "log level (debug, info)")
	dhcpFlags(c, fs)
	tftpFlags(c, fs)
	ipxeHTTPBinaryFlags(c, fs)
	ipxeHTTPScriptFlags(c, fs)
	syslogFlags(c, fs)
	backendFlags(c, fs)
	otelFlags(c, fs)
}

func newCLI(cfg *Service, fs *flag.FlagSet) *ffcli.Command {
	SetFlags(cfg, fs)
	return &ffcli.Command{
		Name:       name,
		ShortUsage: "smee [flags]",
		LongHelp:   "Smee is the DHCP and Network boot service for use in the Tinkerbell stack.",
		FlagSet:    fs,
		Options:    []ff.Option{ff.WithEnvVarPrefix(name)},
		UsageFunc:  customUsageFunc,
	}
}

func detectPublicIPv4() string {
	ipDgw, err := autoDetectPublicIpv4WithDefaultGateway()
	if err == nil {
		return ipDgw.String()
	}

	ip, err := autoDetectPublicIPv4()
	if err != nil {
		return ""
	}

	return ip.String()
}

func autoDetectPublicIPv4() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("unable to auto-detect public IPv4: %w", err)
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

		return v4, nil
	}

	return nil, errors.New("unable to auto-detect public IPv4")
}

// autoDetectPublicIpv4WithDefaultGateway finds the network interface with a default gateway
// and returns the first net.IP address of the first interface that has a default gateway.
func autoDetectPublicIpv4WithDefaultGateway() (net.IP, error) {
	// Get the list of routes from netlink
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	// Find the route with a default gateway (Dst == nil)
	for _, route := range routes {
		if route.Dst == nil && route.Gw != nil {
			// Get the interface associated with this route
			iface, err := net.InterfaceByIndex(route.LinkIndex)
			if err != nil {
				return nil, fmt.Errorf("failed to get interface by index: %v", err)
			}

			// Get the addresses assigned to this interface
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, fmt.Errorf("failed to get addresses for interface %v: %v", iface.Name, err)
			}

			// Return the first valid IP address found
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						return ipNet.IP, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no default gateway found")
}