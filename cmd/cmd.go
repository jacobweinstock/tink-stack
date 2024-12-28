package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// defaultLogger uses the slog logr implementation.
func DefaultLogger(level string) logr.Logger {
	// source file and function can be long. This makes the logs less readable.
	// truncate source file and function to last 3 parts for improved readability.
	customAttr := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.SourceKey {
			ss, ok := a.Value.Any().(*slog.Source)
			if !ok || ss == nil {
				return a
			}
			f := strings.Split(ss.Function, "/")
			if len(f) > 3 {
				ss.Function = filepath.Join(f[len(f)-3:]...)
			}
			p := strings.Split(ss.File, "/")
			if len(p) > 3 {
				ss.File = filepath.Join(p[len(p)-3:]...)
			}

			return a
		}

		return a
	}
	opts := &slog.HandlerOptions{AddSource: true, ReplaceAttr: customAttr}
	switch level {
	case "debug":
		opts.Level = slog.LevelDebug
	default:
		opts.Level = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, opts))

	return logr.FromSlogHandler(log.Handler())
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

// ipByInterface returns the first IPv4 address on the named network interface.
func ipByInterface(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}

	return ""
}

func detectPublicIPv4() string {
	if netint := os.Getenv("SMEE_PUBLIC_IP_INTERFACE"); netint != "" {
		if ip := ipByInterface(netint); ip != "" {
			return ip
		}
	}
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
