package flag

import (
	"fmt"
	"net/netip"
	"strings"
)

type AddrPort struct{ netip.AddrPort }

func (a *AddrPort) Set(s string) error {
	if s == "" {
		return nil
	}
	ip, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if !ip.IsValid() && err != nil {
		return fmt.Errorf("failed to parse IP:Port: %q", s)
	}
	*a = AddrPort{ip}
	return nil
}

func (a *AddrPort) Type() string {
	return "addr:port"
}

type Addr struct{ netip.Addr }

func (a *Addr) String() string { return a.String() }
func (a *Addr) Set(s string) error {
	if s == "" {
		return nil
	}
	ip, err := netip.ParseAddr(s)
	if !ip.IsValid() && err != nil {
		return fmt.Errorf("failed to parse IP: %q", s)
	}
	*a = Addr{ip}
	return nil
}

func (a *Addr) Type() string {
	return "addr"
}

var (
	DHCPModeProxy       DHCPMode = "proxy"
	DHCPModeReservation DHCPMode = "reservation"
	DHCPModeAutoProxy   DHCPMode = "auto-proxy"
)

type DHCPMode string

func (d DHCPMode) String() string {
	return string(d)
}

func (d *DHCPMode) Set(s string) error {
	switch strings.ToLower(s) {
	case string(DHCPModeProxy), string(DHCPModeReservation), string(DHCPModeAutoProxy):
		*d = DHCPMode(s)
		return nil
	default:
		return fmt.Errorf("invalid DHCP mode: %q, must be one of [%s, %s, %s]", s, DHCPModeReservation, DHCPModeProxy, DHCPModeAutoProxy)
	}
}

func (d *DHCPMode) Type() string {
	return "dhcp-mode"
}
