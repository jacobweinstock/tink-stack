package netip

import (
	"fmt"
	"net/netip"
	"strings"
)

type AddrPort struct{ *netip.AddrPort }

func (a *AddrPort) Set(s string) error {
	if s == "" {
		return nil
	}
	ip, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if !ip.IsValid() && err != nil {
		return fmt.Errorf("failed to parse Addr:Port: %q", s)
	}
	*a.AddrPort = ip

	return nil
}

func (a *AddrPort) Type() string {
	return "addr:port"
}

type Addr struct{ *netip.Addr }

func (a *Addr) Set(s string) error {
	if s == "" {
		return nil
	}
	ip, err := netip.ParseAddr(s)
	if !ip.IsValid() && err != nil {
		return fmt.Errorf("failed to parse Address: %q", s)
	}
	*a.Addr = ip

	return nil
}

func (a *Addr) Type() string {
	return "addr"
}

type Prefix struct{ *netip.Prefix }

func (p *Prefix) Set(s string) error {
	if s == "" {
		return nil
	}
	ip, err := netip.ParsePrefix(s)
	if !ip.IsValid() && err != nil {
		return fmt.Errorf("failed to parse Prefix: %q", s)
	}
	*p.Prefix = ip

	return nil
}

func (p *Prefix) Type() string {
	return "prefix"
}
