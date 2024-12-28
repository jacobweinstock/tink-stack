package flag

import (
	"net/netip"
	"net/url"

	ntip "github.com/jacobweinstock/tink-stack/cmd/flag/netip"
	nurl "github.com/jacobweinstock/tink-stack/cmd/flag/url"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffval"
)

type FlagConfig struct {
	Name     string
	Usage    string
	disabled bool
}

func (f *FlagConfig) Disable() {
	f.disabled = true
}

func (f *FlagConfig) Enable() {
	f.disabled = false
}

type FlagSet struct {
	*ff.FlagSet
}

func zeroVal[T any](v *T) T {
	if v != nil {
		return *v
	}
	return *new(T) // zero value of T
}

func toPtr[T any](v T) *T {
	return &v
}

// Uint16Var defines a new flag in the flag set, and panics on any error.
func (fs *FlagSet) Uint16Var(pointer *uint16, short rune, long string, def uint16, usage string) ff.Flag {
	return fs.Value(short, long, ffval.NewValueDefault(pointer, def), usage)
}

func (fs *FlagSet) AddrPortLong(long string, pointer *netip.AddrPort, usage string) ff.Flag {
	g := &ntip.AddrPort{AddrPort: pointer}

	return fs.ValueLong(long, g, usage)
}

func (fs *FlagSet) AddrLong(long string, pointer *netip.Addr, usage string) ff.Flag {
	g := &ntip.Addr{Addr: pointer}

	return fs.ValueLong(long, g, usage)
}

func (fs *FlagSet) URLLong(long string, pointer *url.URL, usage string) ff.Flag {
	u := &nurl.URL{URL: pointer}
	return fs.ValueLong(long, u, usage)
}

func (fs *FlagSet) PrefixLong(long string, pointer *netip.Prefix, usage string) ff.Flag {
	p := &ntip.Prefix{Prefix: pointer}
	return fs.ValueLong(long, p, usage)
}
