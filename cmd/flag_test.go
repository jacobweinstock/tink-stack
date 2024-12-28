package cmd

import (
	"net/netip"
	"testing"

	"github.com/jacobweinstock/tink-stack/cmd/flag"
	"github.com/jacobweinstock/tink-stack/cmd/flag/smee"
	sme "github.com/jacobweinstock/tink-stack/smee"
	ffv4 "github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

func TestXxx(t *testing.T) {
	fs := &flag.FlagSet{FlagSet: ffv4.NewFlagSet("Tinkerbell")}
	sc := &sme.Config{
		DHCP: sme.DHCP{
			BindAddr:    netip.MustParseAddrPort("0.0.0.0:67"),
			IPForPacket: netip.MustParseAddr("127.0.0.1"),
			Mode:        sme.DHCPModeReservation,
			TFTPPort:    69,
		},
	}
	smee.RegisterFlags(fs, sc)

	// fs.StringEnumVar(&cfg.LogLevel, 0, flag.LogLevel.Name, flag.LogLevel.Usage, "info", "debug")

	cc := &ffv4.Command{
		Name:        "Tinkerbell",
		Usage:       "tinkerbell [FLAGS] subcmd [FLAGS]",
		ShortHelp:   "",
		LongHelp:    "",
		Flags:       fs,
		Subcommands: []*ffv4.Command{},
	}
	if err := cc.Parse([]string{
		"--dhcp-ip-for-packet", "127.1.1.4",
		"--dhcp-mode", "auto-proxy",
		"--dhcp-bind-interface", "eno1",
		"--dhcp-bind-addr", "5.5.5.5:78",
		"--dhcp-tftp-ports", "9000",
	}); err != nil {
		t.Log(err)
		t.Logf("\n%v", ffhelp.Command(cc))
		t.Fatal()
	}

	// t.Logf("log level: %s", cfg.LogLevel)
	t.Logf("bind addr: %s", sc.DHCP.BindAddr.String())
	t.Logf("ip for packet: %s", sc.DHCP.IPForPacket.String())
	t.Logf("dhcp mode: %s", sc.DHCP.Mode.String())
	t.Logf("dhcp interface: %s", sc.DHCP.BindInterface)
	t.Logf("dhcp tftp port: %d", sc.DHCP.TFTPPort)
	t.Logf("sc: %+v", sc)

	t.Fail()
}
