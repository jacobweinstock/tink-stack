package main

import (
	"github.com/jacobweinstock/tink-stack/cmd/flag"
	"github.com/jacobweinstock/tink-stack/cmd/flag/config"
	"github.com/peterbourgon/ff/v4"
)

func newCLI(cfg *Config, fs *ff.FlagSet) *ff.Command {
	setFlags(cfg, fs)

	return &ff.Command{
		Name:     "tinkerbell",
		Usage:    "tinkerbell [flags]",
		LongHelp: "Tinkerbell stack.",
		Flags:    fs,
	}
}

func setFlags(c *Config, fs *ff.FlagSet) {
	// Global flags
	gfs := config.NewGlobalFlagSet()
	config.RegisterGlobal(&flag.FlagSet{FlagSet: fs}, c.Global, gfs)
	/*
		fs.StringVar(&c.LogLevel, 0, "log-level", "info", "log level (debug, info)")
		fs.StringVar(&c.Kubeconfig, 0, "kubeconfig", "~/.kube/config", "path to kubeconfig file")
		fs.StringVar(&c.Namespace, 0, "namespace", "tink-system", "namespace for all Tinkerbell resources")
		fs.StringVar(&c.PublicIPv4, 0, "public-ipv4", "", "public IPv4 address to use for all services")
	*/
	tinkControllerFlags(c, fs)
	tinkServerFlags(c, fs)
	hegelFlags(c, fs)
	smeeFlags(c, fs)
}

func tinkControllerFlags(c *Config, fs *ff.FlagSet) {
	fs.BoolVar(&c.TinkController.EnableLeaderElection, 0, "tink-enable-leader-election", "[tink controller] enable leader election")
	fs.StringVar(&c.TinkController.MetricsAddr, 0, "tink-metrics-addr", ":7070", "[tink controller] metrics bind address")
	fs.StringVar(&c.TinkController.ProbeAddr, 0, "tink-probe-addr", ":7071", "[tink controller] probe bind address")
}

func tinkServerFlags(c *Config, fs *ff.FlagSet) {
	fs.StringVar(&c.TinkServer.GRPCAuthority, 0, "tink-grpc-bind-addr", ":42113", "[tink server] GRPC bind address")
	fs.StringVar(&c.TinkServer.HTTPAuthority, 0, "tink-http-bind-addr", ":42114", "[tink server] HTTP bind address")
}

func hegelFlags(c *Config, fs *ff.FlagSet) {
	fs.StringVar(&c.Hegel.HTTPAddr, 0, "hegel-bind-addr", ":50061", "[hegel] HTTP bind address")
	fs.StringVar(&c.Hegel.TrustedProxies, 0, "hegel-trusted-proxies", "", "[hegel] comma separated list of trusted proxies in CIDR notation")
}

func smeeFlags(c *Config, fs *ff.FlagSet) {
	sfs := config.NewSmeeFlagSet()

	config.RegisterSmee(&flag.FlagSet{FlagSet: fs}, c.Smee, sfs)
}
