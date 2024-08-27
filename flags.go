package main

import (
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/jacobweinstock/tink-stack/smee/cmd"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func newCLI(cfg *Config, fs *flag.FlagSet) *ffcli.Command {
	setFlags(cfg, fs)
	return &ffcli.Command{
		Name:       "tinkerbell",
		ShortUsage: "tinkerbell [flags]",
		LongHelp:   "Tinkerbell stack.",
		FlagSet:    fs,
		Options:    []ff.Option{ff.WithEnvVarPrefix("tinkerbell")},
		UsageFunc:  customUsageFunc,
	}
}

func setFlags(c *Config, fs *flag.FlagSet) {
	// Global flags
	fs.StringVar(&c.LogLevel, "log-level", "info", "log level (debug, info)")
	fs.StringVar(&c.Kubeconfig, "kubeconfig", "admin.kubeconfig", "path to kubeconfig file")
	fs.StringVar(&c.Namespace, "namespace", "tink-system", "namespace for all Tinkerbell resources")
	fs.StringVar(&c.PublicIPv4, "public-ipv4", "", "public IPv4 address to use for all services")

	tinkControllerFlags(c, fs)
	tinkServerFlags(c, fs)
	hegelFlags(c, fs)
	smeeFlags(c, fs)
}

func tinkControllerFlags(c *Config, fs *flag.FlagSet) {
	fs.BoolVar(&c.TinkController.EnableLeaderElection, "tink-enable-leader-election", false, "[tink controller] enable leader election")
	fs.StringVar(&c.TinkController.MetricsAddr, "tink-metrics-addr", ":7070", "[tink controller] metrics bind address")
	fs.StringVar(&c.TinkController.ProbeAddr, "tink-probe-addr", ":7071", "[tink controller] probe bind address")
}

func tinkServerFlags(c *Config, fs *flag.FlagSet) {
	fs.StringVar(&c.TinkServer.GRPCAuthority, "tink-grpc-bind-addr", ":42113", "[tink server] GRPC bind address")
	fs.StringVar(&c.TinkServer.HTTPAuthority, "tink-http-bind-addr", ":42114", "[tink server] HTTP bind address")
}

func hegelFlags(c *Config, fs *flag.FlagSet) {
	fs.StringVar(&c.Hegel.HTTPAddr, "hegel-bind-addr", ":50061", "[hegel] HTTP bind address")
	fs.StringVar(&c.Hegel.TrustedProxies, "hegel-trusted-proxies", "", "[hegel] comma separated list of trusted proxies in CIDR notation")
}

func smeeFlags(c *Config, fs *flag.FlagSet) {
	cmd.SetFlags(c.Smee, fs)
}

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
