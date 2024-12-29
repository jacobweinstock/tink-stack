package config

import (
	"net/netip"
	"slices"

	"github.com/jacobweinstock/tink-stack/cmd/flag"
	ntip "github.com/jacobweinstock/tink-stack/cmd/flag/netip"
	"github.com/peterbourgon/ff/v4/ffval"
)

type GlobalConfig struct {
	LogLevel             string
	Backend              string
	BackendFilePath      string
	BackendKubeConfig    string
	BackendKubeNamespace string
	OTELEndpoint         string
	OTELInsecure         bool
	TrustedProxies       []netip.Prefix
	PublicIP             netip.Addr
}

func RegisterGlobal(fs *flag.FlagSet, gc *GlobalConfig, m flag.FlagConfigSet) {
	if m == nil {
		m = NewGlobalFlagSet()
	}

	fs.Register(m.Get(LogLevelConfig.Name), ffval.NewEnum(&gc.LogLevel, "debug", "info"))
	fs.Register(m.Get(BackendConfig.Name), ffval.NewEnum(&gc.Backend, "kube", "file", "none"))
	fs.Register(m.Get(BackendFilePath.Name), ffval.NewValueDefault(&gc.BackendFilePath, gc.BackendFilePath))
	fs.Register(m.Get(BackendKubeConfig.Name), ffval.NewValueDefault(&gc.BackendKubeConfig, gc.BackendKubeConfig))
	fs.Register(m.Get(BackendKubeNamespace.Name), ffval.NewValueDefault(&gc.BackendKubeNamespace, gc.BackendKubeNamespace))
	fs.Register(m.Get(OTELEndpoint.Name), ffval.NewValueDefault(&gc.OTELEndpoint, gc.OTELEndpoint))
	fs.Register(m.Get(OTELInsecure.Name), ffval.NewValueDefault(&gc.OTELInsecure, gc.OTELInsecure))
	fs.Register(m.Get(TrustedProxies.Name), &ntip.PrefixList{PrefixList: &gc.TrustedProxies})
	fs.Register(m.Get(PublicIP.Name), &ntip.Addr{Addr: &gc.PublicIP})
}

func NewGlobalFlagSet(disabled ...string) flag.FlagConfigSet {
	var fs flag.FlagConfigSet = flag.FlagConfigSet{
		LogLevelConfig.Name:       &LogLevelConfig,
		BackendConfig.Name:        &BackendConfig,
		BackendFilePath.Name:      &BackendFilePath,
		BackendKubeConfig.Name:    &BackendKubeConfig,
		BackendKubeNamespace.Name: &BackendKubeNamespace,
		OTELEndpoint.Name:         &OTELEndpoint,
		OTELInsecure.Name:         &OTELInsecure,
		TrustedProxies.Name:       &TrustedProxies,
		PublicIP.Name:             &PublicIP,
	}
	for _, f := range fs {
		fs[f.Name] = f
		if slices.Contains(disabled, f.Name) {
			f.Disable()
		}
	}

	return fs
}

// All these flags are used by at least two services or
// are used to create objects that are used by multiple services.

var LogLevelConfig = flag.FlagConfig{
	Name:  "log-level",
	Usage: "log level",
}

// BackendConfig flags
var BackendConfig = flag.FlagConfig{
	Name:  "backend",
	Usage: "backend to use (kube, file, none)",
}

var BackendFilePath = flag.FlagConfig{
	Name:  "backend-file-path",
	Usage: "path to the file backend",
}

var BackendKubeConfig = flag.FlagConfig{
	Name:  "backend-kube-config",
	Usage: "path to the kubeconfig file",
}

var BackendKubeNamespace = flag.FlagConfig{
	Name:  "backend-kube-namespace",
	Usage: "namespace to watch for resources",
}

// OTEL flags
var OTELEndpoint = flag.FlagConfig{
	Name:  "otel-endpoint",
	Usage: "[otel] OpenTelemetry collector endpoint",
}

var OTELInsecure = flag.FlagConfig{
	Name:  "otel-insecure",
	Usage: "[otel] OpenTelemetry collector insecure",
}

// Shared flags
var TrustedProxies = flag.FlagConfig{
	Name:  "trusted-proxies",
	Usage: "list of trusted proxies in CIDR notation",
}

var PublicIP = flag.FlagConfig{
	Name:  "public-ipv4",
	Usage: "public IPv4 address to use for all services",
}
