package flag

import (
	"flag"

	"github.com/peterbourgon/ff/v4"
)

// All these flags are used by at least two services or
// are used to create objects that are used by multiple services.

var LogLevel = FlagConfig{
	Name:  "log-level",
	Usage: "log level",
}

// Backend flags
var Backend = FlagConfig{
	Name:  "backend",
	Usage: "backend to use",
}

var BackendFilePath = FlagConfig{
	Name:  "backend-file-path",
	Usage: "path to the file backend",
}

var BackendKubeConfig = FlagConfig{
	Name:  "backend-kube-config",
	Usage: "path to the kubeconfig file",
}

var BackendKubeNamespace = FlagConfig{
	Name:  "backend-kube-namespace",
	Usage: "namespace to watch for resources",
}

// OTEL flags
var OTELEndpoint = FlagConfig{
	Name:  "otel-endpoint",
	Usage: "[otel] OpenTelemetry collector endpoint",
}

var OTELInsecure = FlagConfig{
	Name:  "otel-insecure",
	Usage: "[otel] OpenTelemetry collector insecure",
}

// Shared flags
var TrustedProxies = FlagConfig{
	Name:  "trusted-proxies",
	Usage: "list of trusted proxies in CIDR notation",
}

var PublicIP = FlagConfig{
	Name:  "public-ipv4",
	Usage: "public IPv4 address to use for all services",
}

func (fs *FlagSet) Register(f FlagConfig, fv flag.Value) {
	if !f.disabled {
		fs.AddFlag(ff.FlagConfig{
			LongName: f.Name,
			Usage:    f.Usage,
			Value:    fv,
		})
	}
}
