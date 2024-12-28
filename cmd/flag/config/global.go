package config

import "github.com/jacobweinstock/tink-stack/cmd/flag"

// All these flags are used by at least two services or
// are used to create objects that are used by multiple services.

var LogLevel = flag.FlagConfig{
	Name:  "log-level",
	Usage: "log level",
}

// Backend flags
var Backend = flag.FlagConfig{
	Name:  "backend",
	Usage: "backend to use",
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
