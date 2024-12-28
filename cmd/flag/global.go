package flag

var LogLevel = FlagConfig{
	Name:  "log-level",
	Usage: "log level (debug, info)",
}

func (f *FlagSet) LogLevel(dest *string) {
	f.StringEnumVar(dest, 0, LogLevel.Name, LogLevel.Usage, "info", "debug")
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
