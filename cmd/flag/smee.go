package flag

import (
	"fmt"

	ntip "github.com/jacobweinstock/tink-stack/cmd/flag/netip"
	nurl "github.com/jacobweinstock/tink-stack/cmd/flag/url"
	"github.com/jacobweinstock/tink-stack/smee"
	"github.com/peterbourgon/ff/v4/ffval"
)

func RegisterSmee(fs *FlagSet, sc *smee.Config, m FlagConfigSet) {
	// DHCP flags

	fs.Register(m.Get(DHCPEnabled.Name), ffval.NewValueDefault(&sc.DHCP.Enabled, sc.DHCP.Enabled))
	fs.Register(m.Get(DHCPModeFlag.Name), &sc.DHCP.Mode)
	fs.Register(m.Get(DHCPBindAddr.Name), &ntip.AddrPort{AddrPort: &sc.DHCP.BindAddr})
	fs.Register(m.Get(DHCPBindInterface.Name), ffval.NewValueDefault(&sc.DHCP.BindInterface, sc.DHCP.BindInterface))
	fs.Register(m.Get(DHCPIPForPacket.Name), &ntip.Addr{Addr: &sc.DHCP.IPForPacket})
	fs.Register(m.Get(DHCPSyslogIP.Name), &ntip.Addr{Addr: &sc.DHCP.SyslogIP})
	fs.Register(m.Get(DHCPTftpIP.Name), &ntip.Addr{Addr: &sc.DHCP.TFTPIP})
	fs.Register(m.Get(DHCPTftpPort.Name), ffval.NewValueDefault(&sc.DHCP.TFTPPort, sc.DHCP.TFTPPort))
	fs.Register(m.Get(DHCPIPXEHTTPScriptInjectMac.Name), ffval.NewValueDefault(&sc.DHCP.IPXEHTTPScript.InjectMacAddress, sc.DHCP.IPXEHTTPScript.InjectMacAddress))

	// IPXE flags
	fs.Register(m.Get(IPXEEmbeddedScriptPatch.Name), ffval.NewValueDefault(&sc.IPXE.EmbeddedScriptPatch, sc.IPXE.EmbeddedScriptPatch))
	fs.Register(m.Get(IPXEHTTPBinaryEnabled.Name), ffval.NewValueDefault(&sc.IPXE.HTTPBinaryServer.Enabled, sc.IPXE.HTTPBinaryServer.Enabled))
	fs.Register(m.Get(IPXEHTTPScriptEnabled.Name), ffval.NewValueDefault(&sc.IPXE.HTTPScriptServer.Enabled, sc.IPXE.HTTPScriptServer.Enabled))
	fs.Register(m.Get(IPXEHTTPScriptBindAddr.Name), &ntip.Addr{Addr: &sc.IPXE.HTTPScriptServer.BindAddr})
	fs.Register(m.Get(IPXEHTTPScriptBindPort.Name), ffval.NewValueDefault(&sc.IPXE.HTTPScriptServer.BindPort, sc.IPXE.HTTPScriptServer.BindPort))
	fs.Register(m.Get(IPXEHTTPScriptExtraKernelArgs.Name), ffval.NewList(&sc.IPXE.HTTPScriptServer.ExtraKernelArgs))
	fs.Register(m.Get(IPXEHTTPScriptTrustedProxies.Name), ffval.NewList(&sc.IPXE.HTTPScriptServer.TrustedProxies))
	fs.Register(m.Get(IPXEHTTPScriptRetries.Name), ffval.NewValueDefault(&sc.IPXE.HTTPScriptServer.Retries, sc.IPXE.HTTPScriptServer.Retries))
	fs.Register(m.Get(IPXEHTTPScriptRetryDelay.Name), ffval.NewValueDefault(&sc.IPXE.HTTPScriptServer.RetryDelay, sc.IPXE.HTTPScriptServer.RetryDelay))

	// ISO Flags
	fs.Register(m.Get(ISOEnabled.Name), ffval.NewValueDefault(&sc.ISO.Enabled, sc.ISO.Enabled))
	fs.Register(m.Get(ISOUpstreamURL.Name), &nurl.URL{URL: sc.ISO.UpstreamURL})
	fs.Register(m.Get(ISOPatchMagicString.Name), ffval.NewValueDefault(&sc.ISO.PatchMagicString, sc.ISO.PatchMagicString))
	fs.Register(m.Get(ISOStaticIPAMEnabled.Name), ffval.NewValueDefault(&sc.ISO.StaticIPAMEnabled, sc.ISO.StaticIPAMEnabled))

	// Syslog Flags
	fs.Register(m.Get(SyslogEnabled.Name), ffval.NewValueDefault(&sc.Syslog.Enabled, sc.Syslog.Enabled))
	fs.Register(m.Get(SyslogBindAddr.Name), &ntip.Addr{Addr: &sc.Syslog.BindAddr})
	fs.Register(m.Get(SyslogBindPort.Name), ffval.NewValueDefault(&sc.Syslog.BindPort, sc.Syslog.BindPort))

	// TFTP Flags
	fs.Register(m.Get(TFTPServerEnabled.Name), ffval.NewValueDefault(&sc.TFTP.Enabled, sc.TFTP.Enabled))
	fs.Register(m.Get(TFTPServerBindAddr.Name), &ntip.Addr{Addr: &sc.TFTP.BindAddr})
	fs.Register(m.Get(TFTPServerBindPort.Name), ffval.NewValueDefault(&sc.TFTP.BindPort, sc.TFTP.BindPort))
	fs.Register(m.Get(TFTPTimeout.Name), ffval.NewValueDefault(&sc.TFTP.Timeout, sc.TFTP.Timeout))
	fs.Register(m.Get(TFTPBlockSize.Name), ffval.NewValueDefault(&sc.TFTP.BlockSize, sc.TFTP.BlockSize))
}

// FlagConfigSet allows for helper methods on FlagConfig's to be created.
type FlagConfigSet map[string]*FlagConfig

// NewSmeeFlagSet returns a FlagConfigSet with all the Smee flags. All flags are enabled by default.
func NewSmeeFlagSet(disabled ...string) FlagConfigSet {
	var s FlagConfigSet = FlagConfigSet{
		DHCPEnabled.Name:                   &DHCPEnabled,
		DHCPModeFlag.Name:                  &DHCPModeFlag,
		DHCPBindAddr.Name:                  &DHCPBindAddr,
		DHCPBindInterface.Name:             &DHCPBindInterface,
		DHCPIPForPacket.Name:               &DHCPIPForPacket,
		DHCPSyslogIP.Name:                  &DHCPSyslogIP,
		DHCPTftpIP.Name:                    &DHCPTftpIP,
		DHCPTftpPort.Name:                  &DHCPTftpPort,
		DHCPIPXEHTTPBinaryURLScheme.Name:   &DHCPIPXEHTTPBinaryURLScheme,
		DHCPIPXEHTTPBinaryURLHost.Name:     &DHCPIPXEHTTPBinaryURLHost,
		DHCPIPXEHTTPBinaryURLPort.Name:     &DHCPIPXEHTTPBinaryURLPort,
		DHCPIPXEHTTPBinaryURLPath.Name:     &DHCPIPXEHTTPBinaryURLPath,
		DHCPIPXEHTTPScriptScheme.Name:      &DHCPIPXEHTTPScriptScheme,
		DHCPIPXEHTTPScriptHost.Name:        &DHCPIPXEHTTPScriptHost,
		DHCPIPXEHTTPScriptPort.Name:        &DHCPIPXEHTTPScriptPort,
		DHCPIPXEHTTPScriptPath.Name:        &DHCPIPXEHTTPScriptPath,
		DHCPIPXEHTTPScriptURL.Name:         &DHCPIPXEHTTPScriptURL,
		DHCPIPXEHTTPScriptInjectMac.Name:   &DHCPIPXEHTTPScriptInjectMac,
		IPXEHTTPScriptEnabled.Name:         &IPXEHTTPScriptEnabled,
		IPXEHTTPScriptBindAddr.Name:        &IPXEHTTPScriptBindAddr,
		IPXEHTTPScriptBindPort.Name:        &IPXEHTTPScriptBindPort,
		IPXEHTTPScriptExtraKernelArgs.Name: &IPXEHTTPScriptExtraKernelArgs,
		IPXEHTTPScriptTrustedProxies.Name:  &IPXEHTTPScriptTrustedProxies,
		IPXEHTTPScriptOSIEURL.Name:         &IPXEHTTPScriptOSIEURL,
		IPXEHTTPScriptRetries.Name:         &IPXEHTTPScriptRetries,
		IPXEHTTPScriptRetryDelay.Name:      &IPXEHTTPScriptRetryDelay,
		IPXEHTTPBinaryEnabled.Name:         &IPXEHTTPBinaryEnabled,
		IPXEEmbeddedScriptPatch.Name:       &IPXEEmbeddedScriptPatch,
		SyslogEnabled.Name:                 &SyslogEnabled,
		SyslogBindAddr.Name:                &SyslogBindAddr,
		SyslogBindPort.Name:                &SyslogBindPort,
		ISOEnabled.Name:                    &ISOEnabled,
		ISOUpstreamURL.Name:                &ISOUpstreamURL,
		ISOPatchMagicString.Name:           &ISOPatchMagicString,
		ISOStaticIPAMEnabled.Name:          &ISOStaticIPAMEnabled,
		TFTPServerEnabled.Name:             &TFTPServerEnabled,
		TFTPServerBindAddr.Name:            &TFTPServerBindAddr,
		TFTPServerBindPort.Name:            &TFTPServerBindPort,
		TFTPTimeout.Name:                   &TFTPTimeout,
		TFTPBlockSize.Name:                 &TFTPBlockSize,
	}
	for _, f := range s {
		s[f.Name] = f
	}
	for _, d := range disabled {
		s.Disable(d)
	}
	return s
}

// Disable will disable a flag by name.
func (s FlagConfigSet) Disable(name string) {
	if f, ok := s[name]; ok {
		f.Disable()
	}
}

// Get will return the FlagConfig by given name.
func (s FlagConfigSet) Get(name string) FlagConfig {
	if f, ok := s[name]; ok {
		return *f
	}
	return FlagConfig{}
}

// DHCP flags
var DHCPEnabled = FlagConfig{
	Name:  "dhcp-enabled",
	Usage: "[dhcp] enable DHCP server",
}

var DHCPModeFlag = FlagConfig{
	Name:  "dhcp-mode",
	Usage: fmt.Sprintf("[dhcp] DHCP mode (%s, %s, %s)", smee.DHCPModeReservation, smee.DHCPModeProxy, smee.DHCPModeAutoProxy),
}

var DHCPBindAddr = FlagConfig{
	Name:  "dhcp-bind-addr",
	Usage: "[dhcp] DHCP server bind address",
}

var DHCPBindInterface = FlagConfig{
	Name:  "dhcp-bind-interface",
	Usage: "[dhcp] DHCP server bind interface",
}

var DHCPIPForPacket = FlagConfig{
	Name:  "dhcp-ip-for-packet",
	Usage: "[dhcp] DHCP server IP for packet",
}

var DHCPSyslogIP = FlagConfig{
	Name:  "dhcp-syslog-ip",
	Usage: "[dhcp] Syslog server IP address to use in DHCP packets (opt 7)",
}

var DHCPTftpIP = FlagConfig{
	Name:  "dhcp-tftp-ip",
	Usage: "[dhcp] TFTP server IP address to use in DHCP packets (opt 66, etc)",
}

var DHCPTftpPort = FlagConfig{
	Name:  "dhcp-tftp-port",
	Usage: "[dhcp] TFTP server port to use in DHCP packets (opt 66, etc)",
}

var DHCPIPXEHTTPBinaryURLScheme = FlagConfig{
	Name:  "dhcp-ipxe-http-binary-scheme",
	Usage: "[dhcp] HTTP iPXE binaries scheme to use in DHCP packets",
}

var DHCPIPXEHTTPBinaryURLHost = FlagConfig{
	Name:  "dhcp-ipxe-http-binary-host",
	Usage: "[dhcp] HTTP iPXE binaries host or IP to use in DHCP packets",
}

var DHCPIPXEHTTPBinaryURLPort = FlagConfig{
	Name:  "dhcp-ipxe-http-binary-port",
	Usage: "[dhcp] HTTP iPXE binaries port to use in DHCP packets",
}

var DHCPIPXEHTTPBinaryURLPath = FlagConfig{
	Name:  "dhcp-ipxe-http-binary-path",
	Usage: "[dhcp] HTTP iPXE binaries path to use in DHCP packets",
}

var DHCPIPXEHTTPScriptScheme = FlagConfig{
	Name:  "dhcp-ipxe-http-script-scheme",
	Usage: "[dhcp] HTTP iPXE script scheme to use in DHCP packets",
}

var DHCPIPXEHTTPScriptHost = FlagConfig{
	Name:  "dhcp-ipxe-http-script-host",
	Usage: "[dhcp] HTTP iPXE script host or IP to use in DHCP packets",
}

var DHCPIPXEHTTPScriptPort = FlagConfig{
	Name:  "dhcp-ipxe-http-script-port",
	Usage: "[dhcp] HTTP iPXE script port to use in DHCP packets",
}

var DHCPIPXEHTTPScriptPath = FlagConfig{
	Name:  "dhcp-ipxe-http-script-path",
	Usage: "[dhcp] HTTP iPXE script path to use in DHCP packets",
}

var DHCPIPXEHTTPScriptURL = FlagConfig{
	Name:  "dhcp-ipxe-http-script-url",
	Usage: "[dhcp] HTTP iPXE script URL to use in DHCP packets, this overrides the flags for dhcp-http-ipxe-script-{scheme, host, port, path}",
}

var DHCPIPXEHTTPScriptInjectMac = FlagConfig{
	Name:  "dhcp-ipxe-http-script-prepend-mac",
	Usage: "[dhcp] prepend the hardware MAC address to iPXE script URL base, http://1.2.3.4/auto.ipxe -> http://1.2.3.4/40:15:ff:89:cc:0e/auto.ipxe",
}

// iPXE HTTP script flags
var IPXEHTTPScriptEnabled = FlagConfig{
	Name:  "ipxe-http-script-enabled",
	Usage: "[ipxe] enable iPXE HTTP script serving",
}

var IPXEHTTPScriptBindAddr = FlagConfig{
	Name:  "ipxe-http-script-bind-addr",
	Usage: "[ipxe] local IP to listen on for iPXE HTTP script requests",
}

var IPXEHTTPScriptBindPort = FlagConfig{
	Name:  "ipxe-http-script-bind-port",
	Usage: "[ipxe] local port to listen on for iPXE HTTP script requests",
}

var IPXEHTTPScriptExtraKernelArgs = FlagConfig{
	Name:  "ipxe-http-script-extra-kernel-args",
	Usage: "[ipxe] extra set of kernel args (k=v k=v) that are appended to the kernel cmdline iPXE script",
}

var IPXEHTTPScriptTrustedProxies = FlagConfig{
	Name:  "ipxe-http-script-trusted-proxies",
	Usage: "[ipxe] comma separated list of trusted proxies in CIDR notation",
}

var IPXEHTTPScriptOSIEURL = FlagConfig{
	Name:  "ipxe-http-script-osie-url",
	Usage: "[ipxe]  URL where OSIE (HookOS) images are located",
}

var IPXEHTTPScriptRetries = FlagConfig{
	Name:  "ipxe-http-script-retries",
	Usage: "[ipxe] number of retries to attempt when fetching kernel and initrd files in the iPXE script",
}

var IPXEHTTPScriptRetryDelay = FlagConfig{
	Name:  "ipxe-http-script-retry-delay",
	Usage: "[ipxe] delay (in seconds) between retries when fetching kernel and initrd files in the iPXE script",
}

// iPXE HTTP binary flags
var IPXEHTTPBinaryEnabled = FlagConfig{
	Name:  "ipxe-http-binary-enabled",
	Usage: "[ipxe] enable iPXE HTTP binary server",
}

// TFTP flags
var TFTPServerEnabled = FlagConfig{
	Name:  "tftp-server-enabled",
	Usage: "[tftp] enable iPXE TFTP binary server",
}

var TFTPServerBindAddr = FlagConfig{
	Name:  "tftp-server-bind-addr",
	Usage: "[tftp] local IP to listen on for iPXE binary TFTP requests",
}

var TFTPServerBindPort = FlagConfig{
	Name:  "tftp-server-bind-port",
	Usage: "[tftp] local port to listen on for iPXE binary TFTP requests",
}

var TFTPTimeout = FlagConfig{
	Name:  "tftp-timeout",
	Usage: "[tftp] timeout (in seconds) for TFTP requests",
}

var TFTPBlockSize = FlagConfig{
	Name:  "tftp-block-size",
	Usage: "[tftp] TFTP block size a value between 512 (the default block size for TFTP) and 65456 (the max size a UDP packet payload can be)",
}

// iPXE flags
var IPXEEmbeddedScriptPatch = FlagConfig{
	Name:  "ipxe-embedded-script-patch",
	Usage: "[ipxe] iPXE script fragment to patch into served iPXE binaries served via TFTP or HTTP",
}

// Syslog flags
var SyslogEnabled = FlagConfig{
	Name:  "syslog-enabled",
	Usage: "[syslog] enable Syslog server(receiver)",
}

var SyslogBindAddr = FlagConfig{
	Name:  "syslog-bind-addr",
	Usage: "[syslog] local IP to listen on for Syslog messages",
}

var SyslogBindPort = FlagConfig{
	Name:  "syslog-bind-port",
	Usage: "[syslog] local port to listen on for Syslog messages",
}

var ISOEnabled = FlagConfig{
	Name:  "iso-enabled",
	Usage: "[iso] enable OSIE ISO patching server",
}

var ISOUpstreamURL = FlagConfig{
	Name:  "iso-upstream-url",
	Usage: "[iso] an ISO source URL target for patching",
}

var ISOPatchMagicString = FlagConfig{
	Name:  "iso-patch-magic-string",
	Usage: "[iso] the string pattern to match for in the source ISO, defaults to the one defined in HookOS",
}

var ISOStaticIPAMEnabled = FlagConfig{
	Name:  "iso-static-ipam-enabled",
	Usage: "[iso] enable static IPAM for OSIE (HookOS)",
}
