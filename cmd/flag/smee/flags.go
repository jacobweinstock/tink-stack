package smee

import (
	"fmt"

	"github.com/jacobweinstock/tink-stack/cmd/flag"
	"github.com/jacobweinstock/tink-stack/smee"
)

// DHCP flags
var DHCPEnabled = flag.FlagConfig{
	Name:  "dhcp-enabled",
	Usage: "[dhcp] enable DHCP server",
}

var DHCPModeFlag = flag.FlagConfig{
	Name:  "dhcp-mode",
	Usage: fmt.Sprintf("[dhcp] DHCP mode (%s, %s, %s)", smee.DHCPModeReservation, smee.DHCPModeProxy, smee.DHCPModeAutoProxy),
}

var DHCPBindAddr = flag.FlagConfig{
	Name:  "dhcp-bind-addr",
	Usage: "[dhcp] DHCP server bind address",
}

var DHCPBindInterface = flag.FlagConfig{
	Name:  "dhcp-bind-interface",
	Usage: "[dhcp] DHCP server bind interface",
}

var DHCPIPForPacket = flag.FlagConfig{
	Name:  "dhcp-ip-for-packet",
	Usage: "[dhcp] DHCP server IP for packet",
}

var DHCPSyslogIP = flag.FlagConfig{
	Name:  "dhcp-syslog-ip",
	Usage: "[dhcp] Syslog server IP address to use in DHCP packets (opt 7)",
}

var DHCPTftpIP = flag.FlagConfig{
	Name:  "dhcp-tftp-ip",
	Usage: "[dhcp] TFTP server IP address to use in DHCP packets (opt 66, etc)",
}

var DHCPTftpPort = flag.FlagConfig{
	Name:  "dhcp-tftp-port",
	Usage: "[dhcp] TFTP server port to use in DHCP packets (opt 66, etc)",
}

var DHCPIPXEHTTPBinaryURLScheme = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-binary-scheme",
	Usage: "[dhcp] HTTP iPXE binaries scheme to use in DHCP packets",
}

var DHCPIPXEHTTPBinaryURLHost = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-binary-host",
	Usage: "[dhcp] HTTP iPXE binaries host or IP to use in DHCP packets",
}

var DHCPIPXEHTTPBinaryURLPort = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-binary-port",
	Usage: "[dhcp] HTTP iPXE binaries port to use in DHCP packets",
}

var DHCPIPXEHTTPBinaryURLPath = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-binary-path",
	Usage: "[dhcp] HTTP iPXE binaries path to use in DHCP packets",
}

var DHCPIPXEHTTPScriptScheme = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-script-scheme",
	Usage: "[dhcp] HTTP iPXE script scheme to use in DHCP packets",
}

var DHCPIPXEHTTPScriptHost = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-script-host",
	Usage: "[dhcp] HTTP iPXE script host or IP to use in DHCP packets",
}

var DHCPIPXEHTTPScriptPort = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-script-port",
	Usage: "[dhcp] HTTP iPXE script port to use in DHCP packets",
}

var DHCPIPXEHTTPScriptPath = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-script-path",
	Usage: "[dhcp] HTTP iPXE script path to use in DHCP packets",
}

var DHCPIPXEHTTPScriptURL = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-script-url",
	Usage: "[dhcp] HTTP iPXE script URL to use in DHCP packets, this overrides the flags for dhcp-http-ipxe-script-{scheme, host, port, path}",
}

var DHCPIPXEHTTPScriptInjectMac = flag.FlagConfig{
	Name:  "dhcp-ipxe-http-script-prepend-mac",
	Usage: "[dhcp] prepend the hardware MAC address to iPXE script URL base, http://1.2.3.4/auto.ipxe -> http://1.2.3.4/40:15:ff:89:cc:0e/auto.ipxe",
}

// iPXE HTTP script flags
var IPXEHTTPScriptEnabled = flag.FlagConfig{
	Name:  "ipxe-http-script-enabled",
	Usage: "[ipxe] enable iPXE HTTP script serving",
}

var IPXEHTTPScriptBindAddr = flag.FlagConfig{
	Name:  "ipxe-http-script-bind-addr",
	Usage: "[ipxe] local IP to listen on for iPXE HTTP script requests",
}

var IPXEHTTPScriptBindPort = flag.FlagConfig{
	Name:  "ipxe-http-script-bind-port",
	Usage: "[ipxe] local port to listen on for iPXE HTTP script requests",
}

var IPXEHTTPScriptExtraKernelArgs = flag.FlagConfig{
	Name:  "ipxe-http-script-extra-kernel-args",
	Usage: "[ipxe] extra set of kernel args (k=v k=v) that are appended to the kernel cmdline iPXE script",
}

var IPXEHTTPScriptTrustedProxies = flag.FlagConfig{
	Name:  "ipxe-http-script-trusted-proxies",
	Usage: "[ipxe] comma separated list of trusted proxies in CIDR notation",
}

var IPXEHTTPScriptOSIEURL = flag.FlagConfig{
	Name:  "ipxe-http-script-osie-url",
	Usage: "[ipxe]  URL where OSIE (HookOS) images are located",
}

var IPXEHTTPScriptRetries = flag.FlagConfig{
	Name:  "ipxe-http-script-retries",
	Usage: "[ipxe] number of retries to attempt when fetching kernel and initrd files in the iPXE script",
}

var IPXEHTTPScriptRetryDelay = flag.FlagConfig{
	Name:  "ipxe-http-script-retry-delay",
	Usage: "[ipxe] delay (in seconds) between retries when fetching kernel and initrd files in the iPXE script",
}

// iPXE HTTP binary flags
var IPXEHTTPBinaryEnabled = flag.FlagConfig{
	Name:  "ipxe-http-binary-enabled",
	Usage: "[ipxe] enable iPXE HTTP binary server",
}

// TFTP flags
var TFTPServerEnabled = flag.FlagConfig{
	Name:  "tftp-server-enabled",
	Usage: "[tftp] enable iPXE TFTP binary server",
}

var TFTPServerBindAddr = flag.FlagConfig{
	Name:  "tftp-server-bind-addr",
	Usage: "[tftp] local IP to listen on for iPXE binary TFTP requests",
}

var TFTPServerBindPort = flag.FlagConfig{
	Name:  "tftp-server-bind-port",
	Usage: "[tftp] local port to listen on for iPXE binary TFTP requests",
}

var TFTPTimeout = flag.FlagConfig{
	Name:  "tftp-timeout",
	Usage: "[tftp] timeout (in seconds) for TFTP requests",
}

var TFTPBlockSize = flag.FlagConfig{
	Name:  "tftp-block-size",
	Usage: "[tftp] TFTP block size a value between 512 (the default block size for TFTP) and 65456 (the max size a UDP packet payload can be)",
}

// iPXE flags
var IPXEEmbeddedScriptPatch = flag.FlagConfig{
	Name:  "ipxe-embedded-script-patch",
	Usage: "[ipxe] iPXE script fragment to patch into served iPXE binaries served via TFTP or HTTP",
}

// Syslog flags
var SyslogEnabled = flag.FlagConfig{
	Name:  "syslog-enabled",
	Usage: "[syslog] enable Syslog server(receiver)",
}

var SyslogBindAddr = flag.FlagConfig{
	Name:  "syslog-bind-addr",
	Usage: "[syslog] local IP to listen on for Syslog messages",
}

var SyslogBindPort = flag.FlagConfig{
	Name:  "syslog-bind-port",
	Usage: "[syslog] local port to listen on for Syslog messages",
}

var ISOEnabled = flag.FlagConfig{
	Name:  "iso-enabled",
	Usage: "[iso] enable OSIE ISO patching server",
}

var ISOUpstreamURL = flag.FlagConfig{
	Name:  "iso-upstream-url",
	Usage: "[iso] an ISO source URL target for patching",
}

var ISOPatchMagicString = flag.FlagConfig{
	Name:  "iso-patch-magic-string",
	Usage: "[iso] the string pattern to match for in the source ISO, defaults to the one defined in HookOS",
}

var ISOStaticIPAMEnabled = flag.FlagConfig{
	Name:  "iso-static-ipam-enabled",
	Usage: "[iso] enable static IPAM for OSIE (HookOS)",
}
