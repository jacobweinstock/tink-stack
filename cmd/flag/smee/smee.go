package smee

import (
	"github.com/jacobweinstock/tink-stack/cmd/flag"
	"github.com/jacobweinstock/tink-stack/smee"
)

func RegisterFlags(fs *flag.FlagSet, sc *smee.Config) {
	// DHCP flags
	fs.BoolVar(&sc.DHCP.Enabled, 0, DHCPEnabled.Name, DHCPEnabled.Usage)
	fs.ValueLong(DHCPModeFlag.Name, &sc.DHCP.Mode, DHCPModeFlag.Usage)
	fs.AddrPortLong(DHCPBindAddr.Name, &sc.DHCP.BindAddr, DHCPBindAddr.Usage)
	fs.StringVar(&sc.DHCP.BindInterface, 0, DHCPBindInterface.Name, "", DHCPBindInterface.Usage)
	fs.AddrLong(DHCPIPForPacket.Name, &sc.DHCP.IPForPacket, DHCPIPForPacket.Usage)
	fs.AddrLong(DHCPSyslogIP.Name, &sc.DHCP.SyslogIP, DHCPSyslogIP.Usage)
	fs.AddrLong(DHCPTftpIP.Name, &sc.DHCP.TFTPIP, DHCPTftpIP.Usage)
	fs.Uint16Var(&sc.DHCP.TFTPPort, 0, DHCPTftpPort.Name, sc.DHCP.TFTPPort, DHCPTftpPort.Usage)
	fs.BoolVar(&sc.DHCP.IPXEHTTPScript.InjectMacAddress, 0, DHCPIPXEHTTPScriptInjectMac.Name, DHCPIPXEHTTPScriptInjectMac.Usage)

	// IPXE flags
	fs.StringVar(&sc.IPXE.EmbeddedScriptPatch, 0, IPXEEmbeddedScriptPatch.Name, sc.IPXE.EmbeddedScriptPatch, IPXEEmbeddedScriptPatch.Usage)
	fs.BoolVar(&sc.IPXE.HTTPBinaryServer.Enabled, 0, IPXEHTTPBinaryEnabled.Name, IPXEHTTPBinaryEnabled.Usage)
	fs.BoolVar(&sc.IPXE.HTTPScriptServer.Enabled, 0, IPXEHTTPScriptEnabled.Name, IPXEHTTPScriptEnabled.Usage)
	fs.AddrLong(IPXEHTTPScriptBindAddr.Name, &sc.IPXE.HTTPScriptServer.BindAddr, IPXEHTTPScriptBindAddr.Usage)
	fs.Uint16Var(&sc.IPXE.HTTPScriptServer.BindPort, 0, IPXEHTTPScriptBindPort.Name, sc.IPXE.HTTPScriptServer.BindPort, IPXEHTTPScriptBindPort.Usage)
	fs.StringSetVar(&sc.IPXE.HTTPScriptServer.ExtraKernelArgs, 0, IPXEHTTPScriptExtraKernelArgs.Name, IPXEHTTPScriptExtraKernelArgs.Usage)
	fs.StringSetVar(&sc.IPXE.HTTPScriptServer.TrustedProxies, 0, IPXEHTTPScriptTrustedProxies.Name, IPXEHTTPScriptTrustedProxies.Usage)
	fs.IntVar(&sc.IPXE.HTTPScriptServer.Retries, 0, IPXEHTTPScriptRetries.Name, sc.IPXE.HTTPScriptServer.Retries, IPXEHTTPScriptRetries.Usage)
	fs.IntVar(&sc.IPXE.HTTPScriptServer.RetryDelay, 0, IPXEHTTPScriptRetryDelay.Name, sc.IPXE.HTTPScriptServer.RetryDelay, IPXEHTTPScriptRetryDelay.Usage)

	// ISO Flags
	fs.BoolVar(&sc.ISO.Enabled, 0, ISOEnabled.Name, ISOEnabled.Usage)
	fs.URLLong(ISOUpstreamURL.Name, sc.ISO.UpstreamURL, ISOUpstreamURL.Usage)
	fs.StringVar(&sc.ISO.PatchMagicString, 0, ISOPatchMagicString.Name, sc.ISO.PatchMagicString, ISOPatchMagicString.Usage)
	fs.BoolVar(&sc.ISO.StaticIPAMEnabled, 0, ISOStaticIPAMEnabled.Name, ISOStaticIPAMEnabled.Usage)

	// Syslog Flags
	fs.BoolVar(&sc.Syslog.Enabled, 0, SyslogEnabled.Name, SyslogEnabled.Usage)
	fs.AddrLong(SyslogBindAddr.Name, &sc.Syslog.BindAddr, SyslogBindAddr.Usage)
	fs.Uint16Var(&sc.Syslog.BindPort, 0, SyslogBindPort.Name, sc.Syslog.BindPort, SyslogBindPort.Usage)

	// TFTP Flags
	fs.BoolVar(&sc.TFTP.Enabled, 0, TFTPServerEnabled.Name, TFTPServerEnabled.Usage)
	fs.AddrLong(TFTPServerBindAddr.Name, &sc.TFTP.BindAddr, TFTPServerBindAddr.Usage)
	fs.Uint16Var(&sc.TFTP.BindPort, 0, TFTPServerBindPort.Name, sc.TFTP.BindPort, TFTPServerBindPort.Usage)
	fs.IntVar(&sc.TFTP.BlockSize, 0, TFTPBlockSize.Name, sc.TFTP.BlockSize, TFTPBlockSize.Usage)
	fs.DurationVar(&sc.TFTP.Timeout, 0, TFTPTimeout.Name, sc.TFTP.Timeout, TFTPTimeout.Usage)
}
