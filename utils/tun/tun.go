// Package tun creates and manages virtual TUN interfaces across platforms.
// Platform-specific implementations live in tun_linux.go, tun_windows.go, etc.
package tun

import "net"

// DefaultMTU is the MTU used for all virtual interfaces.
const DefaultMTU = 1420

// Iface is the platform-agnostic TUN interface used by the daemon.
// Each platform provides a Create() function that returns an Iface.
type Iface interface {
	// Read reads one IP packet from the TUN device into buf.
	Read(buf []byte) (int, error)
	// Write injects one IP packet into the TUN device.
	Write(buf []byte) (int, error)
	// Close shuts down and removes the TUN interface.
	Close() error
	// AddRoute installs a /32 host route for peerIP via this interface.
	AddRoute(peerIP net.IP) error
	// DelRoute removes the /32 host route for peerIP.
	DelRoute(peerIP net.IP) error
	// AddAddr adds an additional IP address on the interface (used to
	// bind the config node .1 address so the WebUI server can listen on it).
	AddAddr(ip net.IP, mask net.IPMask) error
	// GetName returns the OS interface name (e.g. "p2pvpn0", "Local Area Connection").
	GetName() string
	// GetIP returns the primary assigned virtual IP.
	GetIP() net.IP
	// GetCIDR returns the network CIDR the interface operates in.
	GetCIDR() *net.IPNet
}
