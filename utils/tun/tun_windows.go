//go:build windows

package tun

import (
	"fmt"
	"net"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// windowsTUN implements Iface on Windows using the WireGuard wintun driver.
// Requirements: wintun.dll must be present alongside the binary or in PATH.
// Download: https://www.wintun.net/
type windowsTUN struct {
	dev  wgtun.Device
	name string
	ip   net.IP
	cidr *net.IPNet
	luid winipcfg.LUID
}

// Create creates a WireGuard/wintun TUN adapter named name, assigns localIP
// within cidrStr, and brings the adapter up.
func Create(name, localIP, cidrStr string) (Iface, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}
	ip := net.ParseIP(localIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid local IP: %s", localIP)
	}

	dev, err := wgtun.CreateTUN(name, DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("creating wintun adapter %q: %w (is wintun.dll present?)", name, err)
	}

	nativeDev, ok := dev.(*wgtun.NativeTun)
	if !ok {
		_ = dev.Close()
		return nil, fmt.Errorf("unexpected TUN device type")
	}

	luid := winipcfg.LUID(nativeDev.LUID())

	// Assign the IP address using netip types.
	addrPrefix := netip.PrefixFrom(toNetipAddr(ip.To4()), prefixLen(ipNet.Mask))
	if err := luid.AddIPAddress(addrPrefix); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("assigning IP %s: %w", localIP, err)
	}

	return &windowsTUN{
		dev:  dev,
		name: name,
		ip:   ip.To4(),
		cidr: ipNet,
		luid: luid,
	}, nil
}

func (t *windowsTUN) Read(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	sizes := []int{0}
	n, err := t.dev.Read(bufs, sizes, 0)
	if err != nil || n == 0 {
		return 0, err
	}
	return sizes[0], nil
}

func (t *windowsTUN) Write(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	return t.dev.Write(bufs, 0)
}

func (t *windowsTUN) Close() error  { return t.dev.Close() }
func (t *windowsTUN) GetName() string { return t.name }
func (t *windowsTUN) GetIP() net.IP   { return t.ip }
func (t *windowsTUN) GetCIDR() *net.IPNet { return t.cidr }

func (t *windowsTUN) AddAddr(ip net.IP, mask net.IPMask) error {
	addr := netip.PrefixFrom(toNetipAddr(ip.To4()), prefixLen(mask))
	return t.luid.AddIPAddress(addr)
}

func (t *windowsTUN) AddRoute(peerIP net.IP) error {
	dest := netip.PrefixFrom(toNetipAddr(peerIP.To4()), 32)
	return t.luid.AddRoute(dest, netip.Addr{}, 0)
}

func (t *windowsTUN) DelRoute(peerIP net.IP) error {
	dest := netip.PrefixFrom(toNetipAddr(peerIP.To4()), 32)
	return t.luid.DeleteRoute(dest, netip.Addr{})
}

// toNetipAddr converts a 4-byte net.IP to a netip.Addr.
func toNetipAddr(ip net.IP) netip.Addr {
	ip4 := ip.To4()
	return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
}

func prefixLen(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}
