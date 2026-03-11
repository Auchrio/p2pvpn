//go:build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"p2pvpn/utils/vlog"
)

const (
	tunDevice  = "/dev/net/tun"
	ifnameSize = 16
)

// linuxTUN is the Linux implementation of Iface.
type linuxTUN struct {
	fd   *os.File
	link netlink.Link
	name string
	ip   net.IP
	cidr *net.IPNet
}

// Create opens a new TUN interface named name (e.g. "p2pvpn0"), assigns it
// localIP within the given CIDR, and brings the interface up.
func Create(name, localIP, cidrStr string) (Iface, error) {
	vlog.Logf("tun", "creating TUN: name=%s ip=%s cidr=%s", name, localIP, cidrStr)
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}
	ip := net.ParseIP(localIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid local IP: %s", localIP)
	}

	fd, ifName, err := openTUN(name)
	if err != nil {
		return nil, fmt.Errorf("opening TUN device: %w", err)
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("finding TUN link %q: %w", ifName, err)
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip.To4(), Mask: ipNet.Mask},
	}); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("assigning IP %s to %s: %w", localIP, ifName, err)
	}
	if err := netlink.LinkSetMTU(link, DefaultMTU); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("setting MTU on %s: %w", ifName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("bringing up %s: %w", ifName, err)
	}

	return &linuxTUN{
		fd:   fd,
		link: link,
		name: ifName,
		ip:   ip.To4(),
		cidr: ipNet,
	}, nil
}

func (t *linuxTUN) Read(buf []byte) (int, error)  { return t.fd.Read(buf) }
func (t *linuxTUN) Write(buf []byte) (int, error) {
	vlog.Logf("tun", "TUN write: %d bytes", len(buf))
	return t.fd.Write(buf)
}
func (t *linuxTUN) GetName() string               { return t.name }
func (t *linuxTUN) GetIP() net.IP                 { return t.ip }
func (t *linuxTUN) GetCIDR() *net.IPNet           { return t.cidr }

func (t *linuxTUN) Close() error {
	if err := t.fd.Close(); err != nil {
		return err
	}
	if link, err := netlink.LinkByName(t.name); err == nil {
		_ = netlink.LinkDel(link)
	}
	return nil
}

// AddAddr adds a secondary IP address to the TUN interface.
// Used to bind the .1 config-node address so every peer can serve the WebUI.
func (t *linuxTUN) AddAddr(ip net.IP, mask net.IPMask) error {
	vlog.Logf("tun", "AddAddr: %s/%d on %s", ip, maskBits(mask), t.name)
	if err := netlink.AddrAdd(t.link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip.To4(), Mask: mask},
	}); err != nil && !strings.Contains(err.Error(), "file exists") {
		return fmt.Errorf("adding addr %s to %s: %w", ip, t.name, err)
	}
	return nil
}

func (t *linuxTUN) AddRoute(peerIP net.IP) error {
	vlog.Logf("tun", "AddRoute: %s/32 via %s (linkIndex=%d)", peerIP, t.name, t.link.Attrs().Index)
	route := &netlink.Route{
		LinkIndex: t.link.Attrs().Index,
		Dst:       &net.IPNet{IP: peerIP.To4(), Mask: net.CIDRMask(32, 32)},
	}
	if err := netlink.RouteAdd(route); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			return nil
		}
		return fmt.Errorf("adding route for %s: %w", peerIP, err)
	}
	return nil
}

func (t *linuxTUN) DelRoute(peerIP net.IP) error {
	vlog.Logf("tun", "DelRoute: %s/32 from %s", peerIP, t.name)
	return netlink.RouteDel(&netlink.Route{
		LinkIndex: t.link.Attrs().Index,
		Dst:       &net.IPNet{IP: peerIP.To4(), Mask: net.CIDRMask(32, 32)},
	})
}

// ─── ioctl helpers ────────────────────────────────────────────────────────────

type ifreqFlags struct {
	name  [ifnameSize]byte
	flags uint16
	_     [22]byte
}

func openTUN(name string) (*os.File, string, error) {
	// Use raw syscall.Open instead of os.OpenFile because os.File.Fd()
	// (needed for the TUNSETIFF ioctl) forces the fd into blocking mode,
	// making it incompatible with Go's epoll-based poller ("not pollable").
	rawFd, err := syscall.Open(tunDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("opening %s: %w (are you running as root?)", tunDevice, err)
	}

	var ifr ifreqFlags
	ifr.flags = 0x0001 | 0x1000 // IFF_TUN | IFF_NO_PI
	if name != "" {
		copy(ifr.name[:], []byte(name))
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(rawFd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(rawFd)
		return nil, "", fmt.Errorf("TUNSETIFF ioctl: %w", errno)
	}

	// Set non-blocking so Go's runtime poller (epoll) can manage the fd.
	if err := syscall.SetNonblock(rawFd, true); err != nil {
		syscall.Close(rawFd)
		return nil, "", fmt.Errorf("setting TUN fd non-blocking: %w", err)
	}

	fd := os.NewFile(uintptr(rawFd), tunDevice)
	return fd, strings.TrimRight(string(ifr.name[:]), "\x00"), nil
}

func maskBits(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}
