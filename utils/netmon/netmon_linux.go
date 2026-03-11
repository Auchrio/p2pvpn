//go:build linux

// Package netmon monitors the host's network interfaces for changes (new
// addresses, default route changes) using Linux netlink.  When a significant
// change is detected – such as connecting to a new WiFi network – it sends a
// notification on a channel so the daemon can restart and re-establish its
// libp2p connections on the new network.
package netmon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"p2pvpn/utils/vlog"
)

// Change describes a network event that was detected.
type Change struct {
	Reason string // human-readable description
}

// Monitor watches for host network changes and sends on C when one occurs.
type Monitor struct {
	C          <-chan Change
	ch         chan Change
	tunName    string // TUN interface to ignore (e.g. "p2pvpn0")
	cancel     context.CancelFunc
	debounce   time.Duration
	routeSnap  string // serialized snapshot of the default route at start
	addrsSnap  string // serialized snapshot of non-TUN addresses at start
}

// New creates a Monitor.  tunName is the name of the p2pvpn TUN interface
// which should be ignored when evaluating changes (we only care about the
// underlying physical/wireless network).  The returned Monitor immediately
// begins watching in background goroutines; cancel ctx to stop.
func New(ctx context.Context, tunName string) *Monitor {
	ch := make(chan Change, 1) // buffered so a single event is never lost
	mCtx, cancel := context.WithCancel(ctx)
	m := &Monitor{
		C:        ch,
		ch:       ch,
		tunName:  tunName,
		cancel:   cancel,
		debounce: 5 * time.Second,
	}

	// Take baseline snapshots so we can detect real changes vs. initial
	// netlink noise when the daemon starts.
	m.routeSnap = m.defaultRouteSnapshot()
	m.addrsSnap = m.addrSnapshot()
	vlog.Logf("netmon", "baseline route: %s", m.routeSnap)
	vlog.Logf("netmon", "baseline addrs: %s", m.addrsSnap)

	go m.watch(mCtx)
	return m
}

// Stop terminates the monitor.
func (m *Monitor) Stop() {
	m.cancel()
}

// watch subscribes to netlink address and route updates and debounces changes.
func (m *Monitor) watch(ctx context.Context) {
	addrCh := make(chan netlink.AddrUpdate, 64)
	routeCh := make(chan netlink.RouteUpdate, 64)

	// Subscribe to address changes.
	if err := netlink.AddrSubscribe(addrCh, ctx.Done()); err != nil {
		vlog.Logf("netmon", "AddrSubscribe failed: %v (falling back to polling)", err)
		go m.pollLoop(ctx)
		return
	}
	// Subscribe to route changes.
	if err := netlink.RouteSubscribe(routeCh, ctx.Done()); err != nil {
		vlog.Logf("netmon", "RouteSubscribe failed: %v (falling back to polling)", err)
		go m.pollLoop(ctx)
		return
	}

	vlog.Logf("netmon", "watching for network changes via netlink (ignoring %s)", m.tunName)

	// Debounce: when we get a burst of events (which is typical during a
	// network transition), wait for the storm to settle before emitting a
	// single Change.
	var debounceTimer *time.Timer
	var debounceC <-chan time.Time

	resetDebounce := func(reason string) {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.NewTimer(m.debounce)
		debounceC = debounceTimer.C
		vlog.Logf("netmon", "debounce started (%s): %s", m.debounce, reason)
	}

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case au, ok := <-addrCh:
			if !ok {
				return
			}
			if m.ignoreLink(au.LinkIndex) {
				continue
			}
			reason := fmt.Sprintf("address %s on ifindex %d (new=%v)", au.LinkAddress.IP, au.LinkIndex, au.NewAddr)
			vlog.Logf("netmon", "addr event: %s", reason)
			resetDebounce(reason)

		case ru, ok := <-routeCh:
			if !ok {
				return
			}
			// Only care about default-route changes (Dst == nil or 0.0.0.0/0).
			if ru.Dst != nil && ru.Dst.String() != "0.0.0.0/0" && ru.Dst.String() != "::/0" {
				continue
			}
			if m.ignoreLink(ru.LinkIndex) {
				continue
			}
			reason := fmt.Sprintf("default route via %s on ifindex %d (type=%d)", ru.Gw, ru.LinkIndex, ru.Type)
			vlog.Logf("netmon", "route event: %s", reason)
			resetDebounce(reason)

		case <-debounceC:
			debounceC = nil
			debounceTimer = nil
			// Compare current state to baseline to filter out spurious events.
			newRoute := m.defaultRouteSnapshot()
			newAddrs := m.addrSnapshot()
			if newRoute == m.routeSnap && newAddrs == m.addrsSnap {
				vlog.Logf("netmon", "debounce expired but snapshots unchanged, ignoring")
				continue
			}
			reason := "network configuration changed"
			if newRoute != m.routeSnap {
				reason = fmt.Sprintf("default route changed: %s → %s", m.routeSnap, newRoute)
			} else if newAddrs != m.addrsSnap {
				reason = "host addresses changed"
			}
			vlog.Logf("netmon", "CHANGE DETECTED: %s", reason)
			select {
			case m.ch <- Change{Reason: reason}:
			default:
				// channel already has an unread event
			}
			// Update snapshots so we don't fire again for the same state.
			m.routeSnap = newRoute
			m.addrsSnap = newAddrs
		}
	}
}

// pollLoop is the fallback when netlink subscriptions fail.  It polls every
// 10 seconds and compares snapshots.
func (m *Monitor) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newRoute := m.defaultRouteSnapshot()
			newAddrs := m.addrSnapshot()
			if newRoute != m.routeSnap || newAddrs != m.addrsSnap {
				reason := "network change detected (poll)"
				if newRoute != m.routeSnap {
					reason = fmt.Sprintf("default route changed: %s → %s", m.routeSnap, newRoute)
				}
				vlog.Logf("netmon", "CHANGE DETECTED (poll): %s", reason)
				select {
				case m.ch <- Change{Reason: reason}:
				default:
				}
				m.routeSnap = newRoute
				m.addrsSnap = newAddrs
			}
		}
	}
}

// ignoreLink returns true if the given interface index belongs to the TUN
// or loopback interface.
func (m *Monitor) ignoreLink(index int) bool {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return false
	}
	name := link.Attrs().Name
	if name == m.tunName || name == "lo" {
		return true
	}
	return false
}

// defaultRouteSnapshot returns a string summarising the current IPv4 default
// route so we can compare snapshots.
func (m *Monitor) defaultRouteSnapshot() string {
	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return "<err>"
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			link, _ := netlink.LinkByIndex(r.LinkIndex)
			name := ""
			if link != nil {
				name = link.Attrs().Name
			}
			if name == m.tunName {
				continue
			}
			return fmt.Sprintf("gw=%s dev=%s", r.Gw, name)
		}
	}
	return "<none>"
}

// addrSnapshot returns a sorted, joined string of all IPv4 addresses on non-TUN,
// non-loopback interfaces.
func (m *Monitor) addrSnapshot() string {
	links, err := netlink.LinkList()
	if err != nil {
		return "<err>"
	}
	var parts []string
	for _, link := range links {
		name := link.Attrs().Name
		if name == m.tunName || name == "lo" {
			continue
		}
		addrs, err := netlink.AddrList(link, syscall.AF_INET)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s@%s", a.IP, name))
		}
	}
	return joinSorted(parts)
}

// joinSorted returns a comma-joined string of the slice (order-insensitive
// comparison is good enough since interface enumeration order may vary).
func joinSorted(ss []string) string {
	if len(ss) == 0 {
		return "<none>"
	}
	// Simple sort for small sets.
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if ss[j] < ss[i] {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
	return join(ss)
}

func join(ss []string) string {
	return strings.Join(ss, ",")
}

// IsPhysicalChange returns true if the change is likely a real network
// switch (not just a minor address fluctuation).  Currently always true;
// the debounce + snapshot comparison already filters noise.
func (c Change) IsPhysicalChange() bool {
	return true
}

// String implements fmt.Stringer.
func (c Change) String() string {
	return c.Reason
}

// Ignore returns true if the given IP belongs to the VPN subnet and should
// not trigger a restart (e.g. peer-route additions on the TUN).
func IgnoreIP(ip net.IP, vpnCIDR string) bool {
	_, ipNet, err := net.ParseCIDR(vpnCIDR)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}
