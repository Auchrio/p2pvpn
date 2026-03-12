// Package ipmgr manages virtual IP address assignment within a configured
// CIDR block, including lease tracking and hold-on-disconnect behaviour.
package ipmgr

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	"p2pvpn/utils/vlog"
)

// LeaseStatus describes the current state of an IP address lease.
type LeaseStatus int

const (
	LeaseActive     LeaseStatus = iota // Peer is connected and holding the lease.
	LeaseHeld                          // Peer disconnected, IP held before release.
	LeaseFree                          // IP is available for assignment.
)

// Lease tracks the IP assignment for one peer.
type Lease struct {
	IP       net.IP
	PeerID   string
	Status   LeaseStatus
	HeldAt   time.Time // when peer disconnected (Status == LeaseHeld)
	HoldTTL  time.Duration
}

// Manager handles IP allocation from a CIDR pool.
type Manager struct {
	mu       sync.Mutex
	cidr     *net.IPNet
	leases   map[string]*Lease // key: IP string
	peerToIP map[string]string // peerID -> IP string
	holdTTL  time.Duration
}

// New creates a Manager for the given CIDR block (e.g. "10.42.0.0/24").
// The .1 address is reserved for the distributed config node.
// holdTTL is how long a disconnected peer's IP is held before release.
func New(cidrStr string, holdTTL time.Duration) (*Manager, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}
	m := &Manager{
		cidr:     ipNet,
		leases:   make(map[string]*Lease),
		peerToIP: make(map[string]string),
		holdTTL:  holdTTL,
	}
	return m, nil
}

// AssignDeterministic assigns a virtual IP derived from a SHA-256 hash of the
// peerID, giving every peer a stable, independently-computable address without
// any cross-node coordination. Both the local node and remote peers will reach
// the same IP for the same peerID, so TUN routes and packet addressing are
// automatically consistent across the mesh.
//
// Collisions are possible in very large networks; in a /24 (253 usable IPs)
// the probability is negligible for typical mesh sizes.
func (m *Manager) AssignDeterministic(peerID string) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	vlog.Logf("ipmgr", "AssignDeterministic(%s)", peerID)

	// Re-activate an existing lease if present.
	if ipStr, ok := m.peerToIP[peerID]; ok {
		if lease, ok := m.leases[ipStr]; ok {
			vlog.Logf("ipmgr", "  reactivating existing lease: %s (was %v)", ipStr, lease.Status)
			lease.Status = LeaseActive
			return lease.IP, nil
		}
	}

	ip4 := m.cidr.IP.To4()
	maskBytes := []byte(m.cidr.Mask)
	ones, bits := m.cidr.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 2 {
		return nil, fmt.Errorf("CIDR %s is too small for deterministic assignment", m.cidr)
	}
	maxHost := 1 << uint(hostBits) // e.g. 256 for /24
	// Usable range: .2 through .maxHost-2 (skip network .0, config .1, broadcast .maxHost-1)
	usable := maxHost - 3 // e.g. 253 for /24

	digest := sha256.Sum256([]byte(peerID))
	n := int(digest[0])<<24 | int(digest[1])<<16 | int(digest[2])<<8 | int(digest[3])
	n &= 0x7fffffff // strip sign bit
	hostNum := 2 + (n % usable) // range [2, maxHost-2]

	result := make(net.IP, 4)
	hostBytes := [4]byte{byte(hostNum >> 24), byte(hostNum >> 16), byte(hostNum >> 8), byte(hostNum)}
	for i := 0; i < 4; i++ {
		result[i] = (ip4[i] & maskBytes[i]) | (hostBytes[i] &^ maskBytes[i])
	}
	vlog.Logf("ipmgr", "  hash-based IP for %s: %s (hostNum=%d/%d)", peerID, result, hostNum, usable)

	// Collision handling: if the deterministic IP is already leased by a
	// different peer, probe linearly until a free slot is found.
	ipStr := result.String()
	if existing, occupied := m.leases[ipStr]; occupied && existing.PeerID != peerID && existing.Status != LeaseFree {
		vlog.Logf("ipmgr", "  COLLISION: %s already held by %s, probing linearly", ipStr, existing.PeerID)
		for probe := 1; probe < usable; probe++ {
			alt := 2 + ((n + probe) % usable)
			candidate := make(net.IP, 4)
			altBytes := [4]byte{byte(alt >> 24), byte(alt >> 16), byte(alt >> 8), byte(alt)}
			for i := 0; i < 4; i++ {
				candidate[i] = (ip4[i] & maskBytes[i]) | (altBytes[i] &^ maskBytes[i])
			}
			cs := candidate.String()
			if ex, occ := m.leases[cs]; !occ || ex.Status == LeaseFree {
				vlog.Logf("ipmgr", "  collision resolved: %s (probe=%d)", candidate, probe)
				result = candidate
				break
			}
		}
	}

	vlog.Logf("ipmgr", "  allocated: %s → %s", peerID, result)
	return m.allocate(peerID, result), nil
}

// SetHoldTTL updates the hold duration applied to future disconnects.
func (m *Manager) SetHoldTTL(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holdTTL = d
}

// Assign allocates an IP for peerID. If preferred is non-empty and available,
// that address is used; otherwise the next free IP is assigned.
// Returns the assigned IP.
func (m *Manager) Assign(peerID string, preferred string) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If peer already has a (held) lease, re-activate it.
	if ipStr, ok := m.peerToIP[peerID]; ok {
		if lease, ok := m.leases[ipStr]; ok {
			lease.Status = LeaseActive
			return lease.IP, nil
		}
	}

	m.releaseExpired()

	// Try preferred address first.
	if preferred != "" {
		ip := net.ParseIP(preferred)
		if ip == nil {
			return nil, fmt.Errorf("invalid preferred IP: %s", preferred)
		}
		if !m.cidr.Contains(ip) {
			return nil, fmt.Errorf("preferred IP %s is outside CIDR %s", preferred, m.cidr)
		}
		if isReserved(ip, m.cidr) {
			return nil, fmt.Errorf("preferred IP %s is reserved", preferred)
		}
		ipStr := ip.String()
		if l, occupied := m.leases[ipStr]; occupied && l.Status != LeaseFree {
			return nil, fmt.Errorf("preferred IP %s is already in use by peer %s", preferred, l.PeerID)
		}
		return m.allocate(peerID, ip), nil
	}

	// Sequential allocation.
	ip := nextIP(m.cidr.IP)
	for m.cidr.Contains(ip) {
		if !isReserved(ip, m.cidr) {
			ipStr := ip.String()
			if l, occupied := m.leases[ipStr]; !occupied || l.Status == LeaseFree {
				return m.allocate(peerID, ip), nil
			}
		}
		ip = nextIP(ip)
	}

	return nil, fmt.Errorf("IP pool exhausted for CIDR %s", m.cidr)
}

// Release marks a peer's IP as held, starting the hold timer.
func (m *Manager) Release(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr, ok := m.peerToIP[peerID]
	if !ok {
		vlog.Logf("ipmgr", "Release(%s): no lease found", peerID)
		return
	}
	if lease, ok := m.leases[ipStr]; ok && lease.Status == LeaseActive {
		vlog.Logf("ipmgr", "Release(%s): %s → held (TTL=%s)", peerID, ipStr, m.holdTTL)
		lease.Status = LeaseHeld
		lease.HeldAt = time.Now()
	}
}

// Drop immediately frees a peer's IP without a hold period.
func (m *Manager) Drop(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drop(peerID)
}

func (m *Manager) drop(peerID string) {
	ipStr, ok := m.peerToIP[peerID]
	if !ok {
		return
	}
	if lease, ok := m.leases[ipStr]; ok {
		lease.Status = LeaseFree
		lease.PeerID = ""
	}
	delete(m.peerToIP, peerID)
}

// PeerIP returns the currently assigned IP for a peerID, or nil.
func (m *Manager) PeerIP(peerID string) net.IP {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ipStr, ok := m.peerToIP[peerID]; ok {
		if l, ok := m.leases[ipStr]; ok && l.Status == LeaseActive {
			return l.IP
		}
	}
	return nil
}

// Reassign changes the IP assignment for an existing peer.
// If newIP is empty, a new deterministic IP is assigned.
// Returns the new IP and any error.
func (m *Manager) Reassign(peerID, newIP string) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Must have an existing lease to reassign.
	oldIPStr, hasLease := m.peerToIP[peerID]
	if !hasLease {
		return nil, fmt.Errorf("peer %s has no active lease", peerID)
	}

	// Parse and validate new IP if provided.
	var targetIP net.IP
	if newIP != "" {
		targetIP = net.ParseIP(newIP)
		if targetIP == nil {
			return nil, fmt.Errorf("invalid IP address: %s", newIP)
		}
		targetIP = targetIP.To4()
		if targetIP == nil {
			return nil, fmt.Errorf("only IPv4 addresses are supported")
		}
		if !m.cidr.Contains(targetIP) {
			return nil, fmt.Errorf("IP %s is outside CIDR %s", newIP, m.cidr)
		}
		if isReserved(targetIP, m.cidr) {
			return nil, fmt.Errorf("IP %s is reserved", newIP)
		}
		// Check if already in use by another peer.
		targetIPStr := targetIP.String()
		if l, occupied := m.leases[targetIPStr]; occupied && l.Status != LeaseFree && l.PeerID != peerID {
			return nil, fmt.Errorf("IP %s is already in use by peer %s", newIP, l.PeerID)
		}
	}

	// Release old lease.
	if oldLease, ok := m.leases[oldIPStr]; ok {
		oldLease.Status = LeaseFree
		oldLease.PeerID = ""
	}
	delete(m.peerToIP, peerID)

	// Allocate new IP.
	if targetIP != nil {
		return m.allocate(peerID, targetIP), nil
	}

	// If no IP specified, compute deterministic IP.
	return m.assignDeterministicLocked(peerID)
}

// assignDeterministicLocked is the lock-held version of AssignDeterministic.
func (m *Manager) assignDeterministicLocked(peerID string) (net.IP, error) {
	ip4 := m.cidr.IP.To4()
	maskBytes := []byte(m.cidr.Mask)
	ones, bits := m.cidr.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 2 {
		return nil, fmt.Errorf("CIDR %s is too small for deterministic assignment", m.cidr)
	}
	maxHost := 1 << uint(hostBits)
	usable := maxHost - 3

	digest := sha256.Sum256([]byte(peerID))
	n := int(digest[0])<<24 | int(digest[1])<<16 | int(digest[2])<<8 | int(digest[3])
	n &= 0x7fffffff
	hostNum := 2 + (n % usable)

	result := make(net.IP, 4)
	hostBytes := [4]byte{byte(hostNum >> 24), byte(hostNum >> 16), byte(hostNum >> 8), byte(hostNum)}
	for i := 0; i < 4; i++ {
		result[i] = (ip4[i] & maskBytes[i]) | (hostBytes[i] &^ maskBytes[i])
	}

	// Collision handling.
	ipStr := result.String()
	if existing, occupied := m.leases[ipStr]; occupied && existing.PeerID != peerID && existing.Status != LeaseFree {
		for probe := 1; probe < usable; probe++ {
			alt := 2 + ((n + probe) % usable)
			candidate := make(net.IP, 4)
			altBytes := [4]byte{byte(alt >> 24), byte(alt >> 16), byte(alt >> 8), byte(alt)}
			for i := 0; i < 4; i++ {
				candidate[i] = (ip4[i] & maskBytes[i]) | (altBytes[i] &^ maskBytes[i])
			}
			cs := candidate.String()
			if ex, occ := m.leases[cs]; !occ || ex.Status == LeaseFree {
				result = candidate
				break
			}
		}
	}

	return m.allocate(peerID, result), nil
}

// ActiveLeases returns a snapshot of all currently active leases.
func (m *Manager) ActiveLeases() []Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseExpired()
	var out []Lease
	for _, l := range m.leases {
		if l.Status == LeaseActive {
			out = append(out, *l)
		}
	}
	return out
}

// ConfigIP returns the .1 address of the CIDR (the config node virtual address).
func (m *Manager) ConfigIP() net.IP {
	base := make(net.IP, len(m.cidr.IP))
	copy(base, m.cidr.IP)
	base[len(base)-1] = 1
	return base
}

// allocate records a new active lease — caller must hold m.mu.
func (m *Manager) allocate(peerID string, ip net.IP) net.IP {
	ipCopy := cloneIP(ip)
	ipStr := ipCopy.String()
	m.leases[ipStr] = &Lease{
		IP:      ipCopy,
		PeerID:  peerID,
		Status:  LeaseActive,
		HoldTTL: m.holdTTL,
	}
	m.peerToIP[peerID] = ipStr
	return ipCopy
}

// releaseExpired frees held leases whose hold TTL has elapsed — caller must hold m.mu.
func (m *Manager) releaseExpired() {
	now := time.Now()
	for _, l := range m.leases {
		if l.Status == LeaseHeld && now.Sub(l.HeldAt) >= l.HoldTTL {
			l.Status = LeaseFree
			delete(m.peerToIP, l.PeerID)
			l.PeerID = ""
		}
	}
}

// isReserved returns true for network, broadcast, and .1 (config node) addresses.
func isReserved(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	net4 := ipNet.IP.To4()
	if ip4 == nil || net4 == nil {
		return false
	}
	// Network address.
	if ip4.Equal(net4) {
		return true
	}
	// Broadcast address.
	bcast := make(net.IP, 4)
	for i := range bcast {
		bcast[i] = net4[i] | ^ipNet.Mask[i]
	}
	if ip4.Equal(bcast) {
		return true
	}
	// Config node (.1).
	configNode := make(net.IP, 4)
	copy(configNode, net4)
	configNode[3] = 1
	if ip4.Equal(configNode) {
		return true
	}
	return false
}

// nextIP increments an IP address by 1.
func nextIP(ip net.IP) net.IP {
	n := cloneIP(ip)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}
