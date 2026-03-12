// Package whitelist enforces per-peer quarantine when whitelist mode is enabled.
// A quarantined peer can reach the DHT but the daemon will not route virtual-
// network traffic to or from it until its peer ID is in the allowed list.
//
// Security hardening (v1.3.0):
//   - Quarantined peers do NOT consume virtual IPs or TUN routes
//   - Quarantined peers are auto-disconnected after a timeout
//   - OnPeerPromoted callback triggers IP assignment when a peer is approved
package whitelist

import (
	"sync"
	"time"

	"p2pvpn/utils/config"
	"p2pvpn/utils/vlog"
)

// quarantineEntry tracks when a peer was quarantined.
type quarantineEntry struct {
	since time.Time
}

// Enforcer tracks which peers are quarantined and provides fast Allow checks.
type Enforcer struct {
	mu         sync.RWMutex
	quarantine map[string]quarantineEntry // peerID -> quarantine info
	cfg        *config.Node

	// OnPeerPromoted is called when a previously-quarantined peer is promoted
	// to the whitelist. The daemon uses this to assign an IP and install routes.
	OnPeerPromoted func(peerID string)

	// OnPeerTimeout is called when a quarantined peer exceeds QuarantineTimeout.
	// The daemon uses this to close the peer's VPN stream and release resources.
	OnPeerTimeout func(peerID string)
}

// New creates a new Enforcer backed by the given config node.
func New(cfg *config.Node) *Enforcer {
	return &Enforcer{
		quarantine: make(map[string]quarantineEntry),
		cfg:        cfg,
	}
}

// PeerConnected is called when a new peer connects. If whitelist mode is active
// and the peer is not in the allowed list, it is quarantined.
// Returns true if the peer is whitelisted (or whitelist mode is off).
func (e *Enforcer) PeerConnected(peerID string) bool {
	if e.cfg.IsWhitelisted(peerID) {
		e.mu.Lock()
		delete(e.quarantine, peerID)
		e.mu.Unlock()
		vlog.Logf("whitelist", "peer %s connected: whitelisted, allowing", peerID)
		return true
	}
	// Not in whitelist — quarantine.
	e.mu.Lock()
	e.quarantine[peerID] = quarantineEntry{since: time.Now()}
	e.mu.Unlock()
	vlog.Logf("whitelist", "peer %s connected: NOT whitelisted, quarantined", peerID)
	return false
}

// PeerDisconnected removes a peer from the quarantine map.
func (e *Enforcer) PeerDisconnected(peerID string) {
	e.mu.Lock()
	delete(e.quarantine, peerID)
	e.mu.Unlock()
}

// Allow returns true when traffic to/from peerID should be forwarded.
func (e *Enforcer) Allow(peerID string) bool {
	e.mu.RLock()
	_, quarantined := e.quarantine[peerID]
	e.mu.RUnlock()
	if quarantined {
		return false
	}
	return e.cfg.IsWhitelisted(peerID)
}

// IsQuarantined returns true if the peer is currently in quarantine.
func (e *Enforcer) IsQuarantined(peerID string) bool {
	e.mu.RLock()
	_, quarantined := e.quarantine[peerID]
	e.mu.RUnlock()
	return quarantined
}

// Refresh re-evaluates all currently quarantined peers against the latest
// config. This should be called every time the config's allowed-peers list
// changes, so that peers added to the whitelist are promoted immediately.
// Promoted peers trigger OnPeerPromoted callback so the daemon can assign IPs.
func (e *Enforcer) Refresh() {
	e.mu.Lock()
	var promoted []string
	for peerID := range e.quarantine {
		if e.cfg.IsWhitelisted(peerID) {
			delete(e.quarantine, peerID)
			promoted = append(promoted, peerID)
		}
	}
	e.mu.Unlock()

	// Call promotion callback outside the lock to avoid deadlock.
	if e.OnPeerPromoted != nil {
		for _, peerID := range promoted {
			vlog.Logf("whitelist", "peer %s promoted from quarantine to whitelist", peerID)
			e.OnPeerPromoted(peerID)
		}
	}
}

// CheckTimeouts iterates quarantined peers and calls OnPeerTimeout for any
// that have exceeded the configured quarantine timeout. Should be called periodically.
// If QuarantineTimeout is 0 in the config, timeouts are disabled.
func (e *Enforcer) CheckTimeouts() {
	timeout := e.cfg.GetQuarantineTimeout()
	if timeout == 0 {
		// Quarantine timeout disabled
		return
	}

	e.mu.Lock()
	now := time.Now()
	var timedOut []string
	for peerID, entry := range e.quarantine {
		if now.Sub(entry.since) > timeout {
			timedOut = append(timedOut, peerID)
			delete(e.quarantine, peerID)
		}
	}
	e.mu.Unlock()

	// Call timeout callback outside the lock.
	if e.OnPeerTimeout != nil {
		for _, peerID := range timedOut {
			vlog.Logf("whitelist", "peer %s quarantine timeout (%s), disconnecting", peerID, timeout)
			e.OnPeerTimeout(peerID)
		}
	}
}

// QuarantinedPeers returns the current set of quarantined peer IDs.
func (e *Enforcer) QuarantinedPeers() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.quarantine))
	for id := range e.quarantine {
		out = append(out, id)
	}
	return out
}
