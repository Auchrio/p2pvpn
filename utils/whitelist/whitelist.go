// Package whitelist enforces per-peer quarantine when whitelist mode is enabled.
// A quarantined peer can reach the DHT but the daemon will not route virtual-
// network traffic to or from it until its peer ID is in the allowed list.
package whitelist

import (
	"sync"

	"p2pvpn/utils/config"
)

// Enforcer tracks which peers are quarantined and provides fast Allow checks.
type Enforcer struct {
	mu         sync.RWMutex
	quarantine map[string]struct{} // peerID -> quarantined
	cfg        *config.Node
}

// New creates a new Enforcer backed by the given config node.
func New(cfg *config.Node) *Enforcer {
	return &Enforcer{
		quarantine: make(map[string]struct{}),
		cfg:        cfg,
	}
}

// PeerConnected is called when a new peer connects. If whitelist mode is active
// and the peer is not in the allowed list, it is quarantined.
func (e *Enforcer) PeerConnected(peerID string) {
	if e.cfg.IsWhitelisted(peerID) {
		e.mu.Lock()
		delete(e.quarantine, peerID)
		e.mu.Unlock()
		return
	}
	// Not in whitelist — quarantine.
	e.mu.Lock()
	e.quarantine[peerID] = struct{}{}
	e.mu.Unlock()
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

// Refresh re-evaluates all currently quarantined peers against the latest
// config. This should be called every time the config's allowed-peers list
// changes, so that peers added to the whitelist are promoted immediately.
func (e *Enforcer) Refresh() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for peerID := range e.quarantine {
		if e.cfg.IsWhitelisted(peerID) {
			delete(e.quarantine, peerID)
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
