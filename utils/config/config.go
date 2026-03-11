// Package config defines the distributed network config state that is
// replicated to every peer via gossip and validated by signature.
package config

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"p2pvpn/utils/auth"
	"p2pvpn/utils/vlog"
)

// Duration wraps time.Duration with JSON support for both numeric nanoseconds
// and human-readable strings (e.g. "5m", "1h30m").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case float64:
		*d = Duration(time.Duration(int64(val)))
		return nil
	case string:
		dur, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", val, err)
		}
		*d = Duration(dur)
		return nil
	default:
		return fmt.Errorf("cannot unmarshal %T into Duration", v)
	}
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Network holds all network-wide policy fields.
// These are replicated across every peer and signed by the network authority.
type Network struct {
	IPRange         string        `json:"ip-range"`          // CIDR, e.g. "10.42.0.0/24"
	IPHoldDuration  Duration      `json:"ip-hold-duration"`  // e.g. 5m
	AllowedPorts    []int         `json:"allowed-ports"`     // nil = no restriction
	MaxPeers        int           `json:"max-peers"`         // 0 = unlimited
	HostPubKey      string        `json:"host-pubkey"`       // network's own public key (hex)
	DelegatedPeers  []string      `json:"delegated-peers"`   // hex pub keys of delegated admins
	WhitelistMode   bool          `json:"whitelist-mode"`
	AllowedPeerIDs  []string      `json:"allowed-peers"`     // libp2p peer IDs (whitelist)
	Delegations     []auth.DelegationRecord `json:"delegations"`
	UpdatedAt       time.Time     `json:"updated-at"`
}

// DefaultNetwork returns a sensible default config for a newly created network.
func DefaultNetwork(cidr, hostPubKey string) *Network {
	return &Network{
		IPRange:        cidr,
		IPHoldDuration: Duration(5 * time.Minute),
		MaxPeers:       0,
		HostPubKey:     hostPubKey,
		UpdatedAt:      time.Now().UTC(),
	}
}

// Node is each peer's local view of the distributed config with thread-safe access.
type Node struct {
	mu          sync.RWMutex
	current     *Network
	networkPub  ed25519.PublicKey
	hostLocked  bool // when true, only signed updates are applied
}

// NewNode creates a config node seeded with initial config.
// If networkPubKey is set and hostLocked is true, updates must be signed.
func NewNode(initial *Network, networkPubKey ed25519.PublicKey, hostLocked bool) *Node {
	return &Node{
		current:    initial,
		networkPub: networkPubKey,
		hostLocked: hostLocked,
	}
}

// Get returns a snapshot of the current config.
func (n *Node) Get() *Network {
	n.mu.RLock()
	defer n.mu.RUnlock()
	cfg := *n.current
	return &cfg
}

// ApplyUpdate validates and applies a signed config update envelope.
// Returns nil and no change if validation fails.
func (n *Node) ApplyUpdate(env *auth.ConfigUpdateEnvelope) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	vlog.Logf("config", "ApplyUpdate: signer=%s ts=%s host-locked=%v",
		env.SignerPubKey[:min(16, len(env.SignerPubKey))]+"...", env.Timestamp.Format(time.RFC3339), n.hostLocked)

	if n.hostLocked {
		trusted, err := n.trustedKeys()
		if err != nil {
			return fmt.Errorf("building trusted key list: %w", err)
		}
		vlog.Logf("config", "ApplyUpdate: verifying signature against %d trusted keys", len(trusted))
		if err := auth.Verify(env, trusted); err != nil {
			vlog.Logf("config", "ApplyUpdate: REJECTED: %v", err)
			return fmt.Errorf("rejecting unsigned/invalid config update: %w", err)
		}
		vlog.Logf("config", "ApplyUpdate: signature verified OK")
	}

	var patch Network
	if err := json.Unmarshal(env.Payload, &patch); err != nil {
		return fmt.Errorf("parsing config update payload: %w", err)
	}

	// Merge non-zero fields from patch into current.
	n.merge(&patch)
	n.current.UpdatedAt = env.Timestamp
	vlog.Logf("config", "ApplyUpdate: merged successfully, updated-at=%s", env.Timestamp.Format(time.RFC3339))
	return nil
}

// ApplyUnsigned applies config directly (only valid when not in host-locked mode).
func (n *Node) ApplyUnsigned(cfg *Network) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.hostLocked {
		vlog.Logf("config", "ApplyUnsigned: REJECTED (host-locked mode)")
		return fmt.Errorf("host-locked mode: unsigned updates not permitted")
	}
	vlog.Logf("config", "ApplyUnsigned: applying full-state merge")
	n.merge(cfg)
	n.current.UpdatedAt = time.Now().UTC()
	return nil
}

// Marshal returns the canonical JSON of the current config (for gossiping).
func (n *Node) Marshal() ([]byte, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return json.Marshal(n.current)
}

// IsWhitelisted returns true when whitelist mode is off, OR the peerID is in the allowed list.
func (n *Node) IsWhitelisted(peerID string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.current.WhitelistMode {
		return true
	}
	for _, id := range n.current.AllowedPeerIDs {
		if id == peerID {
			vlog.Logf("config", "IsWhitelisted(%s): YES (in allowed list)", peerID)
			return true
		}
	}
	vlog.Logf("config", "IsWhitelisted(%s): NO (not in allowed list, %d entries)", peerID, len(n.current.AllowedPeerIDs))
	return false
}

// IsDelegated returns true if peerPubKeyHex has an active (non-revoked) delegation.
func (n *Node) IsDelegated(peerPubKeyHex string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, d := range n.current.Delegations {
		if d.DelegatePubKey == peerPubKeyHex && !d.Revoked {
			return true
		}
	}
	return false
}

// PortAllowed returns true if port is permitted (or if no port restrictions are set).
func (n *Node) PortAllowed(port int) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if len(n.current.AllowedPorts) == 0 {
		return true
	}
	for _, p := range n.current.AllowedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// trustedKeys builds the list of currently trusted signing keys from the config.
// Caller must hold n.mu (at least read lock).
func (n *Node) trustedKeys() ([]ed25519.PublicKey, error) {
	keys := []ed25519.PublicKey{n.networkPub}
	for _, d := range n.current.Delegations {
		if d.Revoked {
			continue
		}
		if err := auth.VerifyDelegation(&d, n.networkPub); err != nil {
			continue // skip invalid delegation records
		}
		raw, err := hexDecode(d.DelegatePubKey)
		if err != nil {
			continue
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

// merge applies non-zero fields from patch into n.current.
// Note: WhitelistMode is a bool and cannot be distinguished from a zero-value
// false when using JSON merge. The ipcConfigSet handler now reads the current
// config before unmarshalling the patch on top, so this unconditional copy is
// correct — the caller always supplies the full intended value.
func (n *Node) merge(patch *Network) {
	if patch.IPRange != "" {
		n.current.IPRange = patch.IPRange
	}
	if patch.IPHoldDuration != 0 {
		n.current.IPHoldDuration = patch.IPHoldDuration
	}
	if patch.AllowedPorts != nil {
		n.current.AllowedPorts = patch.AllowedPorts
	}
	if patch.MaxPeers != 0 {
		n.current.MaxPeers = patch.MaxPeers
	}
	if patch.HostPubKey != "" {
		n.current.HostPubKey = patch.HostPubKey
	}
	if patch.DelegatedPeers != nil {
		n.current.DelegatedPeers = patch.DelegatedPeers
	}
	// WhitelistMode: always copy because the ipcConfigSet handler now
	// reads-then-patches (overlay), so the patch always represents the
	// intended final value. For gossip full-state syncs, the complete
	// config is sent, so this is also correct.
	n.current.WhitelistMode = patch.WhitelistMode
	if patch.AllowedPeerIDs != nil {
		n.current.AllowedPeerIDs = patch.AllowedPeerIDs
	}
	if patch.Delegations != nil {
		n.current.Delegations = patch.Delegations
	}
}

func hexDecode(s string) ([]byte, error) {
	var b []byte
	_, err := fmt.Sscanf(s, "%x", &b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
