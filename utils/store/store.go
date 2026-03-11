// Package store manages persistent local state for the daemon: keypairs,
// joined-network info, and cached config.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	PeerKeyFile = "peer.key"
	StateFile   = "state.json"
)

// DefaultStateDir is the platform-appropriate default directory for daemon state.
var DefaultStateDir = defaultStateDir()

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "p2pvpn")
	}
	return "/var/lib/p2pvpn"
}

// JoinedNetwork records the network a peer has joined.
type JoinedNetwork struct {
	NetworkPubKey string `json:"network_pub_key"` // hex-encoded Ed25519 public key
	AssignedIP    string `json:"assigned_ip"`     // e.g. "10.42.0.3"
	PreferredIP   string `json:"preferred_ip"`    // optional preferred IP requested at join
	TUNName       string `json:"tun_name"`        // e.g. "p2pvpn0"
}

// State is the top-level persistent state blob written to disk.
type State struct {
	JoinedNetwork *JoinedNetwork `json:"joined_network,omitempty"`
}

// Store is a simple file-backed key-value state store.
type Store struct {
	dir string
}

// New creates a Store rooted at dir, creating the directory if necessary.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating state dir %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the root directory of the store.
func (s *Store) Dir() string { return s.dir }

// PeerKeyPath returns the path to the node's persistent identity key file.
func (s *Store) PeerKeyPath() string {
	return filepath.Join(s.dir, PeerKeyFile)
}

// LoadState reads the persisted state. Returns an empty State on first run.
func (s *Store) LoadState() (*State, error) {
	path := filepath.Join(s.dir, StateFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parsing state file: %w", err)
	}
	return &st, nil
}

// SaveState atomically writes state to disk.
func (s *Store) SaveState(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling state: %w", err)
	}
	path := filepath.Join(s.dir, StateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing state tmp file: %w", err)
	}
	return os.Rename(tmp, path)
}
