// Package keypair handles Ed25519 keypair generation, serialization, and
// persistence for P2P network identities.
package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

// NetworkKeypair holds the Ed25519 keypair that identifies a P2P network.
// The public key acts as the network/rendezvous ID; the private key is the
// config-signing authority in host-locked mode.
type NetworkKeypair struct {
	PublicKey  string `json:"public_key"`  // hex-encoded Ed25519 public key
	PrivateKey string `json:"private_key"` // hex-encoded Ed25519 private key (secret – keep safe)
}

// PeerKeypair holds the libp2p identity keypair for a daemon node.
type PeerKeypair struct {
	PrivKey libp2pcrypto.PrivKey
	PubKey  libp2pcrypto.PubKey
}

// GenerateNetworkKeypair creates a fresh Ed25519 keypair for a new network.
func GenerateNetworkKeypair() (*NetworkKeypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 keypair: %w", err)
	}
	return &NetworkKeypair{
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
	}, nil
}

// GeneratePeerKeypair creates a fresh libp2p identity keypair for this daemon node.
func GeneratePeerKeypair() (*PeerKeypair, error) {
	priv, pub, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating peer keypair: %w", err)
	}
	return &PeerKeypair{PrivKey: priv, PubKey: pub}, nil
}

// SavePeerPrivKey marshals a libp2p private key to disk.
func SavePeerPrivKey(path string, key libp2pcrypto.PrivKey) error {
	raw, err := libp2pcrypto.MarshalPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshalling peer private key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(raw)), 0600)
}

// LoadPeerPrivKey loads a libp2p private key from disk.
func LoadPeerPrivKey(path string) (libp2pcrypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading peer key file: %w", err)
	}
	raw, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding peer key hex: %w", err)
	}
	key, err := libp2pcrypto.UnmarshalPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling peer private key: %w", err)
	}
	return key, nil
}

// DecodeNetworkPublicKey decodes a hex-encoded Ed25519 public key.
func DecodeNetworkPublicKey(hexKey string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid network public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// DecodeNetworkPrivateKey decodes a hex-encoded Ed25519 private key.
func DecodeNetworkPrivateKey(hexKey string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid network private key hex: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: got %d, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}
