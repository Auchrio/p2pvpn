// Package auth handles Ed25519 signing and verification for config updates
// and delegation records used in host-locked mode.
package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"p2pvpn/utils/vlog"
)

// ConfigUpdateEnvelope is a signed wrapper around a raw config JSON payload.
// Only updates whose Signature verifies against the network public key (or a
// valid delegated key) are applied by peers.
type ConfigUpdateEnvelope struct {
	// Payload is the canonical JSON of the config fields being updated.
	Payload []byte `json:"payload"`
	// SignerPubKey is the hex-encoded Ed25519 public key that produced Signature.
	// Either the network's own public key, or a delegated peer's public key.
	SignerPubKey string `json:"signer_pub_key"`
	// Signature is the Ed25519 signature over Payload.
	Signature string `json:"signature"`
	// Timestamp prevents replay attacks.
	Timestamp time.Time `json:"timestamp"`
}

// DelegationRecord grants a peer the authority to sign config updates.
type DelegationRecord struct {
	// DelegatePubKey is the hex-encoded Ed25519 public key being granted.
	DelegatePubKey string `json:"delegate_pub_key"`
	// Granted is when this delegation was created.
	Granted time.Time `json:"granted"`
	// Revoked is set when the delegation is revoked.
	Revoked    bool      `json:"revoked"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	// Signature over (DelegatePubKey + Granted) by the network private key.
	Signature string `json:"signature"`
}

// Sign creates a signed ConfigUpdateEnvelope for a given payload using the
// network private key.
func Sign(privKey ed25519.PrivateKey, payload interface{}) (*ConfigUpdateEnvelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling payload: %w", err)
	}
	ts := time.Now().UTC()
	msg := buildMessage(raw, ts)
	sig := ed25519.Sign(privKey, msg)

	pubKey := privKey.Public().(ed25519.PublicKey)
	vlog.Logf("auth", "Sign: payload=%d bytes signer=%s ts=%s",
		len(raw), hex.EncodeToString(pubKey)[:16]+"...", ts.Format(time.RFC3339))
	return &ConfigUpdateEnvelope{
		Payload:      raw,
		SignerPubKey: hex.EncodeToString(pubKey),
		Signature:    hex.EncodeToString(sig),
		Timestamp:    ts,
	}, nil
}

// Verify checks that env.Signature is a valid Ed25519 signature over the
// envelope's payload by the given trusted public keys (network pub key or
// active delegates). Returns nil on success.
func Verify(env *ConfigUpdateEnvelope, trustedKeys []ed25519.PublicKey) error {
	vlog.Logf("auth", "Verify: signer=%s ts=%s trusted-keys=%d",
		env.SignerPubKey[:min(16, len(env.SignerPubKey))]+"...", env.Timestamp.Format(time.RFC3339), len(trustedKeys))
	signerRaw, err := hex.DecodeString(env.SignerPubKey)
	if err != nil {
		return fmt.Errorf("invalid signer pub key: %w", err)
	}
	signerKey := ed25519.PublicKey(signerRaw)

	// Ensure the signer is one of the trusted keys.
	trusted := false
	for _, k := range trustedKeys {
		if k.Equal(signerKey) {
			trusted = true
			break
		}
	}
	if !trusted {
		vlog.Logf("auth", "Verify: FAILED - signer %s is not trusted", env.SignerPubKey[:16]+"...")
		return fmt.Errorf("signer %s is not a trusted key", env.SignerPubKey)
	}

	sigRaw, err := hex.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	msg := buildMessage(env.Payload, env.Timestamp)
	if !ed25519.Verify(signerKey, msg, sigRaw) {
		vlog.Logf("auth", "Verify: FAILED - signature invalid")
		return fmt.Errorf("signature verification failed")
	}

	// Reject envelopes older than 30 minutes to prevent replay while still
	// tolerating common clock skew in heterogeneous mesh networks.
	age := time.Since(env.Timestamp)
	if age > 30*time.Minute || age < -5*time.Minute {
		vlog.Logf("auth", "Verify: FAILED - timestamp out of range (age=%s)", age)
		return fmt.Errorf("envelope timestamp out of acceptable range (age=%s)", age)
	}

	vlog.Logf("auth", "Verify: OK (age=%s)", age)
	return nil
}

// CreateDelegation creates a signed DelegationRecord granting delegatePubKey
// authority to sign config updates.
func CreateDelegation(networkPrivKey ed25519.PrivateKey, delegatePubKey string) (*DelegationRecord, error) {
	ts := time.Now().UTC()
	rec := &DelegationRecord{
		DelegatePubKey: delegatePubKey,
		Granted:        ts,
	}
	msg := delegationMessage(delegatePubKey, ts, false, time.Time{})
	sig := ed25519.Sign(networkPrivKey, msg)
	rec.Signature = hex.EncodeToString(sig)
	return rec, nil
}

// RevokeDelegation creates a signed revocation update for a delegation record.
func RevokeDelegation(networkPrivKey ed25519.PrivateKey, rec *DelegationRecord) (*DelegationRecord, error) {
	now := time.Now().UTC()
	rec.Revoked = true
	rec.RevokedAt = now
	msg := delegationMessage(rec.DelegatePubKey, rec.Granted, true, now)
	sig := ed25519.Sign(networkPrivKey, msg)
	rec.Signature = hex.EncodeToString(sig)
	return rec, nil
}

// VerifyDelegation checks that a DelegationRecord was signed by the network
// private key (verified against networkPubKey).
func VerifyDelegation(rec *DelegationRecord, networkPubKey ed25519.PublicKey) error {
	vlog.Logf("auth", "VerifyDelegation: delegate=%s revoked=%v",
		rec.DelegatePubKey[:min(16, len(rec.DelegatePubKey))]+"...", rec.Revoked)
	sigRaw, err := hex.DecodeString(rec.Signature)
	if err != nil {
		return fmt.Errorf("invalid delegation signature hex: %w", err)
	}
	msg := delegationMessage(rec.DelegatePubKey, rec.Granted, rec.Revoked, rec.RevokedAt)
	if !ed25519.Verify(networkPubKey, msg, sigRaw) {
		return fmt.Errorf("delegation signature verification failed")
	}
	return nil
}

// buildMessage constructs the canonical byte slice to be signed for a config envelope.
func buildMessage(payload []byte, ts time.Time) []byte {
	tsBytes := []byte(ts.UTC().Format(time.RFC3339Nano))
	msg := make([]byte, 0, len(payload)+len(tsBytes)+1)
	msg = append(msg, payload...)
	msg = append(msg, '|')
	msg = append(msg, tsBytes...)
	return msg
}

// delegationMessage constructs the canonical byte slice for a delegation record signature.
func delegationMessage(delegatePubKey string, granted time.Time, revoked bool, revokedAt time.Time) []byte {
	grantedStr := granted.UTC().Format(time.RFC3339Nano)
	revokedStr := ""
	if revoked {
		revokedStr = revokedAt.UTC().Format(time.RFC3339Nano)
	}
	msg := fmt.Sprintf("delegation|%s|%s|%v|%s", delegatePubKey, grantedStr, revoked, revokedStr)
	return []byte(msg)
}
