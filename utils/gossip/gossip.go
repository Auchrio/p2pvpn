// Package gossip implements the GossipSub-based config propagation layer.
// Config updates are published to a shared topic and consumed by every peer,
// which validates and applies them to its local config node.
package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"

	"p2pvpn/utils/auth"
	"p2pvpn/utils/config"
	"p2pvpn/utils/vlog"
)

// UpdateHandler is called after a config update has been validated and applied.
type UpdateHandler func(update *config.Network)

// Layer wraps a libp2p PubSub topic for config gossip.
type Layer struct {
	ps      *pubsub.PubSub
	topic   *pubsub.Topic
	sub     *pubsub.Subscription
	cfgNode *config.Node

	mu        sync.RWMutex
	onChange  UpdateHandler
	peerTopic string
}

// New creates a gossip layer backed by GossipSub, subscribed to a per-network
// topic derived from the network public key.
func New(ctx context.Context, h host.Host, networkPubKeyHex string, cfgNode *config.Node) (*Layer, error) {
	vlog.Logf("gossip", "creating gossip layer for network %s", networkPubKeyHex[:min(16, len(networkPubKeyHex))]+"...")
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("creating GossipSub: %w", err)
	}

	topicName := fmt.Sprintf("p2pvpn/config/%s", networkPubKeyHex)
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, fmt.Errorf("joining gossip topic %q: %w", topicName, err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		_ = topic.Close()
		return nil, fmt.Errorf("subscribing to gossip topic: %w", err)
	}

	l := &Layer{
		ps:        ps,
		topic:     topic,
		sub:       sub,
		cfgNode:   cfgNode,
		peerTopic: topicName,
	}

	vlog.Logf("gossip", "subscribed to topic %q", topicName)

	go l.receiveLoop(ctx)
	return l, nil
}

// SetUpdateHandler registers a callback invoked after each successful config update.
func (l *Layer) SetUpdateHandler(h UpdateHandler) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = h
}

// PublishSigned broadcasts a signed config update envelope to all peers.
func (l *Layer) PublishSigned(ctx context.Context, env *auth.ConfigUpdateEnvelope) error {
	vlog.Logf("gossip", "publishing signed config update (signer=%s ts=%s)",
		env.SignerPubKey[:min(16, len(env.SignerPubKey))]+"...", env.Timestamp.Format(time.RFC3339))
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshalling update envelope: %w", err)
	}
	return l.topic.Publish(ctx, data)
}

// PublishState broadcasts the entire current config (unsigned, no-op in
// host-locked networks — peers will reject it). Used during join to sync state.
func (l *Layer) PublishState(ctx context.Context) error {
	vlog.Logf("gossip", "publishing full config state")
	raw, err := l.cfgNode.Marshal()
	if err != nil {
		return fmt.Errorf("marshalling config state: %w", err)
	}
	// Wrap in an envelope with empty signature to signal a full-state sync.
	env := &gossipMessage{Type: msgTypeFullState, Payload: raw}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return l.topic.Publish(ctx, data)
}

// Close unsubscribes and closes the topic.
func (l *Layer) Close() {
	l.sub.Cancel()
	_ = l.topic.Close()
}

// receiveLoop processes incoming gossip messages from all peers.
func (l *Layer) receiveLoop(ctx context.Context) {
	vlog.Logf("gossip", "receive loop started")
	for {
		msg, err := l.sub.Next(ctx)
		if err != nil {
			return
		}
		if err := l.handleMessage(msg.Data); err != nil {
			vlog.Logf("gossip", "rejected message: %v", err)
			// Invalid or rejected update — log and continue.
			_ = err
		}
	}
}

type msgType string

const (
	msgTypeUpdate    msgType = "update"
	msgTypeFullState msgType = "full_state"
)

type gossipMessage struct {
	Type    msgType         `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// handleMessage parses and dispatches an incoming gossip message.
func (l *Layer) handleMessage(data []byte) error {
	vlog.Logf("gossip", "received message (%d bytes)", len(data))
	// Try to decode as a gossipMessage wrapper first.
	var gm gossipMessage
	if err := json.Unmarshal(data, &gm); err != nil {
		// Legacy / plain envelope.
		return l.handleEnvelope(data)
	}

	switch gm.Type {
	case msgTypeUpdate:
		return l.handleEnvelope(gm.Payload)
	case msgTypeFullState:
		return l.handleFullState(gm.Payload)
	default:
		return fmt.Errorf("unknown gossip message type: %s", gm.Type)
	}
}

func (l *Layer) handleEnvelope(raw []byte) error {
	vlog.Logf("gossip", "handling signed envelope (%d bytes)", len(raw))
	var env auth.ConfigUpdateEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("parsing config envelope: %w", err)
	}
	if err := l.cfgNode.ApplyUpdate(&env); err != nil {
		return err
	}
	l.notifyChange()
	return nil
}

func (l *Layer) handleFullState(raw []byte) error {
	vlog.Logf("gossip", "handling full-state sync (%d bytes)", len(raw))
	var cfg config.Network
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parsing full state: %w", err)
	}
	// ApplyUnsigned silently no-ops in host-locked mode, which is fine —
	// the network's canonical signed state will arrive via update envelopes.
	_ = l.cfgNode.ApplyUnsigned(&cfg)
	l.notifyChange()
	return nil
}

func (l *Layer) notifyChange() {
	l.mu.RLock()
	h := l.onChange
	l.mu.RUnlock()
	if h == nil {
		return
	}
	go func() {
		// Small debounce to avoid thundering herd on rapid updates.
		time.Sleep(50 * time.Millisecond)
		h(l.cfgNode.Get())
	}()
}
