// Package p2p manages the libp2p host, DHT-based peer discovery, and
// multiplexed streams used to exchange virtual-network packets.
package p2p

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p"
	libp2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"

	"p2pvpn/utils/vlog"
)

const (
	// VPNProtocol is the libp2p stream protocol for virtual-network packets.
	VPNProtocol = "/p2pvpn/1.0.0"
	// DiscoveryInterval controls how often the node re-advertises and re-scans.
	DiscoveryInterval = 30 * time.Second
)

// PacketHandler is called when a raw IP packet arrives from a remote peer.
type PacketHandler func(fromPeerID string, packet []byte)

// PeerEvent notifies higher layers of peer connect/disconnect.
type PeerEvent struct {
	PeerID    string
	Connected bool
}

// Node wraps a libp2p host with DHT-based peer discovery and a simple
// custom protocol for forwarding virtual-network IP packets.
type Node struct {
	Host       host.Host
	dht        *dht.IpfsDHT
	discovery  *routing.RoutingDiscovery
	rendezvous string // hex-encoded network public key used as topic

	mu            sync.RWMutex
	streams       map[peer.ID]network.Stream
	onPacket      PacketHandler
	peerEventsCh  chan PeerEvent

	cancel context.CancelFunc
}

// New creates a libp2p Node. identityKey is this daemon's persistent identity,
// rendezvous is the network public key (hex) used as the DHT advertisement topic.
// onPacket is the callback for incoming VPN packets (may be nil initially and set
// later via SetPacketHandler, but setting it here avoids the startup race window).
// extraPeers is an optional list of peer multiaddrs to connect to immediately
// (useful when nodes are behind NAT and can't rely solely on DHT discovery).
func New(ctx context.Context, identityKey crypto.PrivKey, rendezvous string, listenPort int, extraPeers []string, onPacket PacketHandler) (*Node, error) {
	vlog.Logf("p2p", "creating libp2p host: rendezvous=%s port=%d extra-peers=%d", rendezvous[:min(16, len(rendezvous))]+"...", listenPort, len(extraPeers))
	opts := []libp2pconfig.Option{
		libp2p.Identity(identityKey),
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort),
			fmt.Sprintf("/ip6/::/tcp/%d", listenPort),
		),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating libp2p host: %w", err)
	}
	vlog.Logf("p2p", "libp2p host created: id=%s", h.ID())
	for _, addr := range h.Addrs() {
		vlog.Logf("p2p", "  listen: %s", addr)
	}

	kadDHT, err := dht.New(ctx, h,
		dht.Mode(dht.ModeAutoServer),
		dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...),
	)
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("creating DHT: %w", err)
	}

	if err := kadDHT.Bootstrap(ctx); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("bootstrapping DHT: %w", err)
	}
	vlog.Logf("p2p", "DHT bootstrapped successfully")

	disc := routing.NewRoutingDiscovery(kadDHT)

	nodeCtx, cancel := context.WithCancel(ctx)
	n := &Node{
		Host:         h,
		dht:          kadDHT,
		discovery:    disc,
		rendezvous:   rendezvous,
		streams:      make(map[peer.ID]network.Stream),
		peerEventsCh: make(chan PeerEvent, 64),
		onPacket:     onPacket,
		cancel:       cancel,
	}

	h.SetStreamHandler(VPNProtocol, n.handleStream)
	// Only DisconnectedF — we deliberately do NOT use ConnectedF here because it
	// fires for every libp2p connection including DHT bootstrap nodes, relay
	// peers, etc. A peer is only treated as a VPN peer once they open (or we
	// open) a stream using VPNProtocol.
	h.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(_ network.Network, conn network.Conn) {
			n.onDisconnect(conn.RemotePeer())
		},
	})

	// mDNS — discovers peers on the same local network without internet access.
	// Service name uses the first 16 hex chars of the network key to scope
	// discovery per-network while staying within DNS label length limits.
	mdnsTag := "_p2pvpn._udp"
	if len(rendezvous) >= 8 {
		mdnsTag = "_p2pvpn-" + rendezvous[:8] + "._udp"
	}
	mdnsSvc := mdns.NewMdnsService(h, mdnsTag, n)
	if err := mdnsSvc.Start(); err != nil {
		fmt.Printf("[p2p] mDNS start warning: %v\n", err)
	} else {
		vlog.Logf("p2p", "mDNS service started: tag=%s", mdnsTag)
	}

	// Connect immediately to any user-supplied bootstrap peers.
	for _, addrStr := range extraPeers {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			fmt.Printf("[p2p] invalid peer address %q: %v\n", addrStr, err)
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			fmt.Printf("[p2p] could not parse peer address %q: %v\n", addrStr, err)
			continue
		}
		go func(info peer.AddrInfo) {
			vlog.Logf("p2p", "connecting to bootstrap peer %s at %v", info.ID, info.Addrs)
			connectCtx, cancel := context.WithTimeout(nodeCtx, 30*time.Second)
			defer cancel()
			if err := n.Host.Connect(connectCtx, info); err != nil {
				fmt.Printf("[p2p] could not connect to peer %s: %v\n", info.ID, err)
				vlog.Logf("p2p", "bootstrap peer %s connect FAILED: %v", info.ID, err)
				return
			}
			fmt.Printf("[p2p] connected to peer %s, opening VPN stream\n", info.ID)
			vlog.Logf("p2p", "bootstrap peer %s connected, opening VPN stream", info.ID)
			// Open the VPN-protocol stream so both sides register this peer.
			_, _ = n.streamFor(info.ID)
		}(*pi)
	}

	go n.discoverLoop(nodeCtx)
	return n, nil
}

// HandlePeerFound implements mdns.Notifee. Called when a peer is found on the
// local network via mDNS. Dials the peer; the VPN connect event is emitted
// later when an actual VPNProtocol stream is exchanged.
func (n *Node) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.Host.ID() {
		return
	}
	// Check for an existing VPN stream (not just TCP connection). A peer
	// can be TCP-connected via DHT/relay without having a VPN stream.
	n.mu.RLock()
	_, hasStream := n.streams[pi.ID]
	n.mu.RUnlock()
	if hasStream {
		return
	}
	vlog.Logf("p2p", "mDNS peer found: %s addrs=%v (no VPN stream yet)", pi.ID, pi.Addrs)
	go func() {
		// Ensure TCP connection first.
		if n.Host.Network().Connectedness(pi.ID) != network.Connected {
			connectCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := n.Host.Connect(connectCtx, pi); err != nil {
				vlog.Logf("p2p", "mDNS: dial %s FAILED: %v", pi.ID, err)
				return
			}
			vlog.Logf("p2p", "mDNS: dial %s OK", pi.ID)
		}
		vlog.Logf("p2p", "mDNS: opening VPN stream to %s", pi.ID)
		if _, err := n.streamFor(pi.ID); err != nil {
			vlog.Logf("p2p", "mDNS: streamFor(%s) FAILED: %v", pi.ID, err)
		}
	}()
}

// SetPacketHandler registers the callback invoked for every incoming VPN packet.
func (n *Node) SetPacketHandler(h PacketHandler) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onPacket = h
}

// PeerEvents returns a channel that emits connection/disconnection events.
func (n *Node) PeerEvents() <-chan PeerEvent { return n.peerEventsCh }

// SendPacket sends a raw IP packet to the peer with peerID via a persistent stream.
func (n *Node) SendPacket(peerID peer.ID, packet []byte) error {
	vlog.Logf("p2p", "TX → %s: %s", peerID, vlog.PacketSummary(packet))
	s, err := n.streamFor(peerID)
	if err != nil {
		return fmt.Errorf("getting stream for %s: %w", peerID, err)
	}

	// Simple length-prefixed framing: 2-byte big-endian length + payload.
	frame := make([]byte, 2+len(packet))
	frame[0] = byte(len(packet) >> 8)
	frame[1] = byte(len(packet))
	copy(frame[2:], packet)

	_, err = s.Write(frame)
	if err != nil {
		vlog.Logf("p2p", "TX write error to %s: %v (evicting stream)", peerID, err)
		// Stream is broken. Evict it so the next call opens a fresh one.
		n.mu.Lock()
		if cur, ok := n.streams[peerID]; ok && cur == s {
			_ = s.Close()
			delete(n.streams, peerID)
		}
		n.mu.Unlock()
		return fmt.Errorf("write to %s: %w", peerID, err)
	}
	return nil
}

// PeerPubKeyHex returns the hex-encoded Ed25519 public key of a peer.
func PeerPubKeyHex(p peer.ID) (string, error) {
	pub, err := p.ExtractPublicKey()
	if err != nil {
		return "", err
	}
	raw, err := pub.Raw()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// Close shuts down the libp2p host and closes the peer events channel.
func (n *Node) Close() error {
	n.cancel()
	err := n.Host.Close()
	close(n.peerEventsCh)
	return err
}

// discoverLoop periodically advertises this node and scans for peers with the
// same rendezvous topic. It uses an aggressive early-retry strategy:
// the first scan is delayed 3 s to let the DHT routing table populate,
// then retries every 5 s for the first 2 minutes, then every 30 s steady-state.
func (n *Node) discoverLoop(ctx context.Context) {
	vlog.Logf("p2p", "discovery loop started, waiting 3s for DHT bootstrap")
	// Brief wait for DHT bootstrap to connect to at least a few nodes so
	// advertisement and FindPeers have a populated routing table to work with.
	select {
	case <-time.After(3 * time.Second):
	case <-ctx.Done():
		return
	}

	util.Advertise(ctx, n.discovery, n.rendezvous)
	vlog.Logf("p2p", "initial DHT advertise complete, running first findPeers")
	n.findPeers(ctx)

	// Aggressive early retries, then settle to steady-state interval.
	earlyTicker := time.NewTicker(5 * time.Second)
	earlyStop := time.NewTimer(2 * time.Minute)
	steadyTicker := time.NewTicker(DiscoveryInterval)
	steadyTicker.Stop() // start stopped; swap after earlyStop fires
	defer earlyTicker.Stop()
	defer steadyTicker.Stop()

	for {
		select {
		case <-earlyTicker.C:
			util.Advertise(ctx, n.discovery, n.rendezvous)
			n.findPeers(ctx)
		case <-earlyStop.C:
			earlyTicker.Stop()
			steadyTicker.Reset(DiscoveryInterval)
		case <-steadyTicker.C:
			util.Advertise(ctx, n.discovery, n.rendezvous)
			n.findPeers(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// findPeers queries the DHT for peers advertising the rendezvous topic and
// opens a VPNProtocol stream to any that don't already have one.
func (n *Node) findPeers(ctx context.Context) {
	vlog.Logf("p2p", "findPeers: querying DHT for rendezvous=%s", n.rendezvous[:min(16, len(n.rendezvous))]+"...")
	peerCh, err := n.discovery.FindPeers(ctx, n.rendezvous)
	if err != nil {
		vlog.Logf("p2p", "findPeers: DHT query failed: %v", err)
		return
	}
	found := 0
	skippedSelf := 0
	skippedHasStream := 0
	attempted := 0
	for p := range peerCh {
		if p.ID == n.Host.ID() {
			skippedSelf++
			continue
		}
		// Check whether we already have a VPN stream for this peer.
		n.mu.RLock()
		_, hasStream := n.streams[p.ID]
		n.mu.RUnlock()
		if hasStream {
			skippedHasStream++
			continue // already fully connected
		}
		found++
		vlog.Logf("p2p", "findPeers: discovered new peer %s addrs=%v, attempting VPN stream", p.ID, p.Addrs)
		attempted++
		go func(pi peer.AddrInfo) {
			// Connect at the TCP level if not already connected.
			if n.Host.Network().Connectedness(pi.ID) != network.Connected {
				vlog.Logf("p2p", "findPeers: dialing %s at %v", pi.ID, pi.Addrs)
				connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				if err := n.Host.Connect(connectCtx, pi); err != nil {
					vlog.Logf("p2p", "findPeers: dial %s FAILED: %v", pi.ID, err)
					return
				}
				vlog.Logf("p2p", "findPeers: dial %s OK, opening VPN stream", pi.ID)
			} else {
				vlog.Logf("p2p", "findPeers: %s already connected at TCP level, opening VPN stream", pi.ID)
			}
			// Open the VPN protocol stream.
			if _, err := n.streamFor(pi.ID); err != nil {
				vlog.Logf("p2p", "findPeers: streamFor(%s) FAILED: %v", pi.ID, err)
			}
		}(p)
	}
	vlog.Logf("p2p", "findPeers: done — found=%d attempted=%d skipped(self=%d, hasStream=%d)",
		found, attempted, skippedSelf, skippedHasStream)
}

// handleStream is called by libp2p when a remote peer opens a VPNProtocol
// stream. This is the authoritative signal that the remote peer is a VPN peer
// (not a DHT bootstrap node or relay). Emits a connect event then reads
// length-prefixed frames and calls onPacket.
func (n *Node) handleStream(s network.Stream) {
	peerID := s.Conn().RemotePeer()
	peerIDStr := peerID.String()
	vlog.Logf("p2p", "incoming VPN stream from %s (remote addr: %s)", peerIDStr, s.Conn().RemoteMultiaddr())

	// This peer has spoken VPNProtocol, so they are definitively a VPN peer.
	// The daemon's onPeerConnect is idempotent so duplicate events are safe.
	n.peerEventsCh <- PeerEvent{PeerID: peerIDStr, Connected: true}

	// Proactively open a reverse outgoing stream so we can send packets back.
	// Without this, the remote can receive our packets but we can't receive
	// theirs until findPeers/mDNS happens to open the reverse stream.
	n.mu.RLock()
	_, hasOutgoing := n.streams[peerID]
	n.mu.RUnlock()
	if !hasOutgoing {
		vlog.Logf("p2p", "no outgoing stream to %s, opening reverse stream", peerIDStr)
		go func() {
			if _, err := n.streamFor(peerID); err != nil {
				vlog.Logf("p2p", "reverse streamFor(%s) FAILED: %v", peerIDStr, err)
			} else {
				vlog.Logf("p2p", "reverse stream to %s opened OK", peerIDStr)
			}
		}()
	}

	defer func() {
		s.Close()
		vlog.Logf("p2p", "incoming stream from %s closed", peerIDStr)
	}()

	buf := make([]byte, 1<<16+2)
	for {
		// Read 2-byte length prefix.
		if _, err := io.ReadFull(s, buf[:2]); err != nil {
			vlog.Logf("p2p", "handleStream(%s): read length prefix error: %v", peerIDStr, err)
			return
		}
		pktLen := int(buf[0])<<8 | int(buf[1])
		if pktLen == 0 || pktLen > 1<<16 {
			vlog.Logf("p2p", "handleStream(%s): invalid frame length %d, closing", peerIDStr, pktLen)
			return
		}
		if _, err := io.ReadFull(s, buf[2:2+pktLen]); err != nil {
			vlog.Logf("p2p", "handleStream(%s): read payload error: %v", peerIDStr, err)
			return
		}
		pkt := make([]byte, pktLen)
		copy(pkt, buf[2:2+pktLen])

		vlog.Logf("p2p", "RX ← %s: %s", peerIDStr, vlog.PacketSummary(pkt))

		n.mu.RLock()
		h := n.onPacket
		n.mu.RUnlock()
		if h != nil {
			h(peerIDStr, pkt)
		}
	}
}

// streamFor returns (or creates) a persistent outgoing VPN stream to peerID.
func (n *Node) streamFor(peerID peer.ID) (network.Stream, error) {
	n.mu.RLock()
	s, ok := n.streams[peerID]
	n.mu.RUnlock()
	if ok {
		return s, nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	// Double-check.
	if s, ok = n.streams[peerID]; ok {
		return s, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := n.Host.NewStream(ctx, peerID, VPNProtocol)
	if err != nil {
		vlog.Logf("p2p", "streamFor(%s): NewStream FAILED: %v", peerID, err)
		return nil, err
	}
	vlog.Logf("p2p", "streamFor(%s): VPN stream opened (remote addr: %s)", peerID, s.Conn().RemoteMultiaddr())
	// Opening a VPN-protocol stream to a peer is the authoritative signal that
	// they are a VPN peer. Emit a connect event now (the remote side does the
	// same in handleStream).
	n.streams[peerID] = s
	// Send outside the lock to avoid deadlock with blocking channel.
	go func() {
		n.peerEventsCh <- PeerEvent{PeerID: peerID.String(), Connected: true}
	}()
	return s, nil
}

// onDisconnect cleans up stream state for a disconnected peer.
// Only emits a disconnect event if the peer was actually a VPN peer
// (i.e. had an active VPNProtocol stream) AND all connections to the
// peer are gone. DisconnectedF fires per-connection, so we must check
// Connectedness to avoid prematurely tearing down a multi-connection peer.
func (n *Node) onDisconnect(peerID peer.ID) {
	// If other connections remain, the peer is still reachable — do nothing.
	if n.Host.Network().Connectedness(peerID) == network.Connected {
		return
	}

	n.mu.Lock()
	s, wasVPNPeer := n.streams[peerID]
	if wasVPNPeer {
		_ = s.Close()
		delete(n.streams, peerID)
	}
	n.mu.Unlock()

	if !wasVPNPeer {
		return // not our peer — ignore
	}

	vlog.Logf("p2p", "emitting disconnect event for VPN peer %s", peerID)
	n.peerEventsCh <- PeerEvent{PeerID: peerID.String(), Connected: false}
}
