// Package p2p manages the libp2p host, DHT-based peer discovery, and
// multiplexed streams used to exchange virtual-network packets.
package p2p

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p"
	libp2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
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

	// Declared before host creation so the AutoRelay peer-source closure can
	// capture the pointer. kadDHT is assigned after the host is created, but
	// the closure is only called later (when AutoRelay needs relay candidates).
	var kadDHT *dht.IpfsDHT
	var h host.Host

	// relayHopProto is the protocol ID for relay v2 hop service.
	// Only peers that advertise this can actually serve as relay nodes.
	const relayHopProto = "/libp2p/circuit/relay/0.2.0/hop"

	// peerSource feeds the AutoRelay subsystem with candidate relay nodes.
	// AutoRelay calls this repeatedly until it successfully reserves a relay slot.
	//
	// Strategy:
	//  1. Wait for DHT routing table to populate (up to 10 s).
	//  2. Scan connected peers for relay v2 hop support — send those FIRST
	//     because they are the only peers that can actually accept reservations.
	//  3. Fall back to remaining connected + DHT peers (some may support relay
	//     but we don't have protocol info yet).
	//  4. Last resort: IPFS bootstrap peers.
	peerSource := func(ctx context.Context, num int) <-chan peer.AddrInfo {
		ch := make(chan peer.AddrInfo, num)
		go func() {
			defer close(ch)
			if kadDHT == nil || h == nil {
				return
			}

			// Wait for the DHT routing table to have at least 1 peer.
			waitStart := time.Now()
			for kadDHT.RoutingTable().Size() == 0 {
				if time.Since(waitStart) > 10*time.Second {
					fmt.Printf("[nat] peerSource: DHT still empty after 10s\n")
					break
				}
				select {
				case <-time.After(500 * time.Millisecond):
				case <-ctx.Done():
					return
				}
			}

			connPeers := h.Network().Peers()
			sent := 0
			relayCapable := 0
			seen := make(map[peer.ID]bool)

			// Helper to emit a single candidate.
			send := func(p peer.ID, tag string) bool {
				if p == h.ID() || seen[p] {
					return true // skip but continue
				}
				addrs := h.Peerstore().Addrs(p)
				if len(addrs) == 0 {
					return true
				}
				seen[p] = true
				vlog.Logf("nat", "  relay candidate (%s): %s", tag, p)
				select {
				case ch <- peer.AddrInfo{ID: p, Addrs: addrs}:
					sent++
					return true
				case <-ctx.Done():
					return false
				}
			}

			// Phase 1: connected peers that support relay v2 hop (highest value).
			for _, p := range connPeers {
				protos, err := h.Peerstore().GetProtocols(p)
				if err != nil {
					continue
				}
				isRelay := false
				for _, proto := range protos {
					if string(proto) == relayHopProto {
						isRelay = true
						break
					}
				}
				if isRelay {
					relayCapable++
					if !send(p, "relay-v2") {
						return
					}
				}
			}

			// Phase 2: remaining DHT routing table peers.
			for _, p := range kadDHT.RoutingTable().ListPeers() {
				if !send(p, "DHT") {
					return
				}
			}

			// Phase 3: remaining connected peers.
			for _, p := range connPeers {
				if !send(p, "connected") {
					return
				}
			}

			// Phase 4: IPFS bootstrap peers as last resort.
			for _, bpi := range dht.GetDefaultBootstrapPeerAddrInfos() {
				if bpi.ID == h.ID() || seen[bpi.ID] {
					continue
				}
				seen[bpi.ID] = true
				select {
				case ch <- bpi:
					sent++
				case <-ctx.Done():
					return
				}
			}

			fmt.Printf("[nat] peerSource: %d relay-capable, %d total candidates (from %d connected)\n",
				relayCapable, sent, len(connPeers))
		}()
		return ch
	}

	opts := []libp2pconfig.Option{
		libp2p.Identity(identityKey),
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort),
			fmt.Sprintf("/ip6/::/tcp/%d", listenPort),
			// QUIC — required for relay circuits through QUIC-based relays
			// (most IPFS infra uses QUIC). Also enables better hole-punching.
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", listenPort),
			fmt.Sprintf("/ip6/::/udp/%d/quic-v1", listenPort),
			// WebTransport — works through restrictive firewalls that block
			// raw UDP/TCP but allow HTTPS-like traffic.
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1/webtransport", listenPort),
			fmt.Sprintf("/ip6/::/udp/%d/quic-v1/webtransport", listenPort),
		),
		// NAT traversal stack:
		//   1. NATPortMap — attempts UPnP / NAT-PMP port mapping so the node
		//      is directly reachable without hole-punching.
		//   2. ForceReachabilityPrivate — always assume we're behind NAT and
		//      immediately seek relays, instead of waiting for AutoNAT probes
		//      (which fail on CGNAT because the return probes can't reach us).
		//      For a VPN daemon this is the correct default — the slight
		//      overhead of an unnecessary relay reservation on a public IP is
		//      negligible.
		//   3. EnableRelay — allows using relay nodes for circuit connections.
		//   4. EnableAutoRelayWithPeerSource — immediately discovers and
		//      reserves relay slots using candidates from the DHT routing table
		//      (or IPFS bootstrap peers as fallback).
		//   5. EnableHolePunching — once peers connect through a relay, they
		//      attempt a direct connection via coordinated hole-punching.
		//   6. EnableNATService — runs the AutoNAT service to help *other*
		//      peers determine their own reachability (good citizen).
		libp2p.NATPortMap(),
		libp2p.ForceReachabilityPrivate(),
		libp2p.EnableRelay(),
		libp2p.EnableAutoRelayWithPeerSource(peerSource),
		libp2p.EnableHolePunching(),
		libp2p.EnableNATService(),
	}

	var err error
	h, err = libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating libp2p host: %w", err)
	}
	vlog.Logf("p2p", "libp2p host created: id=%s", h.ID())
	for _, addr := range h.Addrs() {
		vlog.Logf("p2p", "  listen: %s", addr)
	}

	kadDHT, err = dht.New(ctx, h,
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
	vlog.Logf("p2p", "DHT bootstrap initiated")

	// Explicitly connect to IPFS bootstrap peers in parallel and wait for at
	// least one to succeed. dht.Bootstrap() only starts the process; it doesn't
	// wait for connections, so the routing table can stay empty for a long time
	// on slow mobile networks. This explicit connect ensures we have at least
	// some peers in the routing table before discovery and AutoRelay kick in.
	bootstrapPeers := dht.GetDefaultBootstrapPeerAddrInfos()
	var bootstrapWg sync.WaitGroup
	var bootstrapOK int32 // atomic
	for _, bpi := range bootstrapPeers {
		bootstrapWg.Add(1)
		go func(pi peer.AddrInfo) {
			defer bootstrapWg.Done()
			connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := h.Connect(connectCtx, pi); err != nil {
				vlog.Logf("p2p", "bootstrap connect %s FAILED: %v", pi.ID, err)
				return
			}
			vlog.Logf("p2p", "bootstrap connect %s OK", pi.ID)
			atomic.AddInt32(&bootstrapOK, 1)
		}(bpi)
	}

	// Wait up to 10 s for at least one bootstrap peer, but don't block forever.
	done := make(chan struct{})
	go func() { bootstrapWg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	case <-ctx.Done():
	}
	connected := atomic.LoadInt32(&bootstrapOK)
	fmt.Printf("[p2p] Bootstrap: %d/%d IPFS peers connected, DHT routing table: %d\n",
		connected, len(bootstrapPeers), kadDHT.RoutingTable().Size())

	disc := routing.NewRoutingDiscovery(kadDHT)

	// Print identity and rendezvous so the user can verify both nodes share
	// the same network key. This is the #1 thing to check when discovery fails.
	fmt.Printf("[p2p] Local peer ID: %s\n", h.ID())
	fmt.Printf("[p2p] Network topic : %s\n", rendezvous)

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
	go n.monitorNATEvents(nodeCtx)
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

// monitorNATEvents subscribes to the libp2p event bus and logs NAT traversal
// events so the user can see relay address updates, NAT device type detection,
// and connection status. Important events are always printed; verbose detail is
// gated behind -v.
//
// Also runs a 5-second check: if no relay address has been obtained yet, it
// prints diagnostic info to help troubleshoot connectivity issues.
func (n *Node) monitorNATEvents(ctx context.Context) {
	bus := n.Host.EventBus()

	// Subscribe to the events we care about.
	sub, err := bus.Subscribe([]interface{}{
		new(event.EvtLocalReachabilityChanged),
		new(event.EvtNATDeviceTypeChanged),
		new(event.EvtLocalAddressesUpdated),
		new(event.EvtAutoRelayAddrsUpdated),
	})
	if err != nil {
		fmt.Printf("[nat] WARNING: could not subscribe to event bus: %v\n", err)
		return
	}
	defer sub.Close()

	fmt.Printf("[nat] Reachability forced to PRIVATE — actively seeking relay from startup\n")

	// 5-second relay health check.
	go func() {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
		addrs := n.Host.Addrs()
		hasRelay := false
		for _, a := range addrs {
			if strings.Contains(a.String(), "p2p-circuit") {
				hasRelay = true
			}
		}
		fmt.Printf("[nat] 5s check — addresses (%d):\n", len(addrs))
		for _, a := range addrs {
			fmt.Printf("[nat]   %s\n", a)
		}
		if hasRelay {
			fmt.Printf("[nat] ✓ Relay address available — peers behind NAT can reach us\n")
		} else {
			fmt.Printf("[nat] ⚠ No relay address yet after 5s — still connecting to relay candidates\n")
			fmt.Printf("[nat]   DHT routing table size: %d\n", n.dht.RoutingTable().Size())
			fmt.Printf("[nat]   This is normal on slow connections; relay will activate once a candidate responds\n")
		}

		// Also check VPN peers.
		n.mu.RLock()
		peerCount := len(n.streams)
		n.mu.RUnlock()
		if peerCount == 0 {
			fmt.Printf("[nat] No VPN peers found yet — still discovering via DHT\n")
		} else {
			fmt.Printf("[nat] ✓ %d VPN peer(s) connected\n", peerCount)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-sub.Out():
			switch e := evt.(type) {
			case event.EvtLocalReachabilityChanged:
				switch e.Reachability {
				case network.ReachabilityPublic:
					fmt.Printf("[nat] AutoNAT: reachability = PUBLIC (directly reachable from internet)\n")
				case network.ReachabilityPrivate:
					fmt.Printf("[nat] AutoNAT: reachability = PRIVATE (behind NAT — AutoRelay will find relays)\n")
				default:
					fmt.Printf("[nat] AutoNAT: reachability = UNKNOWN\n")
				}
				vlog.Logf("nat", "EvtLocalReachabilityChanged: %s", e.Reachability)

			case event.EvtNATDeviceTypeChanged:
				fmt.Printf("[nat] NAT device type: %s (transport: %s)\n",
					e.NatDeviceType, e.TransportProtocol)
				vlog.Logf("nat", "EvtNATDeviceTypeChanged: type=%s transport=%s",
					e.NatDeviceType, e.TransportProtocol)

			case event.EvtAutoRelayAddrsUpdated:
				if len(e.RelayAddrs) > 0 {
					fmt.Printf("[nat] AutoRelay: relay addresses updated (%d):\n", len(e.RelayAddrs))
					for _, a := range e.RelayAddrs {
						fmt.Printf("[nat]   %s\n", a)
					}
					fmt.Printf("[nat] ✓ Relay active — peers can reach us via circuit relay\n")
				} else {
					fmt.Printf("[nat] AutoRelay: no relay addresses (looking for relays...)\n")
				}
				vlog.Logf("nat", "EvtAutoRelayAddrsUpdated: %d addrs", len(e.RelayAddrs))

			case event.EvtLocalAddressesUpdated:
				added := 0
				removed := 0
				for _, u := range e.Current {
					if u.Action == event.Added {
						added++
						vlog.Logf("nat", "  address added: %s", u.Address)
						if strings.Contains(u.Address.String(), "p2p-circuit") {
							fmt.Printf("[nat] New relay address: %s\n", u.Address)
						}
					}
				}
				for _, u := range e.Removed {
					removed++
					vlog.Logf("nat", "  address removed: %s", u.Address)
				}
				if added > 0 || removed > 0 {
					vlog.Logf("nat", "EvtLocalAddressesUpdated: +%d -%d (total=%d)",
						added, removed, len(e.Current))
				}
			}
		}
	}
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

	n.advertise(ctx)
	fmt.Printf("[p2p] Initial DHT advertise complete, searching for peers...\n")
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
			n.advertise(ctx)
			n.findPeers(ctx)
		case <-earlyStop.C:
			earlyTicker.Stop()
			steadyTicker.Reset(DiscoveryInterval)
		case <-steadyTicker.C:
			n.advertise(ctx)
			n.findPeers(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// advertise publishes a provider record to the DHT so other nodes with the
// same rendezvous can discover us. Logs errors at user-visible level.
func (n *Node) advertise(ctx context.Context) {
	util.Advertise(ctx, n.discovery, n.rendezvous)
	vlog.Logf("p2p", "Advertise done: rt-size=%d", n.dht.RoutingTable().Size())
}

// findPeers queries the DHT for peers advertising the rendezvous topic and
// opens a VPNProtocol stream to any that don't already have one.
func (n *Node) findPeers(ctx context.Context) {
	vlog.Logf("p2p", "findPeers: querying DHT for rendezvous=%s", n.rendezvous[:min(16, len(n.rendezvous))]+"...")

	// Use a child context with a timeout so we don't block forever on a DHT
	// walk that returns nothing.
	findCtx, findCancel := context.WithTimeout(ctx, 30*time.Second)
	defer findCancel()

	peerCh, err := n.discovery.FindPeers(findCtx, n.rendezvous)
	if err != nil {
		fmt.Printf("[p2p] FindPeers FAILED: %v\n", err)
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
		fmt.Printf("[p2p] Discovered VPN peer %s (%d addrs), connecting...\n", p.ID, len(p.Addrs))
		vlog.Logf("p2p", "findPeers: discovered new peer %s addrs=%v, attempting VPN stream", p.ID, p.Addrs)
		attempted++
		go func(pi peer.AddrInfo) {
			// Connect at the TCP level if not already connected.
			if n.Host.Network().Connectedness(pi.ID) != network.Connected {
				vlog.Logf("p2p", "findPeers: dialing %s at %v", pi.ID, pi.Addrs)
				connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				if err := n.Host.Connect(connectCtx, pi); err != nil {
					fmt.Printf("[p2p] Failed to connect to peer %s: %v\n", pi.ID, err)
					vlog.Logf("p2p", "findPeers: dial %s FAILED: %v", pi.ID, err)
					return
				}
				vlog.Logf("p2p", "findPeers: dial %s OK, opening VPN stream", pi.ID)
			} else {
				vlog.Logf("p2p", "findPeers: %s already connected at TCP level, opening VPN stream", pi.ID)
			}
			// Open the VPN protocol stream.
			if _, err := n.streamFor(pi.ID); err != nil {
				fmt.Printf("[p2p] Failed to open VPN stream to %s: %v\n", pi.ID, err)
				vlog.Logf("p2p", "findPeers: streamFor(%s) FAILED: %v", pi.ID, err)
			} else {
				fmt.Printf("[p2p] ✓ VPN stream opened to %s\n", pi.ID)
			}
		}(p)
	}

	// Print a user-visible summary every cycle so the operator can see progress.
	n.mu.RLock()
	vpnPeerCount := len(n.streams)
	n.mu.RUnlock()
	if found > 0 {
		fmt.Printf("[p2p] FindPeers: discovered %d new, %d already connected, %d total VPN peers\n",
			found, skippedHasStream, vpnPeerCount+found)
	} else if vpnPeerCount == 0 {
		fmt.Printf("[p2p] FindPeers: no VPN peers found yet (DHT rt=%d, connected=%d) — retrying...\n",
			n.dht.RoutingTable().Size(), len(n.Host.Network().Peers()))
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
