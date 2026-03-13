// Package daemon is the long-running process that owns the libp2p node, TUN
// interface, IP manager, config node, gossip layer, and whitelist enforcer.
// The CLI communicates with a running daemon via a Unix domain socket using a
// simple JSON-RPC-like protocol.
package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"

	"errors"

	"p2pvpn/utils/auth"
	"p2pvpn/utils/config"
	"p2pvpn/utils/gossip"
	"p2pvpn/utils/ipmgr"
	"p2pvpn/utils/keypair"
	"p2pvpn/utils/netmon"
	"p2pvpn/utils/p2p"
	"p2pvpn/utils/store"
	"p2pvpn/utils/tun"
	"p2pvpn/utils/vlog"
	"p2pvpn/utils/webui"
	"p2pvpn/utils/whitelist"
	tunnelproxy "p2pvpn/web-tunnel/proxy"
)

// ErrNetworkChanged is returned by Start when the daemon exits because the
// host's network configuration changed (e.g. connected to a new WiFi network).
// The calling code should treat this as a request to restart the daemon.
var ErrNetworkChanged = errors.New("host network changed, restart required")

// ErrSetupComplete is returned by StartSetupMode when the user has submitted
// a network configuration via the WebUI.  The caller should restart the daemon
// with the full config loaded from saved.conf.
var ErrSetupComplete = errors.New("setup complete, restart with config")

// DefaultSocketPath is the Unix socket the daemon listens on.
var DefaultSocketPath = defaultSocketPath()

func defaultSocketPath() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "p2pvpn", "p2pvpn.sock")
	}
	return "/run/p2pvpn.sock"
}

// Daemon is the top-level coordinator.
type Daemon struct {
	st          *store.Store
	p2pNode     *p2p.Node
	tunIface    tun.Iface
	ipMgr       *ipmgr.Manager
	cfgNode     *config.Node
	gossipLayer *gossip.Layer
	wlEnforcer  *whitelist.Enforcer

	networkPub  ed25519.PublicKey
	networkPriv ed25519.PrivateKey // nil on non-authority peers
	localPeerID string
	assignedIP  net.IP
	configIP    net.IP // the .1 address bound to the TUN for the WebUI

	peerIPs   map[string]net.IP // peerID -> virtual IP
	peerIPsMu sync.RWMutex

	noPeersTimer *time.Timer // fires after 1 min of zero connected peers

	ipcListener    net.Listener
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	networkChanged bool // set when the daemon is restarting due to host network change
}

// Config holds startup parameters for the daemon.
type Config struct {
	StateDir       string
	SocketPath     string
	NetworkPubKey  string   // hex Ed25519 public key of the network
	NetworkPrivKey string   // optional; only on authority node
	PreferredIP    string   // optional; preferred virtual IP
	CIDR           string   // CIDR block for virtual IP assignment (e.g. "10.42.0.0/24")
	HostLocked     bool
	ListenPort     int
	BootstrapPeers []string // optional peer multiaddrs for initial discovery (e.g. from --peer)
	Verbose        bool     // enable verbose debug logging
}

// Start creates and runs a new Daemon, returning when the context is cancelled.
func Start(ctx context.Context, cfg Config) error {
	if cfg.Verbose {
		vlog.Enable()
	}
	vlog.Logf("daemon", "starting daemon (verbose mode enabled)")
	vlog.Logf("daemon", "config: network-pub=%s cidr=%s port=%d host-locked=%v preferred-ip=%q peers=%v",
		cfg.NetworkPubKey, cfg.CIDR, cfg.ListenPort, cfg.HostLocked, cfg.PreferredIP, cfg.BootstrapPeers)

	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = store.DefaultStateDir
	}
	st, err := store.New(stateDir)
	if err != nil {
		return err
	}

	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	// Load or generate the peer identity key.
	peerPrivKey, loadErr := keypair.LoadPeerPrivKey(st.PeerKeyPath())
	if loadErr != nil {
		vlog.Logf("daemon", "no existing peer key at %s, generating new one", st.PeerKeyPath())
		kp, err := keypair.GeneratePeerKeypair()
		if err != nil {
			return fmt.Errorf("generating peer identity: %w", err)
		}
		if err := keypair.SavePeerPrivKey(st.PeerKeyPath(), kp.PrivKey); err != nil {
			return fmt.Errorf("saving peer identity: %w", err)
		}
		peerPrivKey = kp.PrivKey
	} else {
		vlog.Logf("daemon", "loaded existing peer key from %s", st.PeerKeyPath())
	}

	// Decode network public key.
	networkPub, err := keypair.DecodeNetworkPublicKey(cfg.NetworkPubKey)
	if err != nil {
		return fmt.Errorf("invalid network public key: %w", err)
	}

	var networkPriv ed25519.PrivateKey
	if cfg.NetworkPrivKey != "" {
		vlog.Logf("daemon", "decoding network PRIVATE key (authority mode)")
		networkPriv, err = keypair.DecodeNetworkPrivateKey(cfg.NetworkPrivKey)
		if err != nil {
			return fmt.Errorf("invalid network private key: %w", err)
		}
	} else {
		vlog.Logf("daemon", "no network private key supplied (non-authority mode)")
	}

	// Build initial config.
	cidr := cfg.CIDR
	if cidr == "" {
		cidr = "10.42.0.0/24"
	}
	netCfg := config.DefaultNetwork(cidr, cfg.NetworkPubKey)

	// Try to restore previously-saved network config so settings (whitelist,
	// delegates, etc.) survive daemon restarts.
	if saved, err := st.LoadNetConfig(); err == nil && saved != nil {
		var restored config.Network
		if err := json.Unmarshal(saved, &restored); err == nil {
			vlog.Logf("daemon", "restored saved network config (updated-at=%s)", restored.UpdatedAt.Format(time.RFC3339))
			netCfg = &restored
			// Preserve the host pubkey from the startup config in case it was
			// missing from the saved state.
			if netCfg.HostPubKey == "" {
				netCfg.HostPubKey = cfg.NetworkPubKey
			}
		} else {
			vlog.Logf("daemon", "warning: could not parse saved net config: %v", err)
		}
	}

	vlog.Logf("daemon", "initial config: cidr=%s hold=%s host-locked=%v", netCfg.IPRange, netCfg.IPHoldDuration.Duration(), cfg.HostLocked)
	cfgNode := config.NewNode(netCfg, networkPub, cfg.HostLocked)

	// Create IP manager.
	ipMgr, err := ipmgr.New(netCfg.IPRange, netCfg.IPHoldDuration.Duration())
	if err != nil {
		return fmt.Errorf("creating IP manager: %w", err)
	}
	vlog.Logf("daemon", "IP manager created for %s (hold TTL %s)", netCfg.IPRange, netCfg.IPHoldDuration.Duration())

	// Create whitelist enforcer.
	wlEnforcer := whitelist.New(cfgNode)

	// Wire up packet handling BEFORE starting p2p to avoid startup race.
	// We set the handler after creating the Daemon struct, then start discovery.

	// Start libp2p node (discovery and stream handlers become active immediately).
	nodeCtx, cancel := context.WithCancel(ctx)
	p2pNode, err := p2p.New(nodeCtx, peerPrivKey, cfg.NetworkPubKey, cfg.ListenPort, cfg.BootstrapPeers, nil)
	if err != nil {
		cancel()
		return fmt.Errorf("starting p2p node: %w", err)
	}
	vlog.Logf("daemon", "p2p node started successfully")

	localPeerID := p2pNode.Host.ID().String()
	fmt.Printf("[daemon] peer ID: %s\n", localPeerID)
	fmt.Printf("[daemon] connect string(s) — pass any of these as --peer on other nodes:\n")
	for _, addr := range p2pNode.Host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, localPeerID)
	}

	// Assign this peer a virtual IP.
	// Priority: 1) Config IP assignment (from gossip), 2) PreferredIP, 3) Deterministic
	var assignedIP net.IP
	if configAssigned := netCfg.IPAssignments[localPeerID]; configAssigned != "" {
		// An admin has explicitly assigned this peer an IP via the config.
		assignedIP, err = ipMgr.Assign(localPeerID, configAssigned)
		if err != nil {
			vlog.Logf("daemon", "config IP assignment %s failed: %v, falling back", configAssigned, err)
			assignedIP = nil // fall through to other methods
		} else {
			vlog.Logf("daemon", "using config-assigned IP: %s", configAssigned)
		}
	}
	if assignedIP == nil && cfg.PreferredIP != "" {
		assignedIP, err = ipMgr.Assign(localPeerID, cfg.PreferredIP)
		if err != nil {
			vlog.Logf("daemon", "preferred IP %s failed: %v, falling back to deterministic", cfg.PreferredIP, err)
			assignedIP = nil
		}
	}
	if assignedIP == nil {
		assignedIP, err = ipMgr.AssignDeterministic(localPeerID)
	}
	if err != nil {
		cancel()
		_ = p2pNode.Close()
		return fmt.Errorf("assigning virtual IP: %w", err)
	}
	fmt.Printf("[daemon] assigned virtual IP: %s\n", assignedIP)

	// Create TUN interface.
	configIP := ipMgr.ConfigIP()
	tunIface, err := tun.Create("p2pvpn0", assignedIP.String(), netCfg.IPRange)
	if err != nil {
		cancel()
		_ = p2pNode.Close()
		return fmt.Errorf("creating TUN interface: %w", err)
	}
	vlog.Logf("daemon", "TUN created: name=%s ip=%s cidr=%s", tunIface.GetName(), assignedIP, netCfg.IPRange)
	fmt.Printf("[daemon] TUN interface: %s\n", tunIface.GetName())

	// Add the .1 config address to the TUN so the WebUI is reachable over the VPN.
	if err := tunIface.AddAddr(configIP, tunIface.GetCIDR().Mask); err != nil {
		fmt.Printf("[daemon] warning: could not add config IP %s to TUN: %v\n", configIP, err)
	}

	// Start gossip layer.
	gossipLayer, err := gossip.New(nodeCtx, p2pNode.Host, cfg.NetworkPubKey, cfgNode)
	if err != nil {
		cancel()
		_ = p2pNode.Close()
		_ = tunIface.Close()
		return fmt.Errorf("starting gossip layer: %w", err)
	}

	d := &Daemon{
		st:          st,
		p2pNode:     p2pNode,
		tunIface:    tunIface,
		ipMgr:       ipMgr,
		cfgNode:     cfgNode,
		gossipLayer: gossipLayer,
		wlEnforcer:  wlEnforcer,
		networkPub:  networkPub,
		networkPriv: networkPriv,
		localPeerID: localPeerID,
		assignedIP:  assignedIP,
		configIP:    configIP,
		peerIPs:     make(map[string]net.IP),
		cancel:      cancel,
	}

	// Persist joined network to state.
	state, _ := st.LoadState()
	state.JoinedNetwork = &store.JoinedNetwork{
		NetworkPubKey: cfg.NetworkPubKey,
		AssignedIP:    assignedIP.String(),
		PreferredIP:   cfg.PreferredIP,
		TUNName:       tunIface.GetName(),
	}
	_ = st.SaveState(state)

	// Wire up packet handling.
	p2pNode.SetPacketHandler(d.onPacket)
	// Wire up the browser TCP-proxy protocol.
	proxyLayer := tunnelproxy.New(cfgNode, wlEnforcer)
	p2pNode.SetProxyHandler(proxyLayer.HandleStream)
	gossipLayer.SetUpdateHandler(d.onConfigUpdate)
	// Let the p2p layer honour the configured peer limit.
	p2pNode.SetMaxPeersFn(d.cfgNode.GetMaxPeers)

	// Wire up whitelist callbacks for deferred IP assignment and quarantine timeout.
	wlEnforcer.OnPeerPromoted = func(peerID string) {
		// Check if the peer is still connected at libp2p level.
		pid, err := libp2ppeer.Decode(peerID)
		if err != nil {
			vlog.Logf("daemon", "OnPeerPromoted: invalid peer ID %s: %v", peerID, err)
			return
		}
		if d.p2pNode.Host.Network().Connectedness(pid) != network.Connected {
			vlog.Logf("daemon", "OnPeerPromoted: peer %s no longer connected, skipping", peerID)
			return
		}
		fmt.Printf("[daemon] peer %s promoted from quarantine → assigning IP\n", peerID)
		d.assignIPAndRoute(peerID)
	}
	wlEnforcer.OnPeerTimeout = func(peerID string) {
		fmt.Printf("[daemon] peer %s quarantine timeout — disconnecting\n", peerID)
		d.disconnectQuarantinedPeer(peerID)
	}

	// Start quarantine timeout checker (runs every 30s).
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				wlEnforcer.CheckTimeouts()
			case <-nodeCtx.Done():
				return
			}
		}
	}()

	// Register a peer pub-key extractor so the WebUI can check delegations.
	webui.SetPeerPubKeyExtractor(func(peerIDStr string) (string, bool) {
		pid, err := libp2ppeer.Decode(peerIDStr)
		if err != nil {
			return "", false
		}
		pub, err := pid.ExtractPublicKey()
		if err != nil {
			return "", false
		}
		// Unwrap Ed25519 public key from the libp2p crypto wrapper.
		raw, err := pub.Raw()
		if err != nil {
			return "", false
		}
		return hex.EncodeToString(raw), true
	})

	// Start the WebUI (bound to the VPN-internal .1 address only).
	wui := webui.New(
		configIP.String(),
		cfgNode,
		networkPub,
		networkPriv,
		func() webui.StatusInfo {
			return webui.StatusInfo{
				PeerID:     d.localPeerID,
				AssignedIP: d.assignedIP.String(),
				TUNName:    d.tunIface.GetName(),
				NetworkID:  fmt.Sprintf("%x", d.networkPub),
			}
		},
		func() map[string]net.IP {
			d.peerIPsMu.RLock()
			defer d.peerIPsMu.RUnlock()
			out := make(map[string]net.IP, len(d.peerIPs))
			for k, v := range d.peerIPs {
				out[k] = v
			}
			return out
		},
		wlEnforcer.QuarantinedPeers,
		d.reassignPeerIP,
		d.webuiConfigUpdate,
		d.webuiDelegateUpdate,
		st,
	)
	// When a user successfully unlocks editor mode via the WebUI, propagate
	// the private key to the daemon so it can sign config/delegate updates.
	wui.OnPrivKeyUnlocked = func(key ed25519.PrivateKey) {
		d.networkPriv = key
		vlog.Logf("daemon", "private key set via WebUI unlock — authority mode enabled")
	}
	// Allow the WebUI to trigger a daemon restart (e.g. after config changes).
	wui.OnDaemonRestart = func() {
		vlog.Logf("daemon", "restart requested via WebUI")
		d.cancel()
	}
	// Allow the user to change their own virtual IP from the WebUI.
	wui.OnChangeSelfIP = d.changeSelfIP
	// Provide the bridge client with the list of connected VPN peers and their
	// multiaddresses so js-libp2p browser peers can bootstrap directly.
	wui.GetBridgePeers = func() []webui.BridgePeer {
		vpnPeers := d.p2pNode.ConnectedVPNPeers()
		d.peerIPsMu.RLock()
		defer d.peerIPsMu.RUnlock()
		result := make([]webui.BridgePeer, 0, len(vpnPeers))
		for _, pi := range vpnPeers {
			ip, ok := d.peerIPs[pi.ID.String()]
			if !ok {
				continue
			}
			addrs := make([]string, len(pi.Addrs))
			for i, a := range pi.Addrs {
				addrs[i] = a.String() + "/p2p/" + pi.ID.String()
			}
			result = append(result, webui.BridgePeer{
				PeerID: pi.ID.String(),
				IP:     ip.String(),
				Addrs:  addrs,
			})
		}
		return result
	}
	d.wg.Add(1)
	go func() { defer d.wg.Done(); wui.Start(nodeCtx) }()
	fmt.Printf("[daemon] WebUI available at http://%s/ (VPN only)\n", configIP)

	// Start network change monitor so we restart when the host connects to a
	// new network (e.g. WiFi roaming, switching from WiFi → Ethernet, etc.).
	netMon := netmon.New(nodeCtx, tunIface.GetName())
	go func() {
		select {
		case chg := <-netMon.C:
			fmt.Printf("[daemon] host network changed: %s — restarting…\n", chg)
			vlog.Logf("daemon", "network change detected: %s, triggering restart", chg)
			d.networkChanged = true
			d.cancel()
		case <-nodeCtx.Done():
		}
	}()

	// Start main goroutines.
	d.wg.Add(3)
	go d.tunReadLoop()
	go d.peerEventLoop()
	go d.ipcServe(socketPath)

	// Announce our presence.
	go func() {
		time.Sleep(2 * time.Second)
		announceCtx, aC := context.WithTimeout(nodeCtx, 10*time.Second)
		defer aC()
		_ = gossipLayer.PublishState(announceCtx)
	}()

	<-nodeCtx.Done()
	netMon.Stop()
	d.shutdown(socketPath)
	if d.networkChanged {
		return ErrNetworkChanged
	}
	return nil
}

// shutdown tears down all resources.
func (d *Daemon) shutdown(socketPath string) {
	vlog.Logf("daemon", "shutting down...")
	d.cancel()
	_ = d.p2pNode.Close()
	_ = d.tunIface.Close()
	d.gossipLayer.Close()
	if d.ipcListener != nil {
		_ = d.ipcListener.Close()
	}
	_ = os.Remove(socketPath)

	// Clear joined network state.
	if st, err := d.st.LoadState(); err == nil {
		st.JoinedNetwork = nil
		_ = d.st.SaveState(st)
	}
	d.wg.Wait()
}

// tunReadLoop reads packets from the TUN interface and forwards them to
// the correct peer via libp2p.
func (d *Daemon) tunReadLoop() {
	defer d.wg.Done()
	vlog.Logf("tun-read", "tunReadLoop started, reading from %s", d.tunIface.GetName())
	buf := make([]byte, 1<<16)
	for {
		n, err := d.tunIface.Read(buf)
		if err != nil {
			vlog.Logf("tun-read", "TUN read error (loop exiting): %v", err)
			fmt.Printf("[daemon] TUN read error: %v\n", err)
			return
		}
		if n < 20 {
			continue // too short to be an IP packet
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Only handle IPv4 packets; skip IPv6 and anything else.
		if pkt[0]>>4 != 4 {
			vlog.Logf("tun-read", "skipping non-IPv4 packet (version=%d, %d bytes)", pkt[0]>>4, n)
			continue
		}

		// Extract destination IP from IPv4 header (bytes 16-19).
		dstIP := net.IP(pkt[16:20])
		vlog.Logf("tun-read", "TUN → %s", vlog.PacketSummary(pkt))
		// Packets destined for the .1 config address are handled by the local
		// kernel TCP stack (WebUI), not forwarded to another peer.
		if dstIP.Equal(d.configIP) {
			vlog.Logf("tun-read", "dst=%s is config IP, handled by kernel", dstIP)
			continue
		}
		peerID := d.peerIDForIP(dstIP)
		if peerID == "" {
			vlog.Logf("tun-read", "dst=%s has no matching peer, dropping", dstIP)
			continue // unknown destination
		}
		pid, err := libp2ppeer.Decode(peerID)
		if err != nil {
			continue
		}
		if !d.wlEnforcer.Allow(peerID) {
			vlog.Logf("tun-read", "peer %s is quarantined by whitelist, dropping packet", peerID)
			continue // quarantined peer
		}
		vlog.Logf("tun-read", "forwarding to peer %s (ip=%s)", peerID, dstIP)
		if err := d.p2pNode.SendPacket(pid, pkt); err != nil {
			fmt.Printf("[daemon] SendPacket to %s failed: %v\n", peerID, err)
		}
	}
}

// onPacket is called when a raw IP packet arrives from a remote peer.
// If this is the first packet from a peer we haven't registered yet, we
// immediately register them so the reverse TUN route exists before the
// packet is written to the kernel. Without this, the first TCP SYN from
// an unregistered peer gets accepted by the local service, but the
// SYN-ACK has no route back through the TUN and exits the wrong interface.
func (d *Daemon) onPacket(fromPeerID string, packet []byte) {
	if !d.wlEnforcer.Allow(fromPeerID) {
		vlog.Logf("rx", "dropping packet from quarantined peer %s", fromPeerID)
		return
	}
	// Ensure the peer is registered (route installed) before the packet
	// touches the TUN. onPeerConnect is idempotent so duplicates are safe.
	d.peerIPsMu.RLock()
	_, registered := d.peerIPs[fromPeerID]
	d.peerIPsMu.RUnlock()
	if !registered {
		vlog.Logf("rx", "peer %s not registered yet, triggering onPeerConnect first", fromPeerID)
		d.onPeerConnect(fromPeerID)
	}
	vlog.Logf("rx", "→ TUN: %s (from %s)", vlog.PacketSummary(packet), fromPeerID)
	if _, err := d.tunIface.Write(packet); err != nil {
		vlog.Logf("rx", "TUN write error: %v", err)
	}
}

// peerEventLoop processes peer connect/disconnect events.
func (d *Daemon) peerEventLoop() {
	defer d.wg.Done()
	for ev := range d.p2pNode.PeerEvents() {
		if ev.Connected {
			d.onPeerConnect(ev.PeerID)
		} else {
			d.onPeerDisconnect(ev.PeerID)
		}
	}
}

func (d *Daemon) onPeerConnect(peerID string) {
	// Deduplicate: skip if we already have an active entry (ConnectedF can fire
	// multiple times for the same peer across mDNS, DHT, and direct dials).
	d.peerIPsMu.RLock()
	_, exists := d.peerIPs[peerID]
	d.peerIPsMu.RUnlock()
	if exists {
		vlog.Logf("daemon", "onPeerConnect(%s): already registered, skipping", peerID)
		return
	}

	// Check whitelist status FIRST — quarantined peers do NOT get an IP or route.
	// This prevents IP pool exhaustion and TUN route leakage from unapproved peers.
	isWhitelisted := d.wlEnforcer.PeerConnected(peerID)
	if !isWhitelisted {
		fmt.Printf("[daemon] peer %s connected (quarantined — awaiting whitelist approval)\n", peerID)
		vlog.Logf("daemon", "onPeerConnect(%s): quarantined, deferring IP assignment", peerID)
		return // Don't assign IP or install route for quarantined peers
	}

	// Peer is whitelisted — proceed with IP assignment and route installation.
	d.assignIPAndRoute(peerID)
}

// assignIPAndRoute assigns a virtual IP and installs the TUN route for peerID.
// Called either from onPeerConnect (if whitelisted immediately) or from
// OnPeerPromoted callback (when a quarantined peer is later added to whitelist).
func (d *Daemon) assignIPAndRoute(peerID string) {
	// Check if already assigned (promotion callback may race with disconnect).
	d.peerIPsMu.RLock()
	_, exists := d.peerIPs[peerID]
	d.peerIPsMu.RUnlock()
	if exists {
		vlog.Logf("daemon", "assignIPAndRoute(%s): already has IP, skipping", peerID)
		return
	}

	vlog.Logf("daemon", "assignIPAndRoute(%s): assigning IP", peerID)
	
	// Check for an explicit IP assignment in the config first.
	// This allows the admin to override the deterministic assignment.
	var ip net.IP
	var err error
	if override := d.cfgNode.GetIPAssignment(peerID); override != "" {
		ip, err = d.ipMgr.Assign(peerID, override)
		if err != nil {
			vlog.Logf("daemon", "assignIPAndRoute(%s): config override %s failed: %v, falling back to deterministic", peerID, override, err)
			ip, err = d.ipMgr.AssignDeterministic(peerID)
		} else {
			vlog.Logf("daemon", "assignIPAndRoute(%s): using config override ip=%s", peerID, override)
		}
	} else {
		// Deterministic assignment: both this node and the remote peer independently
		// compute the same IP for the same peerID, so routes agree on both sides.
		ip, err = d.ipMgr.AssignDeterministic(peerID)
	}
	if err != nil {
		fmt.Printf("[daemon] IP assignment failed for %s: %v\n", peerID, err)
		return
	}
	d.peerIPsMu.Lock()
	d.peerIPs[peerID] = ip
	d.peerIPsMu.Unlock()
	vlog.Logf("daemon", "assignIPAndRoute(%s): assigned ip=%s, installing /32 route", peerID, ip)
	if err := d.tunIface.AddRoute(ip); err != nil {
		vlog.Logf("daemon", "assignIPAndRoute(%s): AddRoute(%s) error: %v", peerID, ip, err)
	} else {
		vlog.Logf("daemon", "assignIPAndRoute(%s): route installed for %s", peerID, ip)
	}
	fmt.Printf("[daemon] peer %s connected → %s\n", peerID, ip)

	// A peer connected — cancel the no-peers restart timer if running.
	if d.noPeersTimer != nil {
		d.noPeersTimer.Stop()
		d.noPeersTimer = nil
		vlog.Logf("daemon", "no-peers timer cancelled (peer connected)")
	}

	// Push our current config to the new peer via gossip full-state sync.
	// The receiving side uses timestamp comparison to keep the most recent.
	// Small delay lets the GossipSub mesh stabilise before publishing.
	go func() {
		time.Sleep(500 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.gossipLayer.PublishState(ctx); err != nil {
			vlog.Logf("daemon", "assignIPAndRoute(%s): PublishState failed: %v", peerID, err)
		}
	}()
}

func (d *Daemon) onPeerDisconnect(peerID string) {
	vlog.Logf("daemon", "onPeerDisconnect(%s)", peerID)
	d.peerIPsMu.Lock()
	ip, ok := d.peerIPs[peerID]
	delete(d.peerIPs, peerID)
	d.peerIPsMu.Unlock()
	if !ok {
		vlog.Logf("daemon", "onPeerDisconnect(%s): was never registered, ignoring", peerID)
		return // was never a registered VPN peer; ignore
	}
	d.wlEnforcer.PeerDisconnected(peerID)
	vlog.Logf("daemon", "onPeerDisconnect(%s): removing route for %s, releasing IP", peerID, ip)
	_ = d.tunIface.DelRoute(ip)
	d.ipMgr.Release(peerID)
	fmt.Printf("[daemon] peer %s disconnected\n", peerID)

	// If no peers remain, re-bootstrap the DHT and re-advertise instead of
	// restarting the entire daemon.  A full restart loses relay reservations
	// and forces a cold DHT bootstrap — making reconnection even harder.
	// The p2p layer's reconnectLoop will actively try to find the lost peers.
	d.peerIPsMu.RLock()
	count := len(d.peerIPs)
	d.peerIPsMu.RUnlock()
	if count == 0 {
		if d.noPeersTimer != nil {
			d.noPeersTimer.Stop()
		}
		vlog.Logf("daemon", "no peers connected — re-bootstrapping DHT in 15s to refresh discovery")
		fmt.Println("[daemon] no peers connected — will re-bootstrap DHT in 15s to find peers")
		d.noPeersTimer = time.AfterFunc(15*time.Second, func() {
			// Only re-bootstrap if we still have no peers.
			d.peerIPsMu.RLock()
			c := len(d.peerIPs)
			d.peerIPsMu.RUnlock()
			if c > 0 {
				return
			}
			fmt.Println("[daemon] re-bootstrapping DHT to rediscover peers…")
			vlog.Logf("daemon", "no peers for 15s, triggering DHT re-bootstrap")
			reCtx, reCancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer reCancel()
			d.p2pNode.ReBootstrapDHT(reCtx)
		})
	}
}

// disconnectQuarantinedPeer forcibly disconnects a peer that was quarantined
// but never whitelisted within the timeout period. This releases libp2p
// resources (file descriptors, memory) and prevents resource exhaustion.
func (d *Daemon) disconnectQuarantinedPeer(peerID string) {
	pid, err := libp2ppeer.Decode(peerID)
	if err != nil {
		vlog.Logf("daemon", "disconnectQuarantinedPeer: invalid peer ID %s: %v", peerID, err)
		return
	}

	// Close all connections to this peer.
	conns := d.p2pNode.Host.Network().ConnsToPeer(pid)
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			vlog.Logf("daemon", "disconnectQuarantinedPeer: error closing conn to %s: %v", peerID, err)
		}
	}
	vlog.Logf("daemon", "disconnectQuarantinedPeer: closed %d connections to %s", len(conns), peerID)

	// Also notify the p2p layer to clean up any stream state.
	d.p2pNode.EvictPeer(pid)
}

func (d *Daemon) onConfigUpdate(cfg *config.Network) {
	vlog.Logf("daemon", "onConfigUpdate: updated-at=%s whitelist=%v hold=%s",
		cfg.UpdatedAt.Format(time.RFC3339), cfg.WhitelistMode, cfg.IPHoldDuration.Duration())
	d.wlEnforcer.Refresh()
	d.ipMgr.SetHoldTTL(cfg.IPHoldDuration.Duration())

	// Check if our own IP assignment has changed.
	if myAssignment := cfg.IPAssignments[d.localPeerID]; myAssignment != "" {
		newIP := net.ParseIP(myAssignment)
		if newIP != nil && !newIP.Equal(d.assignedIP) {
			vlog.Logf("daemon", "onConfigUpdate: my IP assignment changed %s → %s, triggering restart", d.assignedIP, newIP)
			fmt.Printf("[daemon] IP assignment changed: %s → %s — restarting daemon to apply\n", d.assignedIP, newIP)
			// Persist config first so the new IP is used on restart.
			if data, err := json.Marshal(cfg); err == nil {
				_ = d.st.SaveNetConfig(data)
			}
			// Trigger daemon restart. The saved config will have the new IP assignment,
			// so on startup the daemon will use the correct IP.
			go func() {
				time.Sleep(500 * time.Millisecond) // Let other updates complete
				d.cancel()
			}()
			return
		}
	}

	// Check if any connected peer's IP assignment changed and update routes.
	d.peerIPsMu.Lock()
	for peerID, currentIP := range d.peerIPs {
		if newIPStr := cfg.IPAssignments[peerID]; newIPStr != "" {
			newIP := net.ParseIP(newIPStr)
			if newIP != nil && !newIP.Equal(currentIP) {
				vlog.Logf("daemon", "onConfigUpdate: peer %s IP changed %s → %s, updating routes", peerID, currentIP, newIP)
				// Update routes.
				_ = d.tunIface.DelRoute(currentIP)
				if err := d.tunIface.AddRoute(newIP); err != nil {
					vlog.Logf("daemon", "onConfigUpdate: AddRoute(%s) for peer %s failed: %v", newIP, peerID, err)
				}
				// Update IP manager.
				_, _ = d.ipMgr.Reassign(peerID, newIPStr)
				// Update internal mapping.
				d.peerIPs[peerID] = newIP
				fmt.Printf("[daemon] peer %s IP updated: %s → %s\n", peerID, currentIP, newIP)
			}
		}
	}
	d.peerIPsMu.Unlock()

	// Persist to disk so settings survive daemon restarts.
	if data, err := json.Marshal(cfg); err == nil {
		if err := d.st.SaveNetConfig(data); err != nil {
			vlog.Logf("daemon", "warning: failed to persist net config: %v", err)
		}
	}

	fmt.Printf("[daemon] config updated (updated-at: %s)\n", cfg.UpdatedAt.Format(time.RFC3339))
}

// peerIDForIP returns the peer ID that owns a given virtual IP, or "".
func (d *Daemon) peerIDForIP(ip net.IP) string {
	d.peerIPsMu.RLock()
	defer d.peerIPsMu.RUnlock()
	for id, pip := range d.peerIPs {
		if pip.Equal(ip) {
			vlog.Logf("route", "peerIDForIP(%s) → %s", ip, id)
			return id
		}
	}
	if d.assignedIP.Equal(ip) {
		vlog.Logf("route", "peerIDForIP(%s) → self", ip)
		return d.localPeerID
	}
	vlog.Logf("route", "peerIDForIP(%s) → NOT FOUND", ip)
	return ""
}

// reassignPeerIP changes the virtual IP assigned to a peer.
// If newIP is empty, a new deterministic IP is assigned.
// This updates the TUN routes, internal peer→IP mapping, config, and gossips
// the change to all peers so they update their routing tables.
func (d *Daemon) reassignPeerIP(peerID, newIP string) (string, error) {
	// Cannot reassign own IP via this method.
	if peerID == d.localPeerID {
		return "", fmt.Errorf("cannot reassign local peer IP via WebUI")
	}

	d.peerIPsMu.Lock()
	oldIP, exists := d.peerIPs[peerID]
	d.peerIPsMu.Unlock()

	if !exists {
		return "", fmt.Errorf("peer %s is not connected", peerID)
	}

	// Perform the IP reassignment in the manager.
	assignedIP, err := d.ipMgr.Reassign(peerID, newIP)
	if err != nil {
		return "", err
	}

	// Update TUN routes: remove old, add new.
	_ = d.tunIface.DelRoute(oldIP)
	if err := d.tunIface.AddRoute(assignedIP); err != nil {
		vlog.Logf("daemon", "reassignPeerIP: AddRoute(%s) error: %v", assignedIP, err)
	}

	// Update internal mapping.
	d.peerIPsMu.Lock()
	d.peerIPs[peerID] = assignedIP
	d.peerIPsMu.Unlock()

	// Store the IP assignment in the config so it's gossiped to all peers.
	// This ensures the remote peer and all other nodes learn about the new IP.
	d.cfgNode.SetIPAssignment(peerID, assignedIP.String())

	// Gossip the updated config to all peers.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.gossipLayer.PublishState(ctx); err != nil {
			vlog.Logf("daemon", "reassignPeerIP: failed to gossip IP assignment: %v", err)
		} else {
			vlog.Logf("daemon", "reassignPeerIP: gossiped IP assignment for %s → %s", peerID, assignedIP)
		}
	}()

	fmt.Printf("[daemon] peer %s IP changed: %s → %s (gossiping to network)\n", peerID, oldIP, assignedIP)
	vlog.Logf("daemon", "reassignPeerIP: peer %s: %s → %s", peerID, oldIP, assignedIP)

	return assignedIP.String(), nil
}

// changeSelfIP updates the local node's own virtual IP assignment.
// The change is stored in the config and gossiped so all peers learn the new IP.
// onConfigUpdate will detect the self-change and restart the daemon to apply it.
func (d *Daemon) changeSelfIP(newIP string) error {
	ip := net.ParseIP(newIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", newIP)
	}

	// Validate it falls within the VPN subnet.
	_, cidr, err := net.ParseCIDR(d.cfgNode.Get().IPRange)
	if err != nil {
		return fmt.Errorf("network CIDR not configured")
	}
	if !cidr.Contains(ip) {
		return fmt.Errorf("IP %s is not within the VPN subnet %s", newIP, d.cfgNode.Get().IPRange)
	}

	vlog.Logf("daemon", "changeSelfIP: %s → %s", d.assignedIP, ip)
	fmt.Printf("[daemon] self IP change requested: %s → %s\n", d.assignedIP, ip)

	// Store in config so it's gossiped and persisted.
	d.cfgNode.SetIPAssignment(d.localPeerID, newIP)

	// Gossip to all peers so they update routes.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.gossipLayer.PublishState(ctx); err != nil {
			vlog.Logf("daemon", "changeSelfIP: failed to gossip: %v", err)
		} else {
			vlog.Logf("daemon", "changeSelfIP: gossiped new self IP %s", newIP)
		}
	}()

	// onConfigUpdate will detect that our own IP has changed and trigger a
	// restart after persisting. We also persist here immediately as a backup.
	cfg := d.cfgNode.Get()
	if data, err := json.Marshal(cfg); err == nil {
		_ = d.st.SaveNetConfig(data)
	}
	return nil
}

// ─── IPC ────────────────────────────────────────────────────────────────────

// IPCRequest is the envelope the CLI sends to the daemon.
type IPCRequest struct {
	Command string          `json:"command"`
	Args    json.RawMessage `json:"args,omitempty"`
}

// IPCResponse wraps daemon responses.
type IPCResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// ipcServe listens on the Unix socket and handles CLI requests.
func (d *Daemon) ipcServe(socketPath string) {
	defer d.wg.Done()
	_ = os.MkdirAll(filepath.Dir(socketPath), 0755)
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Printf("[daemon] IPC listen error: %v\n", err)
		return
	}
	_ = os.Chmod(socketPath, 0666)
	d.ipcListener = ln
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handleIPCConn(conn)
	}
}

func (d *Daemon) handleIPCConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var req IPCRequest
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(IPCResponse{Error: err.Error()})
		return
	}

	resp := d.dispatchIPC(req)
	_ = enc.Encode(resp)
}

func (d *Daemon) dispatchIPC(req IPCRequest) IPCResponse {
	vlog.Logf("ipc", "request: %s", req.Command)
	switch req.Command {
	case "status":
		return d.ipcStatus()
	case "peers":
		return d.ipcPeers()
	case "config.get":
		return d.ipcConfigGet()
	case "config.set":
		return d.ipcConfigSet(req.Args)
	case "delegate.add":
		return d.ipcDelegateAdd(req.Args)
	case "delegate.remove":
		return d.ipcDelegateRemove(req.Args)
	case "whitelist.add":
		return d.ipcWhitelistAdd(req.Args)
	case "whitelist.remove":
		return d.ipcWhitelistRemove(req.Args)
	case "stop":
		d.cancel()
		return IPCResponse{OK: true}
	default:
		return IPCResponse{Error: fmt.Sprintf("unknown command: %s", req.Command)}
	}
}

// ─── IPC handlers ────────────────────────────────────────────────────────────

type statusResponse struct {
	PeerID     string `json:"peer_id"`
	AssignedIP string `json:"assigned_ip"`
	TUNName    string `json:"tun_name"`
	NetworkID  string `json:"network_id"`
	WebUIURL   string `json:"webui_url"`
}

func (d *Daemon) ipcStatus() IPCResponse {
	resp := statusResponse{
		PeerID:     d.localPeerID,
		AssignedIP: d.assignedIP.String(),
		TUNName:    d.tunIface.GetName(),
		NetworkID:  fmt.Sprintf("%x", d.networkPub),
		WebUIURL:   fmt.Sprintf("http://%s/", d.configIP),
	}
	raw, _ := json.Marshal(resp)
	return IPCResponse{OK: true, Data: raw}
}

type peerEntry struct {
	PeerID string `json:"peer_id"`
	IP     string `json:"ip"`
}

func (d *Daemon) ipcPeers() IPCResponse {
	d.peerIPsMu.RLock()
	defer d.peerIPsMu.RUnlock()
	peers := make([]peerEntry, 0, len(d.peerIPs))
	for id, ip := range d.peerIPs {
		peers = append(peers, peerEntry{PeerID: id, IP: ip.String()})
	}
	raw, _ := json.Marshal(peers)
	return IPCResponse{OK: true, Data: raw}
}

func (d *Daemon) ipcConfigGet() IPCResponse {
	cfg := d.cfgNode.Get()
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	return IPCResponse{OK: true, Data: raw}
}

func (d *Daemon) ipcConfigSet(args json.RawMessage) IPCResponse {
	if d.networkPriv == nil {
		return IPCResponse{Error: "network private key not loaded; cannot sign config updates"}
	}
	// Read current config and apply the partial patch on top, so that
	// omitted fields retain their current values instead of being zeroed.
	current := d.cfgNode.Get()
	if err := json.Unmarshal(args, current); err != nil {
		return IPCResponse{Error: fmt.Sprintf("invalid config patch: %v", err)}
	}
	env, err := auth.Sign(d.networkPriv, current)
	if err != nil {
		return IPCResponse{Error: err.Error()}
	}
	if err := d.cfgNode.ApplyUpdate(env); err != nil {
		return IPCResponse{Error: err.Error()}
	}
	d.onConfigUpdate(d.cfgNode.Get())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.gossipLayer.PublishSigned(ctx, env); err != nil {
		return IPCResponse{Error: fmt.Sprintf("gossip publish: %v", err)}
	}
	return IPCResponse{OK: true}
}

type delegateArgs struct {
	PubKey string `json:"pub_key"`
}

func (d *Daemon) ipcDelegateAdd(rawArgs json.RawMessage) IPCResponse {
	if d.networkPriv == nil {
		return IPCResponse{Error: "network private key not loaded"}
	}
	var args delegateArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return IPCResponse{Error: err.Error()}
	}
	rec, err := auth.CreateDelegation(d.networkPriv, args.PubKey)
	if err != nil {
		return IPCResponse{Error: err.Error()}
	}
	cfg := d.cfgNode.Get()
	cfg.Delegations = append(cfg.Delegations, *rec)
	cfg.DelegatedPeers = append(cfg.DelegatedPeers, args.PubKey)
	return d.signAndPublish(cfg)
}

func (d *Daemon) ipcDelegateRemove(rawArgs json.RawMessage) IPCResponse {
	if d.networkPriv == nil {
		return IPCResponse{Error: "network private key not loaded"}
	}
	var args delegateArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return IPCResponse{Error: err.Error()}
	}
	cfg := d.cfgNode.Get()
	for i, rec := range cfg.Delegations {
		if rec.DelegatePubKey == args.PubKey && !rec.Revoked {
			revoked, err := auth.RevokeDelegation(d.networkPriv, &cfg.Delegations[i])
			if err != nil {
				return IPCResponse{Error: err.Error()}
			}
			cfg.Delegations[i] = *revoked
		}
	}
	// Rebuild DelegatedPeers to remove the revoked key.
	var kept []string
	for _, k := range cfg.DelegatedPeers {
		if k != args.PubKey {
			kept = append(kept, k)
		}
	}
	cfg.DelegatedPeers = kept
	return d.signAndPublish(cfg)
}

type whitelistArgs struct {
	PeerID string `json:"peer_id"`
}

func (d *Daemon) ipcWhitelistAdd(rawArgs json.RawMessage) IPCResponse {
	if d.networkPriv == nil {
		return IPCResponse{Error: "network private key not loaded"}
	}
	var args whitelistArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return IPCResponse{Error: err.Error()}
	}
	cfg := d.cfgNode.Get()
	for _, id := range cfg.AllowedPeerIDs {
		if id == args.PeerID {
			return IPCResponse{OK: true} // already present
		}
	}
	cfg.AllowedPeerIDs = append(cfg.AllowedPeerIDs, args.PeerID)
	return d.signAndPublish(cfg)
}

func (d *Daemon) ipcWhitelistRemove(rawArgs json.RawMessage) IPCResponse {
	if d.networkPriv == nil {
		return IPCResponse{Error: "network private key not loaded"}
	}
	var args whitelistArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return IPCResponse{Error: err.Error()}
	}
	cfg := d.cfgNode.Get()
	var kept []string
	for _, id := range cfg.AllowedPeerIDs {
		if id != args.PeerID {
			kept = append(kept, id)
		}
	}
	cfg.AllowedPeerIDs = kept
	return d.signAndPublish(cfg)
}

// webuiConfigUpdate is called by the WebUI when a config change is submitted.
// It reads the full current config, merges the patch on top (so all fields
// including whitelist, allowed-peers, etc. are included), signs the result
// with the network private key, and gossips the complete config to all peers.
func (d *Daemon) webuiConfigUpdate(patch *config.Network) error {
	if d.networkPriv == nil {
		return fmt.Errorf("network private key not loaded; cannot sign config updates")
	}
	// Read-then-patch: start from the full current config so omitted fields
	// (e.g. allowed-peers when only whitelist-mode was toggled) are preserved
	// in the gossip message rather than sent as nil/zero.
	current := d.cfgNode.Get()
	raw, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshalling patch: %w", err)
	}
	if err := json.Unmarshal(raw, current); err != nil {
		return fmt.Errorf("merging patch: %w", err)
	}
	env, err := auth.Sign(d.networkPriv, current)
	if err != nil {
		return err
	}
	if err := d.cfgNode.ApplyUpdate(env); err != nil {
		return err
	}
	d.onConfigUpdate(d.cfgNode.Get())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.gossipLayer.PublishSigned(ctx, env)
}

// webuiDelegateUpdate adds (revoke=false) or revokes (revoke=true) a
// delegation for the peer identified by pubKeyHex, then gossips the change.
func (d *Daemon) webuiDelegateUpdate(pubKeyHex string, revoke bool) error {
	if d.networkPriv == nil {
		return fmt.Errorf("network private key not loaded")
	}
	cfg := d.cfgNode.Get()
	if revoke {
		for i, rec := range cfg.Delegations {
			if rec.DelegatePubKey == pubKeyHex && !rec.Revoked {
				rev, err := auth.RevokeDelegation(d.networkPriv, &cfg.Delegations[i])
				if err != nil {
					return err
				}
				cfg.Delegations[i] = *rev
			}
		}
		var kept []string
		for _, k := range cfg.DelegatedPeers {
			if k != pubKeyHex {
				kept = append(kept, k)
			}
		}
		cfg.DelegatedPeers = kept
	} else {
		rec, err := auth.CreateDelegation(d.networkPriv, pubKeyHex)
		if err != nil {
			return err
		}
		cfg.Delegations = append(cfg.Delegations, *rec)
		cfg.DelegatedPeers = append(cfg.DelegatedPeers, pubKeyHex)
	}
	resp := d.signAndPublish(cfg)
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// signAndPublish signs the given cfg and gossips it to all peers.
func (d *Daemon) signAndPublish(cfg *config.Network) IPCResponse {
	env, err := auth.Sign(d.networkPriv, cfg)
	if err != nil {
		return IPCResponse{Error: err.Error()}
	}
	if err := d.cfgNode.ApplyUpdate(env); err != nil {
		return IPCResponse{Error: err.Error()}
	}
	d.onConfigUpdate(d.cfgNode.Get())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.gossipLayer.PublishSigned(ctx, env); err != nil {
		return IPCResponse{Error: fmt.Sprintf("gossip publish: %v", err)}
	}
	return IPCResponse{OK: true}
}

// ─── Setup Mode ──────────────────────────────────────────────────────────────

// StartSetupMode runs a lightweight HTTP server on 0.0.0.0:8080 that serves
// the WebUI in "setup mode".  In this mode no VPN or p2p networking is active;
// the only purpose is to let the user supply a network config (network ID or
// .conf upload) via the browser.  Once the config is received and persisted to
// saved.conf, the function returns ErrSetupComplete so the caller can restart
// the daemon normally.
func StartSetupMode(ctx context.Context, cfg Config) error {
	if cfg.Verbose {
		vlog.Enable()
	}
	vlog.Logf("setup", "entering setup mode (no network config)")

	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = store.DefaultStateDir
	}
	st, err := store.New(stateDir)
	if err != nil {
		return err
	}

	fmt.Println("[setup] No network configuration found.")

	srv := webui.NewSetupServer(st)

	setupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// When the setup server signals that config was saved, cancel and return.
	srv.OnSetupComplete = func() {
		vlog.Logf("setup", "config received via WebUI, signalling restart")
		cancel()
	}

	go func() {
		if err := srv.ListenAndServe(setupCtx); err != nil && err != context.Canceled {
			fmt.Printf("[setup] server error: %v\n", err)
		}
	}()

	// Wait briefly for the listener to bind so we can print the actual address.
	time.Sleep(50 * time.Millisecond)
	addr := srv.BoundAddr
	if addr == "" {
		addr = "0.0.0.0:8080"
	}
	fmt.Printf("[setup] Starting setup UI on http://%s\n", addr)
	fmt.Println("[setup] Open that URL in a browser to configure your network.")

	<-setupCtx.Done()

	// If the parent context was cancelled (e.g. SIGINT) we just exit normally.
	// If OUR cancel() was called (setup complete), return the special error.
	if ctx.Err() == nil {
		// Parent context is still alive — setup must have completed.
		return ErrSetupComplete
	}
	return nil
}
