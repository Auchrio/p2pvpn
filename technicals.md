# p2pvpn Technical Deep Dive

This document describes the internal architecture and detailed procedures of how p2pvpn operates at the code level.

## Table of Contents

1. [Peer Discovery (libp2p DHT)](#peer-discovery)
2. [Stream Establishment & VPN Protocol](#stream-protocol)
3. [IP Address Assignment](#ip-assignment)
4. [Configuration Propagation (GossipSub)](#config-propagation)
5. [TUN Interface Management](#tun-interface)
6. [Authentication & Signature Verification](#authentication)
7. [Whitelist Enforcement](#whitelist)
8. [IPC Protocol](#ipc-protocol)

---

## Peer Discovery

### Overview

Peer discovery in p2pvpn uses the **libp2p Kademlia DHT (Distributed Hash Table)** with the network's Ed25519 public key as the **rendezvous topic**. All peers advertising the same public key can discover each other.

### Procedure

#### 1. Daemon Startup (`daemon.New()`)

When the daemon starts, it:

1. **Creates a libp2p host** with a random Ed25519 keypair (the peer identity, separate from the network key)
   ```go
   host, err := libp2p.New()  // Creates Host with random peer ID
   ```

2. **Initializes the DHT** in client mode (or server mode for known peers)
   ```go
   dht := dht.New(ctx, host)
   dht.Bootstrap(ctx)  // Connect to bootstrap nodes
   ```

3. **Bootstraps from hardcoded IPFS nodes** (or user-supplied via `--peer` flag)
   - Default IPFS bootstrap nodes: `/dnsaddr/bootstrap.libp2p.io/...`
   - User bootstrap peers added via `AddBootstrap()`

4. **Announces itself to the DHT** under the network public key as the rendezvous point
   ```go
   h.Host().Peerstore().AddAddrs(peerID, addrs, peerstore.ConnectedAddrTTL)
   dht.Provide(ctx, cid.Hash(networkPublicKey), true)  // Announce self
   ```

#### 2. Peer Discovery (`p2p.findPeers()`)

When the daemon needs to discover other peers:

1. **Query the DHT** for the network public key
   ```go
   peers := dht.FindPeers(ctx, cid.Hash(networkPublicKey))
   ```

2. **Collect discovered peer multi-addresses** (e.g., `/ip4/1.2.3.4/tcp/7777/p2p/QmABC...`)

3. **Dial each discovered peer** to establish a connection
   ```go
   stream, err := host.NewStream(ctx, peerID, VPNProtocolID)
   ```

4. **On successful stream**: Peer is added to the active peer set; IP assignment begins

#### 3. mDNS Discovery (Local Network)

For peers on the same local network, **mDNS (multicast DNS)** provides faster discovery:

1. **mDNS announces the peer** via multicast
   ```go
   mdns := discovery.NewMdnsService(ctx, host, serviceNamespace)
   ```

2. **Receives mDNS announcements** from other local peers
   ```go
   mdns.HandlePeerFound(peerInfo)  // Called when peer announced via mDNS
   ```

3. **Only opens VPN streams for mDNS peers if no existing stream** (bug fix: previously only checked TCP connections)
   ```go
   if streamFor(peerID) == nil {  // Check VPN stream, not TCP connection
       openStream(peerID)  // Open bidirectional VPN stream
   }
   ```

### Code Implementation

File: [utils/p2p/p2p.go](utils/p2p/p2p.go)

**Key functions:**
- `New()` — Creates libp2p host, initializes DHT, announces to rendezvous point
- `findPeers()` — Queries DHT for peers; reports found/attempted/skipped counts (verbose logging)
- `HandlePeerFound()` — Callback when mDNS peer discovered; checks if VPN stream exists, opens if needed
- `streamFor(peerID)` — Looks up existing stream for a peer; opens new if absent

---

## Stream Establishment & VPN Protocol

### Overview

Once discovery locates a peer, a **bidirectional stream** is established over which VPN packets are sent. The protocol uses a custom frame format for packet serialization.

### Stream Procedure

#### 1. Outgoing Stream (Self → Peer)

When the daemon needs to send packets to a peer:

```
Daemon A → Open stream to Peer B
         → Write VPN frames (IPv4 packets + metadata)
         → Peer B reads frames and injects into its TUN
```

**Code flow:**
```go
func (h *Host) SendPacket(peerID peer.ID, pkt *IPv4Packet) error {
    s := streamFor(peerID)  // Get or create stream
    if s == nil {
        s, err = h.Host.NewStream(ctx, peerID, VPNProtocolID)
    }
    frame := marshalPacket(pkt)  // Serialize packet into frame
    s.Write(frame)
}
```

#### 2. Incoming Stream (Peer → Self)

When a peer connects and sends packets:

```
Peer B → Opens stream to Daemon A (Noise-encrypted)
      → Writes VPN frames (IPv4 packets)
      → Daemon A reads and injects into its TUN
      → Daemon A ALSO opens reverse stream back to peer
```

**Key insight (bug fix):** Previously, when Peer B connected to Daemon A, A would only read packets from B's stream. A would NOT open a stream back to B, so B couldn't receive packets from A. This was fixed by having `handleStream()` proactively open a reverse stream in a background goroutine.

**Code:**
```go
func (h *Host) handleStream(stream network.Stream) {
    go func() {
        // Open reverse stream so we can send packets back to this peer
        revStream, err := h.Host.NewStream(ctx, stream.Conn().RemotePeer(), VPNProtocolID)
        if err != nil {
            vlog.Logf("p2p", "Failed to open reverse stream: %v", err)
            return
        }
        h.streamsMu.Lock()
        h.streams[stream.Conn().RemotePeer()] = revStream
        h.streamsMu.Unlock()
    }()

    // Read packets from incoming stream
    for {
        frame, err := readFrame(stream)
        if err != nil {
            vlog.Logf("p2p", "Stream read error: %v", err)
            return
        }
        pkt := unmarshalPacket(frame)
        h.onPacket(pkt)
    }
}
```

### Frame Format

Each VPN packet is serialized into a **frame** for wire transmission:

```
[Frame Header]
  uint32: Frame length (4 bytes)
  uint8:  Protocol version (1 byte)
  [IPv4 Packet Payload]
    variable: Raw IPv4 packet (20+ bytes header, payload)
```

**Marshaling (packet → frame):**
```go
func marshalPacket(pkt *IPv4Packet) []byte {
    payload := pkt.Raw()  // Get raw IPv4 bytes
    frame := make([]byte, 4 + 1 + len(payload))
    binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
    frame[4] = 1  // Protocol version
    copy(frame[5:], payload)
    return frame
}
```

**Unmarshaling (frame → packet):**
```go
func unmarshalPacket(frame []byte) *IPv4Packet {
    length := binary.BigEndian.Uint32(frame[0:4])
    version := frame[4]
    payload := frame[5:5+length]
    return parseIPv4(payload)
}
```

### Noise Encryption

All streams are automatically encrypted by libp2p using **Noise protocol**:
- **Cipher**: ChaCha20-Poly1305 (or AES-GCM, depends on peer capability)
- **Key exchange**: DH (Diffie-Hellman) or ECDH
- **256-bit keys** for symmetric encryption
- **Authenticated encryption** prevents tampering

This happens transparently; the application writes plaintext, libp2p encrypts/decrypts.

---

## IP Address Assignment

### Overview

Each peer is assigned a **deterministic virtual IPv4 address** computed from:
- A stable namespace (hash of network public key + reserved salt)
- The peer's Ed25519 public key
- Collision probing if the computed address is already in use

### Procedure

#### 1. Compute Deterministic IP

**Algorithm:**
```
hash = SHA256(namespace_salt + network_pubkey + peer_pubkey)
base_ip = network_cidr.Base + (hash % subnet_size)
assigned_ip = base_ip
```

**Example:**
- Network CIDR: `10.42.0.0/24` (256 addresses from 10.42.0.0 to 10.42.0.255)
- Namespace: `p2pvpn_v1` (constant salt)
- Peer A pubkey: `08d7f3a...` → SHA256 hash → `12345` (example)
- Assigned IP: `10.42.0.1` (12345 mod 256 = 1)

**Code:**
```go
func (im *IPManager) AssignDeterministic(peerID peer.ID, preferredIP string) (net.IP, error) {
    // Hash: SHA256(salt + networkPubKey + peerPubKeyBytes)
    h := sha256.New()
    h.Write([]byte("p2pvpn_v1"))
    h.Write(networkPubKeyBytes)
    h.Write(peerIDBytes)
    hashBytes := h.Sum(nil)
    hashValue := binary.BigEndian.Uint32(hashBytes[:4])
    
    // Compute base IP
    baseIP := cidrBase + Net(hashValue % cidrSize)
    
    // Check preferred IP first (if provided and available)
    if preferredIP != "" && !isLeased(preferredIP) {
        assignIP(peerID, preferredIP)
        return preferredIP, nil
    }
    
    // Probe forward until finding unused address
    ip := baseIP
    for {
        if !isLeased(ip) {
            assignIP(peerID, ip)
            return ip, nil
        }
        ip = ip + 1
        if ip > cidrEnd {
            return nil, ErrSubnetFull
        }
    }
}
```

#### 2. Collision Detection & Probing

If the computed IP is already in use (collision), the daemon **probes linearly**:

```
If 10.42.0.1 is taken, try 10.42.0.2
If 10.42.0.2 is taken, try 10.42.0.3
...continue until finding available IP
```

**Collision handling:**
```go
func (im *IPManager) isLeased(ip net.IP) bool {
    lease, exists := im.leases[ip.String()]
    if !exists {
        return false  // Not leased
    }
    if time.Now().After(lease.ExpiresAt) {
        im.ReleaseLease(ip)
        return false  // Expired, can reuse
    }
    return true  // Still active
}
```

#### 3. IP Lease Management

When a peer **disconnects**, its IP is **held (leased) for a configurable duration** before being released:

```
Peer disconnects at 10:00:00
IP 10.42.0.5 is leased until 10:05:00 (hold duration = 5 minutes)
At 10:05:00, lease expires; IP 10.42.0.5 becomes available
It reconnects at 10:04:00 → Gets same IP 10.42.0.5 (pre-expiry reuse)
```

**Code:**
```go
func (im *IPManager) ReleaseLease(peerID peer.ID) {
    ip := im.peerToIP[peerID]
    lease := &Lease{
        PeerID:    peerID,
        IP:        ip,
        StartTime: time.Now(),
        ExpiresAt: time.Now().Add(im.HoldDuration),
    }
    im.leases[ip.String()] = lease
}

// On reconnect:
func (im *IPManager) AssignDeterministic(...) (..., error) {
    // ...
    if lease, exists := im.leases[ip.String()]; exists && time.Now().Before(lease.ExpiresAt) {
        if lease.PeerID == peerID {
            // Reactivate pre-existing lease for same peer
            delete(im.leases, ip.String())
            assignIP(peerID, ip)
            return ip, nil
        }
    }
    // ...probe for new address
}
```

### Special IPs

- **`.1` address** (e.g., `10.42.0.1`): Distributed config node (virtual router)  
  - Not assigned to any individual peer
  - All peers can send packets to `.1`; config gossip responds from `.1`
- **`.0` address**: Network address (reserved)
- **`.255` address**: Broadcast address (reserved)

---

## Configuration Propagation

### Overview

Network-wide configuration (IP ranges, whitelist, max peers, delegation list) is maintained at a virtual `.1` address and propagated via **GossipSub** gossip protocol. All peers independently validate and apply changes.

### Procedure

#### 1. Config State Structure

```go
type Config struct {
    IPRange           string        `json:"ip-range"`              // e.g., "10.42.0.0/24"
    IPHoldDuration    Duration      `json:"ip-hold-duration"`      // e.g., "5m"
    MaxPeers          int           `json:"max-peers"`             // 0 = unlimited
    WhitelistMode     bool          `json:"whitelist-mode"`
    AllowedPeerIDs    []string      `json:"allowed-peers"`
    AllowedPorts      []int         `json:"allowed-ports"`
    DelegatedPeerKeys []string      `json:"delegated-peers"`       // Public keys
    
    // Metadata (not gossiped, local only)
    UpdatedAt         time.Time
    Signature         []byte        // Ed25519 signature
    SignedBy          string        // Signer's public key
}
```

#### 2. Publishing Config Updates

When the network authority (or delegated peer) updates config:

```go
func (c *Config) PublishSigned(ctx context.Context, privKey ed25519.PrivateKey) error {
    // 1. Serialize current state to JSON
    payload, err := json.Marshal(c)
    
    // 2. Sign the payload
    sig := ed25519.Sign(privKey, payload)
    
    // 3. Create signed message envelope
    msg := SignedConfigUpdate{
        Payload:   payload,
        Signature: sig,
        Signer:    privKey.Public().(ed25519.PublicKey),
    }
    
    // 4. Publish to GossipSub topic (derived from network public key)
    topic := fmt.Sprintf("config.%s", hex.EncodeToString(networkPubKey[:8]))
    pubsub.Publish(ctx, topic, json.Marshal(msg))
}
```

**Example: User runs `p2pvpn config set --max-peers 100`**
1. CLI sends RPC to daemon: `{"method": "config.set", "params": {"max-peers": 100}}`
2. Daemon patches config: `config.MaxPeers = 100`
3. Daemon signs and publishes: `pubsub.Publish(topic, SignedUpdate{...})`
4. All peers receive the message via gossip

#### 3. Receiving & Validating Updates

When a peer receives a config update via gossip:

```go
func (c *Config) handleGossipMessage(msg SignedConfigUpdate) error {
    // 1. Unmarshal payload
    var incomingConfig Config
    err := json.Unmarshal(msg.Payload, &incomingConfig)
    if err != nil {
        vlog.Logf("config", "Invalid JSON in config update")
        return err
    }
    
    // 2. Verify signature
    isValid := ed25519.Verify(
        msg.Signer,                    // Signer's public key
        msg.Payload,                   // Original payload
        msg.Signature,                 // Signature to verify
    )
    if !isValid {
        vlog.Logf("config", "Config signature verification failed")
        return ErrInvalidSignature
    }
    
    // 3. Check if signer is authorized (network privkey or delegated peer)
    if !c.IsSignerAuthorized(msg.Signer) {
        vlog.Logf("config", "Signer not authorized: %s", msg.Signer)
        return ErrUnauthorizedSigner
    }
    
    // 4. Apply the update (merge changes)
    c.ApplyUpdate(incomingConfig)
    
    // 5. Persist to disk
    c.Save()
    
    vlog.Logf("config", "Config update applied from %s", msg.Signer[:8])
    return nil
}
```

**Authorization check:**
```go
func (c *Config) IsSignerAuthorized(signer ed25519.PublicKey) bool {
    signerHex := hex.EncodeToString(signer)
    
    // Check if signer is the network authority
    if signerHex == c.NetworkAuthority {
        return true
    }
    
    // Check if signer is in delegated list
    for _, delegated := range c.DelegatedPeerKeys {
        if delegated == signerHex {
            return true
        }
    }
    
    return false
}
```

#### 4. GossipSub Topic Structure

All peers subscribe to the **same topic** derived from the network public key:

```go
topic := fmt.Sprintf("config.%s", hex.EncodeToString(networkPubKey[:8]))
```

This ensures:
- Only peers with the correct network public key subscribe  
- Each network has an isolated topic (no cross-network interference)
- All peers in a network receive all updates (eventual consistency)

**GossipSub properties:**
- **Flood publishing**: New peers receive all recent messages
- **Gossip propagation**: Peers forward messages to neighbors
- **TTL**: Messages expire after 5 minutes (configurable)
- **Deduplication**: Same message only processed once

---

## TUN Interface Management

### Overview

The TUN interface is a **virtual network interface** that allows the daemon to:
1. **Write packets** destined for other peers into the TUN
2. **Read packets** from applications trying to reach other peers
3. **Route transparently** between the virtual network and physical network

### Linux TUN Creation

#### 1. Opening the TUN Device

**Critical issue (fixed):** Previously, using `os.OpenFile().Fd()` put the fd in **blocking mode**, incompatible with Go's epoll-based async I/O, causing "not pollable" errors.

**Solution:** Use raw `syscall.Open()` with `O_CLOEXEC`, then `SetNonblock(true)`, then wrap with `os.NewFile()`:

```go
func openTUN(name string) (*TUN, error) {
    // Use raw syscall instead of os.OpenFile to avoid blocking mode
    fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
    if err != nil {
        return nil, fmt.Errorf("open /dev/net/tun: %w", err)
    }
    
    // Set non-blocking mode for Go's epoll poller
    err = syscall.SetNonblock(fd, true)
    if err != nil {
        syscall.Close(fd)
        return nil, fmt.Errorf("SetNonblock: %w", err)
    }
    
    // Configure TUN parameters via ioctl
    ifr := ifreq{Name: [16]byte{}}
    copy(ifr.Name[:], name)
    ifr.Flags = IFF_TUN | IFF_NO_PI  // TUN mode, no packet info
    
    _, _, errno := syscall.Syscall(
        syscall.SYS_IOCTL,
        uintptr(fd),
        TUNSETIFF,
        uintptr(unsafe.Pointer(&ifr)),
    )
    if errno != 0 {
        syscall.Close(fd)
        return nil, fmt.Errorf("IOCTL TUNSETIFF: %w", syscall.Errno(errno))
    }
    
    // Wrap fd in os.File for Go's I/O
    f := os.NewFile(uintptr(fd), name)
    return &TUN{File: f}, nil
}
```

#### 2. IP Configuration

After TUN creation, configure IP addresses via **netlink**:

```go
func (t *TUN) AddAddr(ip net.IP, maskBits int) error {
    // Use netlink to add IP to TUN interface
    addr := &netlink.Addr{
        IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(maskBits, 32)},
    }
    return netlink.AddrAdd(t.Link, addr)
}

func (t *TUN) AddRoute(dest *net.IPNet, via net.IP) error {
    // Add route: "to <dest> via <via>"
    route := &netlink.Route{
        LinkIndex: t.Link.Attrs().Index,
        Dst:       dest,
        Gw:        via,
    }
    return netlink.RouteAdd(route)
}
```

**Example setup:**
```
For peer with IP 10.42.0.5 in network 10.42.0.0/24:
1. AddAddr(10.42.0.5, 24)        — Assign IP to TUN
2. AddRoute(10.42.0.0/24, nil)   — Route entire subnet through TUN
```

### Packet Read Loop

The **tunReadLoop** reads packets from applications and forwards them to peers:

```go
func (d *Daemon) tunReadLoop() {
    vlog.Logf("tun-read", "tunReadLoop started")
    
    for {
        // Read raw IPv4 packet from TUN
        pkt := make([]byte, 1500)
        n, err := d.TUN.Read(pkt)
        if err != nil {
            vlog.Logf("tun-read", "TUN read error (loop exiting): %v", err)
            return
        }
        
        // Parse IPv4 packet
        ipv4, err := parseIPv4(pkt[:n])
        if err != nil {
            vlog.Logf("tun-read", "Invalid IPv4 packet, skipping")
            continue
        }
        
        // Handle the packet
        d.onPacket(ipv4)
    }
}
```

**Critical fix:** The loop now logs startup, so we immediately see if TUN is misconfigured. Previously, silent exit meant no error visibility.

### Packet Write Loop

When a peer sends a packet, it's written back to TUN:

```go
func (d *Daemon) onPacket(pkt *IPv4Packet) {
    // Lookup peer for destination IP
    peerID, exists := d.IPManager.PeerForIP(pkt.DstIP)
    if !exists {
        vlog.Logf("daemon", "No peer for IP %s", pkt.DstIP)
        return
    }
    
    // Check whitelist if enabled
    config := d.Config.Current()
    if config.WhitelistMode && !config.AllowedPeerIDs.Contains(peerID.String()) {
        vlog.Logf("daemon", "Peer %s quarantined (not in whitelist)", peerID.String()[:8])
        return
    }
    
    // Send packet to peer via libp2p stream
    err := d.P2P.SendPacket(peerID, pkt)
    if err != nil {
        vlog.Logf("daemon", "Failed to send packet to %s: %v", peerID.String()[:8], err)
        return
    }
}
```

**On receive from peer:**
```go
func (d *Daemon) ReceivePacket(pkt *IPv4Packet) error {
    // Write IPv4 packet directly to TUN interface
    _, err := d.TUN.Write(pkt.Raw())
    if err != nil {
        vlog.Logf("daemon", "TUN write error: %v", err)
        return err
    }
    vlog.Logf("daemon", "Packet written to TUN: %s → %s", pkt.SrcIP, pkt.DstIP)
    return nil
}
```

### MTU & Packet Fragmentation

Default TUN MTU is 1500 bytes. Packets larger are **silently dropped** or fragmented by the kernel. Applications should:
- Use PMTUD (Path MTU Discovery) to learn optimal packet size
- Respond with ICMP "Fragmentation Needed" on oversized packets

---

## Authentication & Signature Verification

### Overview

Signatures are used for:
1. **Config integrity** — Authority proves it authored a config update
2. **Delegation records** — Authority proves it delegated to another peer
3. **Whitelist changes** — Proves an authorized party modified the list

**Algorithm:** Ed25519 (256-bit keys, 64-byte signatures)

### Signature Creation

**Code:**
```go
func Sign(data []byte, privKey ed25519.PrivateKey) ([]byte, error) {
    return ed25519.Sign(privKey, data), nil
}

// Example: Authority signs a config update
payload := json.Marshal(config)
sig := ed25519.Sign(authorityPrivKey, payload)

// Create signed message
signedMsg := struct {
    Payload   []byte
    Signature []byte
    Signer    []byte  // Public key
}{
    Payload:   payload,
    Signature: sig,
    Signer:    authorityPrivKey.Public().(ed25519.PublicKey),
}
```

### Signature Verification

```go
func Verify(data, sig []byte, pubKey ed25519.PublicKey) bool {
    return ed25519.Verify(pubKey, data, sig)
}

// Example: Peer validates config update from authority
isValid := ed25519.Verify(
    authorityPubKey,  // Public key of claimed signer
    payload,          // Original data
    sig,              // Signature to verify
)

if !isValid {
    vlog.Logf("auth", "Signature verification failed")
    return ErrInvalidSignature
}
```

### Delegation Verification Chain

**Scenario:** Authority delegates to Peer B, who then signs a config update. Peer A must verify the chain.

1. **Peer A receives config update from Peer B:**
   ```go
   msg := receivedMessage{
       Payload:   config_json,
       Signature: sig_by_peerB,
       Signer:    peerB_pubkey,
   }
   ```

2. **Peer A verifies Peer B is delegated:**
   ```go
   // Check if Peer B's public key is in config's delegated list
   delegatedList := currentConfig.DelegatedPeerKeys
   isDelegate := false
   for _, delegated := range delegatedList {
       if delegated == hex(peerB_pubkey) {
           isDelegate = true
           break
       }
   }
   ```

3. **Peer A verifies signature:**
   ```go
   if !isDelegate {
       return ErrNotDelegated
   }
   if !ed25519.Verify(peerB_pubkey, payload, sig_by_peerB) {
       return ErrInvalidSignature
   }
   ```

4. **Peer A applies the update:**
   ```go
   config.ApplyUpdate(payload)
   config.Save()
   ```

### Timestamp Validation (Optional)

For added security, signatures can include a **timestamp** to prevent replay attacks:

```go
type SignedMessage struct {
    Timestamp int64  // Unix seconds
    Payload   []byte
    Signature []byte
}

// Verify timestamp is within acceptable window (e.g., 1 minute old)
now := time.Now().Unix()
if abs(now - msg.Timestamp) > 60 {
    return ErrStaleSignature
}
```

---

## Whitelist Enforcement

### Overview

**Whitelist mode** quarantines newly joined peers until explicitly approved. Enforcement is **fully local** — each peer independently checks the whitelist before routing.

### Procedure

#### 1. Whitelist Mode Activation

Network authority enables whitelist:

```bash
p2pvpn config set --whitelist-mode
```

This publishes a signed config update:
```json
{
    "whitelist-mode": true,
    "allowed-peers": [],  // Initially empty
    ...
}
```

#### 2. New Peer Joins

When a new peer connects:

```go
func (d *Daemon) onPeerConnect(peerID peer.ID) {
    ip, err := d.IPManager.AssignDeterministic(peerID)
    if err != nil {
        return
    }
    
    // Peer is added, but routes are NOT installed yet
    d.addPeer(peerID, ip)
    
    vlog.Logf("daemon", "Peer connected: %s (IP %s)", peerID.String()[:8], ip)
}
```

Peer is **registered in the system** but **cannot send/receive packets** until added to whitelist.

#### 3. Checking Whitelist Before Routing

Before routing any packet to a peer:

```go
func (d *Daemon) onPacket(pkt *IPv4Packet) {
    // Lookup destination peer
    peerID, exists := d.IPManager.PeerForIP(pkt.DstIP)
    if !exists {
        return
    }
    
    // Check whitelist
    config := d.Config.Current()
    if config.WhitelistMode {
        // Get all currently allowed peer IDs
        allowed := config.AllowedPeerIDs
        isAllowed := false
        for _, allowed_id := range allowed {
            if allowed_id == peerID.String() {
                isAllowed = true
                break
            }
        }
        
        if !isAllowed {
            vlog.Logf("whitelist", "Packet dropped: %s not in whitelist", peerID.String()[:8])
            return  // DROP packet
        }
    }
    
    // Route to peer
    d.P2P.SendPacket(peerID, pkt)
}
```

#### 4. Adding to Whitelist

Network authority (or delegated peer) approves a peer:

```bash
p2pvpn whitelist add QmNewPeer...
```

This sends an IPC call to the daemon:
```go
// CLI → Daemon
c.Call("whitelist.add", {"peer_id": "QmNewPeer..."})

// Daemon handler
func (d *Daemon) whitelistAdd(peerID peer.ID) error {
    // Update config
    config := d.Config.Current()
    config.AllowedPeerIDs = append(config.AllowedPeerIDs, peerID.String())
    
    // Sign and publish
    d.Config.PublishSigned(ctx, authorityPrivKey)
    
    // Immediately accept packets from this peer
    vlog.Logf("whitelist", "Peer added: %s", peerID.String()[:8])
    return nil
}
```

#### 5. Network-Wide Convergence

Once the update is gossiped and applied on all peers:

```
Time T:
  Authority: publish whitelist update
  Peer 1:    receive (immediately allow packets from QmNewPeer)
  Peer 2:    receive (immediately allow packets from QmNewPeer)
  QmNewPeer: can now send/receive with Peer 1 and Peer 2
```

All peers converge to the same view via gossip.

---

## IPC Protocol

### Overview

The daemon listens on a **Unix domain socket** (default: `/var/run/p2pvpn.sock`) for RPC commands from the CLI.

### Message Format

**Request (CLI → Daemon):**
```json
{
    "method": "status",
    "params": {},
    "id": 1
}
```

**Response (Daemon → CLI):**
```json
{
    "ok": true,
    "result": {
        "peer_id": "Qm...",
        "assigned_ip": "10.42.0.2",
        "tun_name": "tun0"
    },
    "id": 1
}
```

**Error Response:**
```json
{
    "ok": false,
    "error": "daemon not running",
    "id": 1
}
```

### Implemented Commands

#### `status`

**Request:**
```json
{"method": "status", "params": {}}
```

**Response:**
```json
{
    "ok": true,
    "result": {
        "peer_id": "QmABC123...",
        "assigned_ip": "10.42.0.2",
        "tun_name": "tun0",
        "network_id": "08d7f3a..."
    }
}
```

**Code:**
```go
func (d *Daemon) handleStatus(params map[string]interface{}) interface{} {
    return map[string]interface{}{
        "peer_id":     d.P2P.Host.ID().String(),
        "assigned_ip": d.IPManager.OwnIP().String(),
        "tun_name":    d.TUN.Name,
        "network_id":  d.NetworkPubKey[:16],
    }
}
```

#### `peers`

**Request:**
```json
{"method": "peers", "params": {}}
```

**Response:**
```json
{
    "ok": true,
    "result": [
        {"peer_id": "QmBCD456...", "ip": "10.42.0.3"},
        {"peer_id": "QmXYZ789...", "ip": "10.42.0.4"}
    ]
}
```

#### `config.get`

**Request:**
```json
{"method": "config.get", "params": {}}
```

**Response:**
```json
{
    "ok": true,
    "result": {
        "ip-range": "10.42.0.0/24",
        "ip-hold-duration": "5m",
        "max-peers": 100,
        "whitelist-mode": false,
        "allowed-peers": [],
        "delegated-peers": []
    }
}
```

#### `config.set`

**Request:**
```json
{"method": "config.set", "params": {"max-peers": 50, "whitelist-mode": true}}
```

**Processing:**
1. Daemon patches config with provided fields
2. Signs with authority private key
3. Publishes to gossip topic
4. Applies locally

**Response:**
```json
{"ok": true, "result": null}
```

#### `delegate.add` / `delegate.remove`

**Request:**
```json
{"method": "delegate.add", "params": {"pub_key": "QmXYZ..."}}
```

Adds/removes public key from delegated list, signs, and publishes.

#### `whitelist.add` / `whitelist.remove`

**Request:**
```json
{"method": "whitelist.add", "params": {"peer_id": "QmABC..."}}
```

Adds/removes peer ID from whitelist, signs, and publishes.

#### `stop`

**Request:**
```json
{"method": "stop", "params": {}}
```

Gracefully shuts down the daemon.

### Implementation Details

**Socket listener:**
```go
func (d *Daemon) listenIPC() {
    listener, err := net.Listen("unix", d.SocketPath)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go d.handleIPCConn(conn)
    }
}

func (d *Daemon) handleIPCConn(conn net.Conn) {
    defer conn.Close()
    
    // Read request JSON
    var req struct {
        Method string                 `json:"method"`
        Params map[string]interface{} `json:"params"`
        ID     int                    `json:"id"`
    }
    json.NewDecoder(conn).Decode(&req)
    
    // Dispatch to handler
    result, err := d.handleMethod(req.Method, req.Params)
    
    // Write response JSON
    resp := struct {
        OK     bool        `json:"ok"`
        Result interface{} `json:"result,omitempty"`
        Error  string      `json:"error,omitempty"`
        ID     int         `json:"id"`
    }{
        OK:     err == nil,
        Result: result,
        Error:  fmt.Sprint(err),
        ID:     req.ID,
    }
    json.NewEncoder(conn).Encode(resp)
}
```

---

## Summary

**p2pvpn Architecture Summary:**

| Component | Technology | Details |
|---|---|---|
| **Peer Discovery** | libp2p DHT + mDNS | Rendezvous on network public key; local discovery via mDNS |
| **Stream Transport** | libp2p Noise protocol | Bidirectional encrypted streams; automatic reverse stream opening |
| **IP Assignment** | Deterministic hash | SHA256-based; collision-resistant; leased on disconnect |
| **Config Propagation** | GossipSub pubsub | Gossip-replicated; signed updates; independent validation |
| **Packet Routing** | TUN interface | Linux: raw syscall with SetNonblock; packet marshaling into frames |
| **Authentication** | Ed25519 signatures | Config and delegation signing; threshold-free (all-or-none) |
| **Access Control** | Whitelist enforcement | Per-peer quarantine; local packet dropping |
| **Control Plane** | Unix IPC | JSON-RPC over Unix domain socket |

All components are **fully decentralized** — no single point of failure or trust.
