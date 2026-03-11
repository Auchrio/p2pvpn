# p2pvpn — Serverless P2P Mesh VPN

A **fully decentralized, self-hosted peer-to-peer mesh VPN** with no central servers, support for delegated network administrators, and signed configuration policy enforced by every peer.

## TL;DR

```bash
# On machine A: create a new network
p2pvpn network create --cidr 10.42.0.0/24 --out ~/.config/p2pvpn

# Start the daemon
sudo p2pvpn daemon start \
  --network-pub <public-key-from-create> \
  --network-priv <private-key-from-create>

# Get status
p2pvpn status
p2pvpn peers list

# On machine B: join the network
sudo p2pvpn network join <public-key-from-A>

# Now both machines can ping each other on 10.42.0.0/24
ping 10.42.0.1
```

## What It Does

**p2pvpn** creates a virtual Layer-3 mesh network where:

- **Every peer is equal** — No distinguished server or coordinator; any machine can start a network
- **Discovery is automatic** — Peers find each other via a distributed hash table (DHT), encrypted with the network's public key
- **Configuration is signed** — Network policy (IP ranges, access control, peer limits) is Ed25519-signed and validated by every peer before application
- **Admins can delegate** — The network creator can grant config-write authority to other peers via tamper-proof delegation records
- **New peers are protected** — Optional whitelist mode quarantines newly joined peers until explicitly approved
- **Traffic stays private** — All peer-to-peer links use Noise encryption; packets are bridged privately over TUN/TAP interfaces

## Features

✓ **Serverless** — Pure P2P DHT peer discovery; no relay, rendezvous, or coordination servers  
✓ **Keypair-based network identity** — Network ID is an Ed25519 public key; private key signs all config updates  
✓ **Encrypted by default** — All peer-to-peer streams use Noise protocol (256-bit authenticated encryption)  
✓ **Distributed config** — Updates propagated via GossipSub gossip protocol; validated independently by each peer  
✓ **Delegated authority** — Network creator can grant config-write privileges to other peers via signed delegation records  
✓ **Peer whitelist** — Optional quarantine mode for newly joined peers; requires admin approval to route traffic  
✓ **IP assignment** — Deterministic hash-based addresses with collision detection; supports manual requests  
✓ **Virtual networking** — TUN interface per peer; automatic IP routing among all connected machines  

## Quick Start

### 1. Install

Clone and build:
```bash
git clone <repo>
cd holesail-tuntap
bash build.sh   # produces binaries in bin/
sudo install -m755 bin/p2pvpn /usr/local/bin/
```

**Requirements:**
- Linux 4.1+ (for TUN support)
- Go 1.20+
- Root privileges (for TUN interface creation)

### 2. Create a Network

Network creator (machine A) generates a keypair:

```bash
p2pvpn network create \
  --cidr 10.42.0.0/24 \
  --hold-duration 5m \
  --out ~/.config/p2pvpn/mynet
```

Output:
```
Network created successfully!

  Public key  (network ID, share freely): 08d7f3a...
  Private key (authority key, keep safe): 3c2e8b1...

Keypair saved to:
  /home/user/.config/p2pvpn/mynet/network.pub
  /home/user/.config/p2pvpn/mynet/network.key
```

### 3. Start the First Peer (Network Creator)

```bash
sudo p2pvpn daemon start \
  --network-pub 08d7f3a... \
  --network-priv 3c2e8b1... \
  --cidr 10.42.0.0/24
```

The daemon will:
- Create a peer identity (Ed25519 keypair)
- Join the DHT with the public key as the rendezvous topic
- Assign itself a virtual IP (deterministically computed)
- Create a TUN interface
- Start listening for incoming peer connections

Verbose output (add `-v` flag):
```
[p2p] Host created: Qm1234567...
[p2p] Listening on /ip4/0.0.0.0/tcp/52345
[daemon] Assigned IP: 10.42.0.1
[tun] TUN interface 'tun0' created
[daemon] tunReadLoop started
[gossip] Started GossipSub node
```

Check status:
```bash
p2pvpn status

# Output:
Daemon status:
  Peer ID     : Qm1234567...
  Virtual IP  : 10.42.0.1
  TUN device  : tun0
  Network ID  : 08d7f3a...
```

### 4. Join Another Peer

On machine B:
```bash
sudo p2pvpn network join 08d7f3a...
```

This peer will:
- Create its own identity keypair
- Discover machine A via the DHT
- Establish an encrypted connection (Noise protocol)
- Negotiate a virtual IP from the CIDR block (e.g., `10.42.0.2`)
- Create a TUN interface
- Be ready to route packets

### 5. Verify Connectivity

Check connected peers:
```bash
p2pvpn peers list

# Output:
PEER ID                                           VIRTUAL IP
-------                                           ----------
QmBcdef5678...                                    10.42.0.2
```

Test with ping:
```bash
ping -c 4 10.42.0.2
# PING 10.42.0.2 (10.42.0.2) 56(84) bytes of data.
# 64 bytes from 10.42.0.2: icmp_seq=1 time=25.3 ms
# 64 bytes from 10.42.0.2: icmp_seq=1 time=24.8 ms
```

## Command Reference

### Network Commands

#### `p2pvpn network create [flags]`

Generate a new Ed25519 keypair for a network.

```bash
p2pvpn network create \
  --cidr 10.42.0.0/24 \
  --hold-duration 5m \
  --out ~/.config/p2pvpn/mynet
```

| Flag | Description | Default |
|------|---|---|
| `--cidr CIDR` | Virtual IP block | `10.42.0.0/24` |
| `--hold-duration DURATION` | How long to hold a peer's IP after disconnect | `5m` |
| `--out DIR` | Save keypair files to this directory | (no save) |

#### `p2pvpn network join <public-key> [flags]`

Start the daemon and join an existing network.

```bash
sudo p2pvpn network join 08d7f3a... \
  --preferred-ip 10.42.0.5 \
  --cidr 10.42.0.0/24
```

| Flag | Description | Default |
|------|---|---|
| `--preferred-ip IP` | Request a specific virtual IP | (auto-assigned) |
| `--network-priv KEY` | Private key for authority mode | (non-authority) |
| `--cidr CIDR` | IP block (must match network config) | `10.42.0.0/24` |
| `--port PORT` | libp2p listen port | (random) |
| `--host-locked` | Require signed config updates | false |
| `--peer MULTIADDR` | Bootstrap peer (repeatable) | (public DHT) |

**Requirements:** Root privileges

#### `p2pvpn network leave`

Stop the daemon and leave the network.

```bash
p2pvpn network leave
```

### Daemon Commands

#### `p2pvpn daemon start [flags]`

Start the VPN daemon in the foreground.

```bash
sudo p2pvpn daemon start \
  --network-pub 08d7f3a... \
  --network-priv 3c2e8b1... \
  --cidr 10.42.0.0/24 \
  --port 7777
```

| Flag | Description | Required |
|------|---|---|
| `--network-pub KEY` | Network public key | **Yes** |
| `--network-priv KEY` | Network private key (authority mode) | No |
| `--cidr CIDR` | Virtual IP block | No |
| `--preferred-ip IP` | Request specific virtual IP | No |
| `--port PORT` | Listen port | No |
| `--host-locked` | Require signed config updates | No |
| `--peer MULTIADDR` | Bootstrap peer (repeatable) | No |

#### `p2pvpn daemon stop`

Stop a running daemon.

```bash
p2pvpn daemon stop
```

### Status Commands

#### `p2pvpn status`

Show daemon status and virtual IP assignment.

```bash
p2pvpn status

# Output:
Daemon status:
  Peer ID     : Qm1234567...
  Virtual IP  : 10.42.0.2
  TUN device  : tun0
  Network ID  : 08d7f3a...
```

#### `p2pvpn peers list`

List all connected peers and their virtual IPs.

```bash
p2pvpn peers list

# Output:
PEER ID                                           VIRTUAL IP
-------                                           ----------
QmBcdef5678...                                    10.42.0.2
QmAbc...                                          10.42.0.3
```

### Configuration Commands

#### `p2pvpn config get`

Print the current network config (distributed policy).

```bash
p2pvpn config get

# Output (JSON):
{
  "ip-range": "10.42.0.0/24",
  "ip-hold-duration": "5m",
  "max-peers": 100,
  "whitelist-mode": false,
  "allowed-peers": [],
  "allowed-ports": [22, 80, 443],
  "delegated-peers": []
}
```

#### `p2pvpn config set [flags]`

Update network config (requires authority private key in daemon).

```bash
p2pvpn config set --max-peers 50
p2pvpn config set --whitelist-mode
p2pvpn config set --allowed-ports 22,80,443
p2pvpn config set \
  --max-peers 30 \
  --whitelist-mode \
  --hold-duration 10m
```

| Flag | Description |
|------|---|
| `--ip-range CIDR` | Update IP block |
| `--hold-duration DURATION` | Update IP hold time |
| `--allowed-ports PORTS` | Comma-separated allowed ports |
| `--max-peers NUM` | Maximum concurrent peers |
| `--whitelist-mode BOOL` | Enable/disable whitelist quarantine |

Changes are signed by the authority key and gossiped to all peers.

### Delegation Commands

Grant or revoke config-write authority to other peers.

#### `p2pvpn delegate add <peer-pubkey>`

Grant config-signing authority to another peer.

```bash
p2pvpn delegate add QmBcdef5678...
```

This peer can now push signed config updates.

#### `p2pvpn delegate remove <peer-pubkey>`

Revoke config-signing authority.

```bash
p2pvpn delegate remove QmBcdef5678...
```

### Whitelist Commands

Manage peer access control (whitelist mode only).

#### `p2pvpn whitelist add <peer-id>`

Add a peer to the allowed list.

```bash
p2pvpn whitelist add QmAbc...
```

Once added, this peer's traffic will be routed.

#### `p2pvpn whitelist remove <peer-id>`

Remove a peer from the allowed list.

```bash
p2pvpn whitelist remove QmAbc...
```

#### `p2pvpn whitelist list`

Show the current whitelist.

```bash
p2pvpn whitelist list

# Output:
Allowed peers (3):
  QmAbc...
  QmBcdef...
  QmXyz...
```

### Global Flags

All commands support:

```bash
p2pvpn [command] -v              # Enable verbose debug logging
p2pvpn [command] -s /tmp/sock    # Custom IPC socket path
p2pvpn [command] --state-dir DIR # Custom state directory
```

| Flag | Description | Default |
|------|---|---|
| `-v, --verbose` | Enable verbose debug logging to stderr | false |
| `-s, --socket PATH` | IPC socket path | `/var/run/p2pvpn.sock` |
| `--state-dir DIR` | Persistent state directory | `~/.config/p2pvpn` |

## Configuration Options

The distributed config node (`10.x.x.1`) holds network-wide policy, replicated to all peers via gossip:

| Field | Type | Default | Description |
|---|---|---|---|
| `ip-range` | string | `10.42.0.0/24` | CIDR block for IP assignment |
| `ip-hold-duration` | duration | `5m` | How long to hold a peer's IP after disconnect |
| `max-peers` | int | ∞ | Maximum concurrent peers in network |
| `whitelist-mode` | bool | false | If true, new peers are quarantined until approved |
| `allowed-peers` | []string | — | Peer IDs permitted to participate (whitelist mode) |
| `allowed-ports` | []int | — | Ports allowed for peer communication (optional) |
| `delegated-peers` | []string | — | Peer public keys with config-write authority |

All changes are signed by the authority and gossiped via GossipSub.

## Architecture

### Peer Discovery (libp2p DHT)

1. **Bootstrap** — Daemon seeds DHT with bootstrap peers (hardcoded public IPFS nodes or user-supplied via `--peer`)
2. **Announce** — Each peer announces itself to the DHT under the network **public key** as the rendezvous topic
3. **Find** — Joining peers look up the public key in the DHT and learn multiaddresses of other peers
4. **Connect** — Establish direct TCP/QUIC connections with Noise encryption; libp2p manages reconnection on failure

### Config Propagation (GossipSub)

- All peers subscribe to a network-derived **GossipSub topic**
- Config updates are signed by the authority and published
- Each receiving peer verifies the signature before applying
- **No central broadcaster** — gossip consensus ensures rapid convergence

### IP Assignment (Deterministic)

- Each peer computes `SHA256(namespace, peer-id) mod subnet-size` independently
- If collision detected, probe forward until finding unused address
- **No allocator service** — fully distributed, collision-resistant

### Virtual Networking (TUN Interface)

- **Linux**: Raw syscall TUN creation with non-blocking mode for Go's epoll poller
- **Peer-to-IP mapping**: Maintained in memory; looked up on packet read
- **Packet forward**: Serialize IPv4 packets into frames; send over encrypted libp2p stream
- **Packet receive**: Deserialize frames; write back to TUN interface

## Security Model

### Transit Encryption
All peer-to-peer streams use **Noise protocol** (AEAD with 256-bit keys). No plaintext data on the wire.

### Network Access
Gated by the **Ed25519 public key** (DHT rendezvous topic). Intended to be shared freely; acts as network ID.

### Config Integrity (Signed Updates)
- In **host-locked mode**: All config updates must be signed by the network **private key**
- Every peer independently verifies signatures; invalid updates are rejected
- **No central authority** — enforcement is fully distributed
- Signature verification happens locally on each peer

### Delegation (Signed Delegation Records)
- Network authority grants config-write permission via signed **delegation records**
- Delegation itself is signed by the network private key
- Any peer can verify: `Signature(DelegationRecord) was created by network-priv`
- Revocation via new signed update; immediate effect after gossip convergence

### Peer Whitelist (Quarantine Mode)
- Optional mode enabled via `config set --whitelist-mode`
- New peers connect but cannot send/receive until added to `allowed-peers`
- `allowed-peers` is part of the signed config state
- **Enforcement is local** — each peer independently checks routes

### IP Spoofing Resistance
Peer-to-IP mappings derived from **verified peer identities** (Ed25519 public keys), not self-reported. Routes only installed after successful peer authentication.

## Debugging

### Enable Verbose Logging

Add `-v` flag to any command:

```bash
sudo p2pvpn daemon start --network-pub 08d7f3a... -v
```

Output tags:
- `[p2p]` — Peer discovery, streams, connection events
- `[daemon]` — Peer connect/disconnect, IP assignment, routes
- `[tun]` — Packet read/write, interface events
- `[gossip]` — Config publication and receipt
- `[auth]` — Signature verification, delegation checks

### Check Daemon Status

```bash
p2pvpn status       # Daemon status and assigned IP
p2pvpn peers list   # Connected peers
p2pvpn config get   # Current network config
```

### IPC Socket

The daemon listens on a Unix domain socket for RPC commands. Test manually:

```bash
echo '{"method": "status", "params": {}}' | nc -U /var/run/p2pvpn.sock
```

### Common Issues

**"address already in use"** — Another daemon is running:
```bash
p2pvpn daemon stop
# or
sudo pkill -f "daemon start"
```

**"no peers connected"** — Check discovery with verbose logging:
```bash
sudo p2pvpn daemon start -v  # Look for [p2p] discovery logs
```

**"read /dev/net/tun: operation not permitted"** — Daemon must run as root:
```bash
sudo p2pvpn ...
```

**"TUN interface already exists"** — Previous daemon crashed:
```bash
sudo ip link del tun0  # or appropriate device name
```

## Advanced Usage

### Multi-Admin Delegation

Network creator starts with private key; later delegates authority:

```bash
# Get delegated peer's public key
p2pvpn status  # on Peer B

# From Peer A (authority):
p2pvpn delegate add QmBcdef5678...

# Now Peer B can push config updates:
p2pvpn config set --max-peers 100
```

### Combining Whitelist + Delegation

1. Enable whitelist mode:
   ```bash
   p2pvpn config set --whitelist-mode
   ```

2. Delegate to a peer (Peer B):
   ```bash
   p2pvpn delegate add QmBcdef5678...
   ```

3. Peer B can now approve new peers without authority key:
   ```bash
   # as Peer B
   p2pvpn whitelist add QmNewPeer...
   ```

### Bootstrap from Private DHT

For networks behind NAT with no public DHT access, use explicit bootstrap peers:

```bash
sudo p2pvpn daemon start \
  --network-pub 08d7f3a... \
  --peer /ip4/203.0.113.45/tcp/7777/p2p/QmKnownPeer... \
  --peer /ip4/198.51.100.1/tcp/8888/p2p/QmAnotherPeer...
```

### Persistent Configuration

Save network keys and common flags:

```bash
# Create config file
mkdir -p ~/.config/p2pvpn
cat > ~/.config/p2pvpn/config.sh << 'EOF'
export NETWORK_PUB="08d7f3a..."
export NETWORK_PRIV="3c2e8b1..."
export NETWORK_CIDR="10.42.0.0/24"
EOF

# Use in scripts
source ~/.config/p2pvpn/config.sh
sudo p2pvpn daemon start \
  --network-pub "$NETWORK_PUB" \
  --network-priv "$NETWORK_PRIV" \
  --cidr "$NETWORK_CIDR"
```

## Comparison with Other VPN Solutions

| Feature | p2pvpn | ZeroTier | Tailscale | WireGuard |
|---|---|---|---|---|
| **Central server** | None | ZeroTier roots | Coordination+DERP | None |
| **Account required** | No | Yes | Yes | No |
| **Config distribution** | Gossip + signed | Central | Central | Manual |
| **Delegated admins** | Yes | No | Yes | N/A |
| **Whitelist mode** | Yes | Yes | ACLs | No |
| **Encryption** | Noise (libp2p) | Custom | WireGuard | WireGuard |
| **Peer discovery** | DHT | Central | Central | Manual |
| **Platforms** | Linux | Wide | Wide | Very wide |
| **License** | Open Source | Proprietary | Proprietary | GPL |

## Technical Deep Dive

For detailed technical explanations of the implementation, peer discovery procedure, IP assignment algorithm, config propagation protocol, TUN read/write loops, authentication model, and whitelist enforcement, see [technicals.md](technicals.md).

## License

See [LICENSE](LICENSE).
