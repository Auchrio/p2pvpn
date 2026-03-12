# p2pvpn — Serverless P2P Mesh VPN

A **fully decentralized, self-hosted peer-to-peer mesh VPN** with no central servers, support for delegated network administrators, and signed configuration policy enforced by every peer.

## TL;DR

```bash
# On machine A: create a new network (generates config file)
p2pvpn network create mynet --cidr 10.42.0.0/24
# Output: mynet.conf (contains keys + settings)

# Start the daemon using the config file
sudo p2pvpn daemon start --config mynet.conf

# Optionally: enable autostart on boot
sudo p2pvpn daemon autostart mynet.conf

# Get status
p2pvpn status
p2pvpn peers list

# On machine B: join the network using the config
sudo p2pvpn network join --config mynet.conf

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
✓ **NAT traversal** — Automatic hole-punching, relay circuits (QUIC-based), and coordinated firewall traversal  
✓ **Config persistence** — Network settings saved to `.conf` files; reusable across reboots  
✓ **Systemd & Windows service integration** — Optional auto-start daemon on boot with automatic restart on failure  

## Comparison with Other VPN Solutions

### Why p2pvpn?

ZeroTier and Tailscale are excellent products but monetize by restricting free tiers.
p2pvpn provides equivalent core functionality with **zero artificial limits** and **no account required**.

### Feature Comparison

| Feature | p2pvpn | ZeroTier (Free) | Tailscale (Free) |
|---|---|---|---|
| **Price** | **Free, forever** | Free up to limits | Free up to limits |
| **Device limit** | **Unlimited** | 25 devices | 100 devices |
| **User / admin seats** | **Unlimited** | 1 admin | 3 users |
| **Network count** | **Unlimited** | 1 network | 1 tailnet |
| **Account / sign-up required** | **No** | Yes | Yes (Google/Microsoft/etc.) |
| **Central server dependency** | **None** | ZeroTier root servers | Coordination server + DERP relays |
| **Subnet routing** | **Included** | Paid plans only | Paid plans only |
| **Access control / ACLs** | **Included** (whitelist + delegation) | Paid plans only (Flow Rules) | Limited (full ACLs paid) |
| **Custom DNS** | Network-level | Paid plans only | Limited free |
| **SSO / OIDC integration** | N/A (keypair auth) | Paid plans only | Paid plans only |
| **Admin API** | IPC + Web UI | Paid plans only | Paid plans only |
| **Priority support / SLA** | Community | Paid plans only | Paid plans only |
| **Self-hosted / air-gapped** | **Yes, fully** | Requires root servers | Requires coordination server |
| **Open source** | **Yes (full)** | Partially | Client only |

### Architecture Comparison

| Aspect | p2pvpn | ZeroTier | Tailscale |
|---|---|---|---|
| **Peer discovery** | DHT (fully decentralized) | Central root servers | Central coordination |
| **Config distribution** | Gossip + Ed25519 signatures | Centralized push | Centralized push |
| **Delegated admins** | Yes (signed delegation records) | No (single owner on free) | No (1 admin on free) |
| **NAT traversal** | Automatic (hole-punch + relay) | Automatic | Automatic (DERP relays) |
| **Encryption** | Noise protocol (libp2p) | Custom (ChaCha20-Poly1305) | WireGuard (ChaCha20-Poly1305) |
| **Platforms** | Linux, Windows | Linux, Windows, macOS, mobile | Linux, Windows, macOS, mobile |

### Key Advantages

- **No vendor lock-in** — Your network runs entirely on your hardware. No accounts, no telemetry, no central servers that can go down or change pricing.
- **No artificial limits** — Connect as many devices, create as many networks, and add as many admins as you need. No "upgrade to unlock" gates.
- **Delegated authority** — Grant config-signing privileges to trusted peers without sharing the master private key. ZeroTier and Tailscale restrict multi-admin to paid tiers.
- **Air-gap friendly** — Works in fully isolated environments with bootstrap peers. No internet-facing coordination server needed.
- **Whitelist mode included** — Quarantine and approve new peers at no cost. Comparable ACL features in ZeroTier (Flow Rules) and Tailscale require paid plans.

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

Network creator (machine A) generates a network and config file:

```bash
p2pvpn network create mynet --cidr 10.42.0.0/24
```

Output:
```
Network created successfully!

  Public key  (network ID, share freely): 08d7f3a...
  Private key (authority key, keep safe): 3c2e8b1...

Settings:
  CIDR          : 10.42.0.0/24
  IP hold time  : 5m

Config saved to: mynet.conf

To start the daemon:
  sudo p2pvpn daemon start --config mynet.conf

To enable autostart on boot:
  sudo p2pvpn daemon autostart mynet.conf
```

The `.conf` file contains all network parameters and can be:
- **Shared with peers** — They use `sudo p2pvpn network join --config mynet.conf` to join
- **Reused across reboots** — `sudo p2pvpn daemon start --config mynet.conf` always uses the same network
- **Backed up** — Store it in a safe location; it's all you need to rejoin the network

### 3. Start the First Peer (Network Creator)

```bash
sudo p2pvpn daemon start --config mynet.conf
```

The daemon will:
- Create a peer identity (Ed25519 keypair)
- Join the DHT with the public key as the rendezvous topic
- Discover peers and bridge packets across the network
- Assign itself a virtual IP (deterministically computed)
- Create a TUN interface
- Start listening for incoming peer connections

**For machines behind NAT or CGNAT:** The daemon automatically:
- Attempts UPnP/NAT-PMP port mapping if available
- Uses libp2p relay circuits as a fallback (circuit relay v2 protocol)
- Performs coordinated hole-punching to upgrade relay connections to direct
- Advertises all reachable addresses to other peers

**Relay circuits:** When direct connections aren't possible (CGNAT, restrictive firewalls), peers automatically:
1. Discover relay nodes (pub/sub gossip on the DHT)
2. Reserve a relay slot on a relay node
3. Connect through the relay node as an intermediary
4. Attempt coordinated hole-punching to upgrade to direct
5. Route packets through the relay until a direct path is available

Relay paths are **fully encrypted end-to-end** using the same Noise encryption as direct connections — the relay node sees only encrypted packets and cannot inspect VPN traffic.

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

On machine B: Copy `mynet.conf` from machine A, then join:
```bash
cp mynet.conf /tmp/  # from machine A
sudo p2pvpn network join --config /tmp/mynet.conf
```

Alternatively, join directly by public key (without copying the file):
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

**NAT-friendly:** If behind a different NAT/CGNAT than machine A, the daemon automatically negotiates a relay path or direct hole-punched connection.

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

## Network Config Files

When you run `p2pvpn network create`, a `.conf` file is automatically generated with all network parameters and keys. This file is:

- **Portable** — Copy it to other machines to let them join the same network
- **Reusable** — Use `--config` with `daemon start` or `network join` to avoid typing keys
- **Backupable** — Store it securely; it's sufficient to rejoin your network after a reinstall
- **Safe** — Readable only by root (mode 0600); includes both public and private keys

### Config File Format

The `.conf` file is a simple KEY=VALUE text format:

```ini
# p2pvpn network configuration
# Generated by: p2pvpn network create

NETWORK_PUB=<hex-public-key>
NETWORK_PRIV=<hex-private-key>

CIDR=10.42.0.0/24
PREFERRED_IP=
HOST_LOCKED=false
LISTEN_PORT=0
BOOTSTRAP_PEERS=

VERBOSE=false
STATE_DIR=
SOCKET=
```

### Using Config Files

**Start the daemon with a config file:**
```bash
sudo p2pvpn daemon start --config ~/.config/p2pvpn/mynet.conf
```

**Join a network using the config file (other peer):**
```bash
sudo p2pvpn network join --config mynet.conf
```

**Override config values with CLI flags:**
```bash
# Config file says CIDR=10.42.0.0/24, but override it:
sudo p2pvpn daemon start --config mynet.conf --cidr 10.50.0.0/24
```

CLI flags always take precedence over values in the config file.

## Daemon Autostart Setup

To make the daemon start automatically on boot and restart on failure, use `daemon autostart` on **Linux with systemd**:

```bash
# Install the service
sudo p2pvpn daemon autostart mynet.conf
```

This command:
1. Creates a systemd service unit file (`/etc/systemd/system/p2pvpn.service`)
2. Enables the service to start on boot
3. Starts the daemon immediately
4. Configures auto-restart on crashes (5s delay between restarts)

### Managing the Autostart Service

**Check status:**
```bash
sudo systemctl status p2pvpn
```

**View recent logs:**
```bash
journalctl -u p2pvpn -f
```

**Manually stop/start:**
```bash
sudo systemctl stop p2pvpn
sudo systemctl start p2pvpn
```

**Restart on next boot:**
```bash
sudo systemctl restart p2pvpn
```

**Disable autostart (keep running until next reboot):**
```bash
sudo systemctl disable p2pvpn
# Then stop manually:
sudo systemctl stop p2pvpn
```

**Remove the service completely:**
```bash
sudo p2pvpn daemon autostart mynet.conf --remove
```

## Command Reference

### Network Commands

#### `p2pvpn network create [name] [flags]`

Generate a new Ed25519 keypair for a network and write a `.conf` file.

```bash
# Create with default name (network.conf)
p2pvpn network create --cidr 10.42.0.0/24

# Create with custom name (output: mynet.conf)
p2pvpn network create mynet --cidr 10.42.0.0/24

# Create in a specific directory
p2pvpn network create office --out /etc/p2pvpn --cidr 10.50.0.0/24
```

| Flag | Description | Default |
|------|---|---|
| `[name]` | Config filename prefix (` <name>.conf`) | `network` |
| `--cidr CIDR` | Virtual IP block | `10.42.0.0/24` |
| `--hold-duration DURATION` | How long to hold a peer's IP after disconnect | `5m` |
| `--out DIR` | Save config file to this directory | current directory |
| `--port PORT` | libp2p listen port (written to conf) | (random, chosen by OS) |
| `--peer MULTIADDR` | Bootstrap peer multiaddr (repeatable) | (use public DHT) |
| `--host-locked` | Require signed config updates (written to conf) | false |

#### `p2pvpn network join [public-key] [flags]`

Start the daemon and join an existing network. You can either:
- Join using a config file (recommended): `--config <file.conf>`
- Join using the network's public key directly: `<public-key>`

```bash
# Join using config file (contains keys and CIDR)
sudo p2pvpn network join --config mynet.conf

# Join by public key only (uses defaults for CIDR, etc.)
sudo p2pvpn network join 08d7f3a...

# Join from config but override specific settings
sudo p2pvpn network join --config mynet.conf --preferred-ip 10.42.0.5
```

| Flag | Description | Default |
|------|---|---|
| `[public-key]` | Network public key (optional if `--config` is used) | — |
| `-c, --config FILE` | Config file path (from `network create`) | — |
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

Start the VPN daemon in the foreground. You can either:
- Start from a config file (recommended): `--config <file.conf>`
- Start with CLI flags: `--network-pub <key> [--network-priv <key>]`

```bash
# Start from config file
sudo p2pvpn daemon start --config mynet.conf

# Start with CLI flags (legacy)
sudo p2pvpn daemon start \
  --network-pub 08d7f3a... \
  --network-priv 3c2e8b1... \
  --cidr 10.42.0.0/24

# Start from config but override a setting
sudo p2pvpn daemon start --config mynet.conf --port 7777
```

| Flag | Description | Required |
|------|---|---|
| `-c, --config FILE` | Config file path (from `network create`) | If no `--network-pub` |
| `--network-pub KEY` | Network public key | If no `--config` |
| `--network-priv KEY` | Network private key (authority mode) | No |
| `--cidr CIDR` | Virtual IP block | No |
| `--preferred-ip IP` | Request specific virtual IP | No |
| `--port PORT` | Listen port | No |
| `--host-locked` | Require signed config updates | No |
| `--peer MULTIADDR` | Bootstrap peer (repeatable) | No |

#### `p2pvpn daemon autostart <config-file> [flags]`

**Linux only.** Install a systemd service that starts the daemon on boot with auto-restart.

```bash
# Install and enable the service
sudo p2pvpn daemon autostart mynet.conf

# Use a custom service name
sudo p2pvpn daemon autostart mynet.conf --name p2pvpn-office

# Write the service file but don't enable/start yet
sudo p2pvpn daemon autostart mynet.conf --no-enable

# Remove the service
sudo p2pvpn daemon autostart mynet.conf --remove
```

| Flag | Description | Default |
|------|---|---|
| `<config-file>` | Path to `.conf` file (from `network create`) | — |
| `--name NAME` | systemd service name (e.g., `p2pvpn-office`) | `p2pvpn` |
| `--bin PATH` | Path to p2pvpn binary (auto-detected if not specified) | (auto-detect) |
| `--no-enable` | Write service file but don't start/enable | false |
| `--remove` | Uninstall the service | false |

**What it does:**
1. Writes a systemd unit file to `/etc/systemd/system/<name>.service`
2. Reloads the systemd daemon
3. Enables the service (auto-start on boot)
4. Starts the daemon immediately
5. Configures restart on failure (5-second delay)

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

Optional access control mode enabled via `config set --whitelist-mode`. When enabled:

- **Quarantine on connect** — New peers are placed in quarantine immediately upon connecting
- **No resource consumption** — Quarantined peers do **not** consume virtual IPs, TUN routes, or other network resources until approved
- **Traffic blocked** — Quarantined peers cannot send/receive VPN traffic
- **Config sanitization** — Sensitive fields (`allowed-peers`, `delegations`) are stripped from state syncs, preventing adversaries from enumerating the whitelist
- **Auto-disconnect** — Peers that remain quarantined for more than 2 minutes are automatically disconnected to prevent resource exhaustion
- **Instant promotion** — When added to `allowed-peers`, the peer is immediately assigned an IP and routes without requiring reconnection

**Security notes:**
- Enforcement is local — each peer independently checks whitelist membership
- Quarantined peers can still participate in DHT (cannot be prevented without breaking libp2p)
- See [SECURITY.md](SECURITY.md) for detailed threat analysis and remaining attack surface

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

### NAT Traversal & Relay Circuits

The daemon automatically optimizes for peers behind NAT or CGNAT:

- **Transport options:** Listens on TCP, QUIC, and WebTransport to maximize compatibility
- **Relay selection:** Smart candidate filtering prioritizes peers that advertise relay v2 support
- **Hole-punching:** Coordinated ICE-style negotiation attempts direct connection once relay is established

**Verbose relay diagnostics:**
```bash
sudo p2pvpn daemon start -v 2>&1 | grep -E '\[nat\]|\[p2p\]'

# Output examples:
[nat] Reachability forced to PRIVATE — actively seeking relay from startup
[p2p] Bootstrap: 3/10 IPFS peers connected, DHT routing table: 3
[nat] peerSource: 2 relay-capable, 12 total candidates (from 12 connected)
[nat] ✓ Relay address available — peers behind NAT can reach us
[p2p] ✓ VPN stream opened to Qm12345...
```

**Relay candidates are selected in priority order:**
1. **Relay-capable peers** (advertise `/libp2p/circuit/relay/0.2.0/hop`) — most likely to succeed
2. DHT routing table peers (may support relay)
3. Remaining connected peers (fallback)
4. IPFS bootstrap peers (public last resort)

This adaptive selection ensures reliable relay reservations even on slow mobile networks.

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



## Security

### Encryption & Data Privacy

All peer-to-peer traffic uses the **Noise protocol** with 256-bit keys for authenticated encryption. Data is encrypted at the application layer before transmission, ensuring end-to-end confidentiality and integrity. Configuration updates are signed with Ed25519 keys and verified independently by each peer.

### Relay Circuits & NAT Traversal

When peers are behind NAT or CGNAT, the daemon automatically negotiates relay circuits. **Relay nodes cannot inspect or modify VPN traffic** because frames are encrypted end-to-end. The relay only sees encrypted packets and metadata (peer IDs, connection timing).

For detailed security analysis of relay usage, threat models, and best practices for enterprise deployments, see [SECURITY.md](SECURITY.md).

### Configuration Integrity

Network configuration is distributed via GossipSub gossip protocol. All updates must be cryptographically signed if `host-locked` mode is enabled. Peers reject unsigned or incorrectly signed updates, preventing unauthorized configuration changes.

## Technical Deep Dive

For detailed technical explanations of the implementation, peer discovery procedure, IP assignment algorithm, config propagation protocol, TUN read/write loops, authentication model, and whitelist enforcement, see [technicals.md](technicals.md).

## License

See [LICENSE](LICENSE).
