# v1.1.0 Release Notes

## What's New

- **Windows autostart support** — Install as a Windows Service via `p2pvpn daemon autostart` (complements existing systemd support on Linux)
- **Bundled wintun.dll** — Windows releases now include architecture-specific DLL files, eliminating manual setup
- **README comparison tables** — New tables highlighting p2pvpn vs. ZeroTier vs. Tailscale with focus on free-tier advantages
- **Polished Web UI** — Enhanced Virtual Router dashboard with improved styling

## Downloads

- Linux: `p2pvpn-linux-{x64,x86,arm,arm64}`
- Windows: `p2pvpn-windows-{x64,arm64}.zip` (includes wintun.dll)

# v1.2.0 Release Notes

## What's New

### Setup & Installation
- **Config-less daemon startup** — Run `p2pvpn setup` to enter interactive setup mode without a pre-existing config file
- **WebUI setup wizard** — Three-tab wizard in setup mode: Create Network, Join Network, Upload Config
- **Unified install scripts** — Cross-platform install scripts for Linux (`install.sh`) and Windows (`install.ps1`) with automatic architecture detection
- **Network creation from UI** — Create a new p2pvpn network directly from the WebUI setup wizard (no CLI required)

### Daemon Management
- **Daemon restart via WebUI** — Restart the daemon without stopping the local service via the new Daemon management tab
- **Setup port fallback** — Setup mode intelligently tries ports 8080–8090 before falling back to OS-assigned port

### Web UI Improvements
- **Unified Manage button** — Single "⚙ Manage" button accessible in both viewer and editor modes, consolidating Download, Update Config, Remove, and Daemon Restart
- **Viewer access to daemon restart** — Viewers can now restart the daemon without requiring edit privileges
- **Improved authentication flow** — Fixed private key authentication; viewers with the network private key automatically elevate to editor mode

## Downloads

- Linux: `p2pvpn-linux-{x64,x86,arm,arm64}`
- Windows: `p2pvpn-windows-{x64,arm64}.zip` (includes wintun.dll)

# v1.3.0 Release Notes

## What's New

### Whitelist Mode Security Hardening

Major security improvements to prevent resource exhaustion and information leakage from quarantined (non-whitelisted) peers:

- **Deferred IP assignment** — Quarantined peers no longer consume virtual IPs from the CIDR pool. IPs are only assigned when a peer is whitelisted, preventing IP pool exhaustion attacks.
- **No TUN route installation** — Routes are only installed for whitelisted peers. Quarantined peers do not accumulate `/32` routes in the kernel routing table.
- **Quarantine timeout (2 minutes)** — Peers that remain quarantined for more than 2 minutes are automatically disconnected. This prevents indefinite resource consumption (file descriptors, memory, DHT routing slots).
- **Config sanitization** — Gossip state syncs now strip sensitive fields (`allowed-peers`, `delegated-peers`, `delegations`) when whitelist mode is enabled. Quarantined peers can no longer enumerate the whitelist.
- **Instant promotion** — When a quarantined peer is added to the whitelist, the `OnPeerPromoted` callback immediately assigns an IP and installs routes without requiring reconnection.

### Peer Reconnection Improvements

Fixes for peer reconnection issues when peers restart (from v1.2.1 development):

- **Active reconnection loop** — Tracks recently-disconnected VPN peers and aggressively attempts DHT-based reconnection every 10 seconds for up to 30 minutes.
- **Stale address cleanup** — Peerstore addresses are cleared before reconnection attempts, ensuring fresh relay addresses are used instead of expired circuits.
- **Re-advertisement on relay change** — When relay addresses update, the node immediately re-advertises on the DHT so peers can discover the new addresses.
- **DHT re-bootstrap instead of restart** — When all peers disconnect, the daemon re-bootstraps the DHT after 15 seconds instead of restarting entirely, preserving relay reservations.

### Security Documentation

- **Updated SECURITY.md** — Comprehensive documentation of whitelist mode security model, including the new v1.3.0 hardening measures and remaining attack surface.
- **Detailed relay encryption analysis** — In-depth explanation of the three encryption layers used when traffic flows through relays, demonstrating end-to-end security.

## Breaking Changes

None. Fully backward compatible with v1.2.x networks.

## Downloads

- Linux: `p2pvpn-linux-{x64,x86,arm,arm64}`
- Windows: `p2pvpn-windows-{x64,arm64}.zip` (includes wintun.dll)
