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
