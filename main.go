package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"p2pvpn/utils/daemon"
	"p2pvpn/utils/ipcclient"
	"p2pvpn/utils/keypair"
	"p2pvpn/utils/netconf"
	"p2pvpn/utils/store"
	"p2pvpn/utils/vlog"
)

// ─── global flags ─────────────────────────────────────────────────────────────

var (
	flagSocket   string // --socket / -s  (IPC socket path)
	flagStateDir string // --state-dir
	flagVerbose  bool   // -v / --verbose
)

func main() {
	root := &cobra.Command{
		Use:   "p2pvpn",
		Short: "P2P Mesh VPN — serverless, keypair-based virtual networking",
		Long: `p2pvpn creates a serverless mesh VPN using libp2p for peer discovery and
encrypted transport, and a Linux TUN interface for virtual Layer-3 networking.

A network is identified by an Ed25519 keypair.  The public key is the network
ID (DHT rendezvous topic); the private key is the config-signing authority.

Subcommand groups:
  network   create / join / leave
  daemon    start / stop
  status    show daemon status
  peers     list connected peers
  config    get / set distributed config
  delegate  manage delegated admin peers
  whitelist manage per-peer access (whitelist mode)`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVarP(&flagSocket, "socket", "s", daemon.DefaultSocketPath,
		"path to the daemon Unix socket")
	root.PersistentFlags().StringVar(&flagStateDir, "state-dir", store.DefaultStateDir,
		"directory for persistent daemon state")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false,
		"enable verbose debug logging to stderr")
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if flagVerbose {
			vlog.Enable()
		}
	}

	root.AddCommand(
		networkCmd(),
		daemonCmd(),
		statusCmd(),
		peersCmd(),
		configCmd(),
		delegateCmd(),
		whitelistCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─── network ──────────────────────────────────────────────────────────────────

func networkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage network keypairs and membership",
	}
	cmd.AddCommand(networkCreateCmd(), networkJoinCmd(), networkLeaveCmd())
	return cmd
}

func networkCreateCmd() *cobra.Command {
	var cidr string
	var holdDuration time.Duration
	var outDir string
	var hostLocked bool
	var port int
	var bootstrapPeers []string

	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Generate a new network keypair and config file",
		Args:  cobra.MaximumNArgs(1),
		Long: `Generates a fresh Ed25519 keypair that defines a new network and writes a
.conf file to the current directory (or the --out directory).

The optional [name] argument becomes the config filename: <name>.conf
If omitted, the file is named "network.conf".

The public key is the network ID: share it with peers who should join.
The private key is the config-signing authority: keep it safe.

Examples:
  p2pvpn network create
  p2pvpn network create mynet --cidr 10.42.0.0/24
  p2pvpn network create office --out /etc/p2pvpn --host-locked`,
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := keypair.GenerateNetworkKeypair()
			if err != nil {
				return err
			}

			// Determine config file name.
			confName := "network"
			if len(args) > 0 && args[0] != "" {
				confName = args[0]
			}
			confFile := confName + ".conf"

			fmt.Printf("Network created successfully!\n\n")
			fmt.Printf("  Public key  (network ID, share freely): %s\n", kp.PublicKey)
			fmt.Printf("  Private key (authority key, keep safe): %s\n", kp.PrivateKey)
			fmt.Printf("\nSettings:\n")
			fmt.Printf("  CIDR          : %s\n", cidr)
			fmt.Printf("  IP hold time  : %s\n", holdDuration)

			// Build the config.
			nc := &netconf.NetConf{
				NetworkPubKey:  kp.PublicKey,
				NetworkPrivKey: kp.PrivateKey,
				CIDR:           cidr,
				HostLocked:     hostLocked,
				ListenPort:     port,
			}
			if len(bootstrapPeers) > 0 {
				nc.BootstrapPeers = strings.Join(bootstrapPeers, ",")
			}

			// Determine output directory.
			dir := "."
			if outDir != "" {
				dir = outDir
				if err := os.MkdirAll(dir, 0700); err != nil {
					return fmt.Errorf("creating output dir: %w", err)
				}
			}

			// Write .conf file.
			confPath := filepath.Join(dir, confFile)
			if err := nc.Save(confPath); err != nil {
				return err
			}
			fmt.Printf("\nConfig saved to: %s\n", confPath)

			// Also write separate key files into --out if provided.
			if outDir != "" {
				pubPath := filepath.Join(dir, confName+".pub")
				privPath := filepath.Join(dir, confName+".key")
				if err := os.WriteFile(pubPath, []byte(kp.PublicKey), 0644); err != nil {
					return err
				}
				if err := os.WriteFile(privPath, []byte(kp.PrivateKey), 0600); err != nil {
					return err
				}
				fmt.Printf("Keypair saved to:\n  %s\n  %s\n", pubPath, privPath)
			}

			// Automatically start the daemon with the new network.
			fmt.Printf("\nStarting daemon...\n")

			cfg := daemon.Config{
				NetworkPubKey:  kp.PublicKey,
				NetworkPrivKey: kp.PrivateKey,
				CIDR:           cidr,
				HostLocked:     hostLocked,
				ListenPort:     port,
				BootstrapPeers: bootstrapPeers,
				StateDir:       flagStateDir,
				SocketPath:     flagSocket,
				Verbose:        flagVerbose,
			}

			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()
			return daemon.Start(ctx, cfg)
		},
	}
	cmd.Flags().StringVar(&cidr, "cidr", "10.42.0.0/24", "CIDR block for virtual IP assignment")
	cmd.Flags().DurationVar(&holdDuration, "hold-duration", 5*time.Minute, "IP hold time on disconnect")
	cmd.Flags().StringVar(&outDir, "out", "", "save config and keypair files to this directory")
	cmd.Flags().BoolVar(&hostLocked, "host-locked", false, "require signed config updates (written to conf)")
	cmd.Flags().IntVar(&port, "port", 0, "libp2p listen port (written to conf)")
	cmd.Flags().StringArrayVar(&bootstrapPeers, "peer", nil, "bootstrap peer multiaddr (repeatable, written to conf)")
	return cmd
}

func networkJoinCmd() *cobra.Command {
	var preferredIP string
	var networkPriv string
	var cidr string
	var port int
	var hostLocked bool
	var bootstrapPeers []string
	var configFile string
	var outDir string

	cmd := &cobra.Command{
		Use:   "join [network-public-key]",
		Short: "Join an existing network (starts the daemon)",
		Args:  cobra.MaximumNArgs(1),
		Long: `Starts the daemon and joins the network identified by <network-public-key>
or a config file.

The daemon will:
  1. Discover peers via the libp2p DHT using the public key as rendezvous topic.
  2. Assign itself a virtual IP in the network's CIDR block.
  3. Create a TUN interface and route traffic to/from connected peers.

A local .conf file is saved automatically so you can re-join later with:
  sudo p2pvpn daemon start --config <name>.conf

Requires root privileges (TUN interface creation).

Examples:
  sudo p2pvpn network join <hex-public-key>
  sudo p2pvpn network join --config network.conf
  sudo p2pvpn network join <hex-public-key> --preferred-ip 10.42.0.5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := daemon.Config{
				StateDir:   flagStateDir,
				SocketPath: flagSocket,
				Verbose:    flagVerbose,
			}

			// Load config file first (if specified), then overlay CLI flags.
			if configFile != "" {
				nc, err := netconf.Load(configFile)
				if err != nil {
					return err
				}
				cfg.NetworkPubKey = nc.NetworkPubKey
				cfg.NetworkPrivKey = nc.NetworkPrivKey
				cfg.CIDR = nc.CIDR
				cfg.PreferredIP = nc.PreferredIP
				cfg.HostLocked = nc.HostLocked
				cfg.ListenPort = nc.ListenPort
				cfg.BootstrapPeers = nc.BootstrapPeerList()
				if nc.Verbose {
					cfg.Verbose = true
				}
				if nc.StateDir != "" {
					cfg.StateDir = nc.StateDir
				}
				if nc.Socket != "" {
					cfg.SocketPath = nc.Socket
				}
			}

			// Positional arg overrides config file pub key.
			if len(args) > 0 {
				cfg.NetworkPubKey = args[0]
			}

			// CLI flags override config/positional values.
			if cmd.Flags().Changed("network-priv") {
				cfg.NetworkPrivKey = networkPriv
			}
			if cmd.Flags().Changed("preferred-ip") {
				cfg.PreferredIP = preferredIP
			}
			if cmd.Flags().Changed("cidr") {
				cfg.CIDR = cidr
			}
			if cmd.Flags().Changed("port") {
				cfg.ListenPort = port
			}
			if cmd.Flags().Changed("host-locked") {
				cfg.HostLocked = hostLocked
			}
			if cmd.Flags().Changed("peer") {
				cfg.BootstrapPeers = bootstrapPeers
			}

			if cfg.NetworkPubKey == "" {
				return fmt.Errorf("provide a network public key or --config")
			}
			if _, err := keypair.DecodeNetworkPublicKey(cfg.NetworkPubKey); err != nil {
				return fmt.Errorf("invalid network public key: %w", err)
			}
			if cfg.CIDR == "" {
				cfg.CIDR = "10.42.0.0/24"
			}

			// Save a local .conf so the user can re-join later with
			// "daemon start --config" without remembering all the flags.
			nc := &netconf.NetConf{
				NetworkPubKey:  cfg.NetworkPubKey,
				NetworkPrivKey: cfg.NetworkPrivKey,
				CIDR:           cfg.CIDR,
				PreferredIP:    cfg.PreferredIP,
				HostLocked:     cfg.HostLocked,
				ListenPort:     cfg.ListenPort,
			}
			if len(cfg.BootstrapPeers) > 0 {
				nc.BootstrapPeers = strings.Join(cfg.BootstrapPeers, ",")
			}

			// Determine output directory and filename.
			dir := "."
			if outDir != "" {
				dir = outDir
				if err := os.MkdirAll(dir, 0700); err != nil {
					return fmt.Errorf("creating output dir: %w", err)
				}
			}
			// Use the first 8 hex chars of the public key as a short filename.
			shortKey := cfg.NetworkPubKey
			if len(shortKey) > 8 {
				shortKey = shortKey[:8]
			}
			confPath := filepath.Join(dir, shortKey+".conf")
			if err := nc.Save(confPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not save local config: %v\n", err)
			} else {
				fmt.Printf("Local config saved to: %s\n", confPath)
				fmt.Printf("  Re-join later: sudo p2pvpn daemon start --config %s\n", confPath)
			}

			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()
			fmt.Printf("Joining network %s...\n", cfg.NetworkPubKey[:16]+"...")
			return daemon.Start(ctx, cfg)
		},
	}
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to a .conf file (from 'network create')")
	cmd.Flags().StringVar(&outDir, "out", "", "save local config file to this directory (default: current dir)")
	cmd.Flags().StringVar(&preferredIP, "preferred-ip", "", "request a specific virtual IP address")
	cmd.Flags().StringVar(&networkPriv, "network-priv", "", "network private key (authority mode)")
	cmd.Flags().StringVar(&cidr, "cidr", "", "CIDR block for virtual IP assignment")
	cmd.Flags().IntVar(&port, "port", 0, "libp2p listen port (0 = random)")
	cmd.Flags().BoolVar(&hostLocked, "host-locked", false, "require signed config updates")
	cmd.Flags().StringArrayVar(&bootstrapPeers, "peer", nil, "bootstrap peer multiaddr (repeatable)")
	return cmd
}

func networkLeaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "leave",
		Short: "Stop the daemon and leave the current network",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("stop", nil)
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Println("Left network. Daemon stopped.")
			return nil
		},
	}
}

// ─── daemon ───────────────────────────────────────────────────────────────────

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Directly manage the daemon process",
	}
	cmd.AddCommand(daemonStartCmd(), daemonStopCmd(), daemonAutostartCmd())
	return cmd
}

func daemonStartCmd() *cobra.Command {
	var networkPub string
	var networkPriv string
	var preferredIP string
	var cidr string
	var port int
	var hostLocked bool
	var bootstrapPeers []string
	var configFile string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the VPN daemon",
		Long: `Starts the VPN daemon in the foreground.  The daemon creates a TUN interface,
joins the DHT, and waits for peers.  Send SIGINT / SIGTERM to shut down cleanly.

You can pass a config file (generated by 'network create') instead of individual
flags.  CLI flags override values from the config file.

Requires root privileges.

Examples:
  sudo p2pvpn daemon start --config network.conf
  sudo p2pvpn daemon start --network-pub <hex> --network-priv <hex>
  sudo p2pvpn daemon start --config network.conf --preferred-ip 10.42.0.5`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := daemon.Config{
				StateDir:   flagStateDir,
				SocketPath: flagSocket,
				Verbose:    flagVerbose,
			}

			// Load config file first (if specified), then overlay CLI flags.
			if configFile != "" {
				nc, err := netconf.Load(configFile)
				if err != nil {
					return err
				}
				cfg.NetworkPubKey = nc.NetworkPubKey
				cfg.NetworkPrivKey = nc.NetworkPrivKey
				cfg.CIDR = nc.CIDR
				cfg.PreferredIP = nc.PreferredIP
				cfg.HostLocked = nc.HostLocked
				cfg.ListenPort = nc.ListenPort
				cfg.BootstrapPeers = nc.BootstrapPeerList()
				if nc.Verbose {
					cfg.Verbose = true
				}
				if nc.StateDir != "" {
					cfg.StateDir = nc.StateDir
				}
				if nc.Socket != "" {
					cfg.SocketPath = nc.Socket
				}
			}

			// CLI flags override config file values.
			if cmd.Flags().Changed("network-pub") {
				cfg.NetworkPubKey = networkPub
			}
			if cmd.Flags().Changed("network-priv") {
				cfg.NetworkPrivKey = networkPriv
			}
			if cmd.Flags().Changed("preferred-ip") {
				cfg.PreferredIP = preferredIP
			}
			if cmd.Flags().Changed("cidr") {
				cfg.CIDR = cidr
			}
			if cmd.Flags().Changed("port") {
				cfg.ListenPort = port
			}
			if cmd.Flags().Changed("host-locked") {
				cfg.HostLocked = hostLocked
			}
			if cmd.Flags().Changed("peer") {
				cfg.BootstrapPeers = bootstrapPeers
			}

			if cfg.NetworkPubKey == "" {
				return fmt.Errorf("--network-pub or --config is required")
			}
			if cfg.CIDR == "" {
				cfg.CIDR = "10.42.0.0/24"
			}

			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()
			return daemon.Start(ctx, cfg)
		},
	}
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to a .conf file (from 'network create')")
	cmd.Flags().StringVar(&networkPub, "network-pub", "", "network public key (hex Ed25519)")
	cmd.Flags().StringVar(&networkPriv, "network-priv", "", "network private key (hex Ed25519, authority only)")
	cmd.Flags().StringVar(&preferredIP, "preferred-ip", "", "preferred virtual IP address")
	cmd.Flags().StringVar(&cidr, "cidr", "", "CIDR block for virtual IP assignment")
	cmd.Flags().IntVar(&port, "port", 0, "libp2p listen port (0 = random)")
	cmd.Flags().BoolVar(&hostLocked, "host-locked", false, "require signed config updates (host-locked mode)")
	cmd.Flags().StringArrayVar(&bootstrapPeers, "peer", nil, "bootstrap peer multiaddr (repeatable)")
	return cmd
}

func daemonStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop a running daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("stop", nil)
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Println("Daemon stopped.")
			return nil
		},
	}
}

func daemonAutostartCmd() *cobra.Command {
	var serviceName string
	var binPath string
	var noEnable bool
	var remove bool

	cmd := &cobra.Command{
		Use:   "autostart <config-file>",
		Short: "Install a systemd service for automatic daemon startup",
		Long: `Creates a systemd service unit that starts the p2pvpn daemon on boot using the
specified config file.  The service is configured to auto-restart on failure.

This command:
  1. Resolves the config file to an absolute path.
  2. Writes a systemd unit file to /etc/systemd/system/.
  3. Runs 'systemctl daemon-reload'.
  4. Enables and starts the service.

Use --remove to uninstall the service.

Requires root privileges.

Examples:
  sudo p2pvpn daemon autostart network.conf
  sudo p2pvpn daemon autostart /etc/p2pvpn/office.conf --name p2pvpn-office
  sudo p2pvpn daemon autostart --remove --name p2pvpn`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS != "linux" {
				return fmt.Errorf("autostart is currently only supported on Linux (systemd)")
			}

			if serviceName == "" {
				serviceName = "p2pvpn"
			}
			unitPath := "/etc/systemd/system/" + serviceName + ".service"

			// ── Remove mode ───────────────────────────────────────────
			if remove {
				fmt.Printf("Removing service %s...\n", serviceName)
				_ = runSystemctl("stop", serviceName)
				_ = runSystemctl("disable", serviceName)
				if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("removing unit file: %w", err)
				}
				_ = runSystemctl("daemon-reload", "")
				fmt.Println("Service removed.")
				return nil
			}

			// ── Install mode ──────────────────────────────────────────
			if len(args) == 0 {
				return fmt.Errorf("config file argument is required (use --remove to uninstall)")
			}

			// Resolve config path to absolute.
			confPath, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("resolving config path: %w", err)
			}
			if _, err := os.Stat(confPath); err != nil {
				return fmt.Errorf("config file not found: %w", err)
			}

			// Validate it is a loadable config.
			if _, err := netconf.Load(confPath); err != nil {
				return err
			}

			// Resolve binary path.
			if binPath == "" {
				binPath, err = os.Executable()
				if err != nil {
					return fmt.Errorf("cannot determine binary path: %w", err)
				}
			}

			unit := generateSystemdUnit(serviceName, binPath, confPath)

			fmt.Printf("Writing %s\n", unitPath)
			if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
				return fmt.Errorf("writing unit file: %w", err)
			}

			fmt.Println("Reloading systemd...")
			if err := runSystemctl("daemon-reload", ""); err != nil {
				return fmt.Errorf("systemctl daemon-reload: %w", err)
			}

			if !noEnable {
				fmt.Printf("Enabling and starting %s...\n", serviceName)
				if err := runSystemctl("enable", serviceName); err != nil {
					return fmt.Errorf("systemctl enable: %w", err)
				}
				if err := runSystemctl("restart", serviceName); err != nil {
					return fmt.Errorf("systemctl start: %w", err)
				}
			}

			fmt.Printf("\nService installed: %s\n", unitPath)
			fmt.Printf("  Status : systemctl status %s\n", serviceName)
			fmt.Printf("  Logs   : journalctl -u %s -f\n", serviceName)
			fmt.Printf("  Stop   : sudo systemctl stop %s\n", serviceName)
			fmt.Printf("  Disable: sudo p2pvpn daemon autostart --remove --name %s\n", serviceName)
			return nil
		},
	}
	cmd.Flags().StringVar(&serviceName, "name", "p2pvpn", "systemd service name")
	cmd.Flags().StringVar(&binPath, "bin", "", "override the p2pvpn binary path (default: auto-detect)")
	cmd.Flags().BoolVar(&noEnable, "no-enable", false, "write the unit file but do not enable/start the service")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the installed service instead of installing")
	return cmd
}

// generateSystemdUnit returns a complete systemd .service unit string.
func generateSystemdUnit(name, binPath, confPath string) string {
	return fmt.Sprintf(`[Unit]
Description=p2pvpn mesh VPN daemon (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s daemon start --config %s
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=no
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
`, name, binPath, confPath)
}

// runSystemctl runs a systemctl command, returning any error.
func runSystemctl(verb, unit string) error {
	var cmd *exec.Cmd
	if unit == "" {
		cmd = exec.Command("systemctl", verb)
	} else {
		cmd = exec.Command("systemctl", verb, unit+".service")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ─── status ───────────────────────────────────────────────────────────────────

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the status of the running daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := ipcclient.New(flagSocket)
			data := c.MustCall("status", nil)
			if data == nil {
				return nil
			}
			var s struct {
				PeerID     string `json:"peer_id"`
				AssignedIP string `json:"assigned_ip"`
				TUNName    string `json:"tun_name"`
				NetworkID  string `json:"network_id"`
			}
			_ = json.Unmarshal(data, &s)
			fmt.Printf("Daemon status:\n")
			fmt.Printf("  Peer ID     : %s\n", s.PeerID)
			fmt.Printf("  Virtual IP  : %s\n", s.AssignedIP)
			fmt.Printf("  TUN device  : %s\n", s.TUNName)
			fmt.Printf("  Network ID  : %s\n", s.NetworkID)
			return nil
		},
	}
}

// ─── peers ────────────────────────────────────────────────────────────────────

func peersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peers",
		Short: "Manage and inspect connected peers",
	}
	cmd.AddCommand(peersListCmd())
	return cmd
}

func peersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all connected peers and their virtual IPs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := ipcclient.New(flagSocket)
			data := c.MustCall("peers", nil)
			if data == nil {
				return nil
			}
			var peers []struct {
				PeerID string `json:"peer_id"`
				IP     string `json:"ip"`
			}
			if err := json.Unmarshal(data, &peers); err != nil {
				return err
			}
			if len(peers) == 0 {
				fmt.Println("No peers connected.")
				return nil
			}
			fmt.Printf("%-55s  %s\n", "PEER ID", "VIRTUAL IP")
			fmt.Printf("%-55s  %s\n", "-------", "----------")
			for _, p := range peers {
				fmt.Printf("%-55s  %s\n", p.PeerID, p.IP)
			}
			return nil
		},
	}
}

// ─── config ───────────────────────────────────────────────────────────────────

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Get or set the distributed network configuration",
	}
	cmd.AddCommand(configGetCmd(), configSetCmd())
	return cmd
}

func configGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Print the current network config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := ipcclient.New(flagSocket)
			data := c.MustCall("config.get", nil)
			if data == nil {
				return nil
			}
			fmt.Println(string(data))
			return nil
		},
	}
}

func configSetCmd() *cobra.Command {
	var (
		ipRange        string
		holdDuration   time.Duration
		allowedPorts   []int
		maxPeers       int
		whitelistMode  bool
	)

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Update network config fields (requires authority private key in daemon)",
		Long: `Pushes a signed config update to the network.  The daemon must have been
started with --network-priv.  Changes are gossiped to all peers who
independently validate the signature before applying.

Only non-zero / explicitly set flags are included in the update.

Examples:
  p2pvpn config set --max-peers 20
  p2pvpn config set --whitelist-mode
  p2pvpn config set --allowed-ports 22,80,443`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			patch := make(map[string]interface{})
			if cmd.Flags().Changed("ip-range") {
				patch["ip-range"] = ipRange
			}
			if cmd.Flags().Changed("hold-duration") {
				patch["ip-hold-duration"] = holdDuration
			}
			if cmd.Flags().Changed("allowed-ports") {
				patch["allowed-ports"] = allowedPorts
			}
			if cmd.Flags().Changed("max-peers") {
				patch["max-peers"] = maxPeers
			}
			if cmd.Flags().Changed("whitelist-mode") {
				patch["whitelist-mode"] = whitelistMode
			}
			if len(patch) == 0 {
				return fmt.Errorf("no config fields specified; use --help for options")
			}
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("config.set", patch)
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Println("Config updated and gossiped to network.")
			return nil
		},
	}
	cmd.Flags().StringVar(&ipRange, "ip-range", "", "new CIDR block (e.g. 10.42.0.0/24)")
	cmd.Flags().DurationVar(&holdDuration, "hold-duration", 0, "IP hold time on disconnect (e.g. 10m)")
	cmd.Flags().IntSliceVar(&allowedPorts, "allowed-ports", nil, "comma-separated allowed ports (e.g. 22,80,443)")
	cmd.Flags().IntVar(&maxPeers, "max-peers", 0, "maximum concurrent peers (0 = unlimited)")
	cmd.Flags().BoolVar(&whitelistMode, "whitelist-mode", false, "enable/disable whitelist quarantine mode")
	return cmd
}

// ─── delegate ─────────────────────────────────────────────────────────────────

func delegateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delegate",
		Short: "Manage delegated config-signing authority",
		Long: `Grant or revoke the ability for another peer to push signed config updates.

Delegation records are signed by the network private key and gossiped to all
peers.  Every peer independently validates the delegation chain.`,
	}
	cmd.AddCommand(delegateAddCmd(), delegateRemoveCmd())
	return cmd
}

func delegateAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <peer-pubkey>",
		Short: "Grant config-signing authority to a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("delegate.add", map[string]string{"pub_key": args[0]})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Printf("Delegated config authority to peer %s\n", args[0][:16]+"...")
			return nil
		},
	}
}

func delegateRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <peer-pubkey>",
		Short: "Revoke config-signing authority from a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("delegate.remove", map[string]string{"pub_key": args[0]})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Printf("Revoked config authority from peer %s\n", args[0][:16]+"...")
			return nil
		},
	}
}

// ─── whitelist ────────────────────────────────────────────────────────────────

func whitelistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whitelist",
		Short: "Manage the peer whitelist (whitelist mode only)",
		Long: `When whitelist mode is enabled, newly connected peers are quarantined until
their peer ID is explicitly added to the allowed-peers list.  Only the network
private key holder (or a delegated peer) can manage this list.`,
	}
	cmd.AddCommand(whitelistAddCmd(), whitelistRemoveCmd(), whitelistListCmd())
	return cmd
}

func whitelistAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <peer-id>",
		Short: "Add a peer ID to the allowed list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("whitelist.add", map[string]string{"peer_id": args[0]})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Printf("Added %s to whitelist.\n", args[0])
			return nil
		},
	}
}

func whitelistRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <peer-id>",
		Short: "Remove a peer ID from the allowed list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := ipcclient.New(flagSocket)
			resp, err := c.Call("whitelist.remove", map[string]string{"peer_id": args[0]})
			if err != nil {
				return err
			}
			if !resp.OK {
				return fmt.Errorf("daemon error: %s", resp.Error)
			}
			fmt.Printf("Removed %s from whitelist.\n", args[0])
			return nil
		},
	}
}

func whitelistListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the current whitelist from network config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := ipcclient.New(flagSocket)
			data := c.MustCall("config.get", nil)
			if data == nil {
				return nil
			}
			var cfg struct {
				WhitelistMode  bool     `json:"whitelist-mode"`
				AllowedPeerIDs []string `json:"allowed-peers"`
			}
			if err := json.Unmarshal(data, &cfg); err != nil {
				return err
			}
			if !cfg.WhitelistMode {
				fmt.Println("Whitelist mode is disabled.")
				return nil
			}
			if len(cfg.AllowedPeerIDs) == 0 {
				fmt.Println("Whitelist is empty (all non-authority peers are quarantined).")
				return nil
			}
			fmt.Printf("Allowed peers (%d):\n", len(cfg.AllowedPeerIDs))
			for _, id := range cfg.AllowedPeerIDs {
				fmt.Printf("  %s\n", id)
			}
			return nil
		},
	}
}
