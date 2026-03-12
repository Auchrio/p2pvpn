// Package webui serves the browser-based configuration editor.
//
// The HTTP server binds exclusively to the virtual network's .1 address
// (e.g. 10.42.0.1:80), so it is only reachable from within the VPN —
// never from the public internet.
//
// Authorization tiers:
//   - Any VPN peer can VIEW the current config (read-only by default).
//   - A peer whose daemon loaded the network private key is auto-authorized
//     as an editor when their virtual IP matches the daemon's own IP.
//   - Any peer (including non-authority nodes) can unlock editor mode by
//     submitting the correct private key via the in-browser Unlock dialog.
//     This issues a short-lived session token (cookie) without sending the
//     key to any other machine.
//   - Peers that have been granted a delegation record are also auto-
//     authorized as editors (their virtual IP is matched against the peer map
//     and their public key against the delegation list).
package webui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "embed"

	"p2pvpn/utils/config"
	"p2pvpn/utils/netconf"
	"p2pvpn/utils/store"
	"p2pvpn/utils/vlog"
)

//go:embed ui.html
var uiHTML []byte

// PeerLookup returns the virtual IP of a given peer ID, or nil.
type PeerLookup func(peerID string) net.IP

// PeersSnapshot returns a map of peerID → virtualIP for all connected peers.
type PeersSnapshot func() map[string]net.IP

// QuarantinedSnapshot returns the list of currently quarantined peer IDs.
type QuarantinedSnapshot func() []string

// ReassignIPFn reassigns a peer's virtual IP. Returns the new IP or error.
type ReassignIPFn func(peerID, newIP string) (string, error)

// StatusInfo is the data returned by /api/status.
type StatusInfo struct {
	PeerID     string `json:"peer_id"`
	AssignedIP string `json:"assigned_ip"`
	TUNName    string `json:"tun_name"`
	NetworkID  string `json:"network_id"`
}

// ConfigUpdateFn applies and gossips a config patch. Called on POST /api/config
// and on whitelist/delegate mutations.
type ConfigUpdateFn func(patch *config.Network) error

// DelegateFn adds or revokes a delegation.
type DelegateFn func(pubKeyHex string, revoke bool) error

// Server is the WebUI HTTP server.
type Server struct {
	bindAddr string // e.g. "10.42.0.1:80"

	cfgNode        *config.Node
	networkPriv    ed25519.PrivateKey // nil on non-authority peers; may be set at runtime via unlock
	networkPub     ed25519.PublicKey
	privMu         sync.RWMutex       // guards networkPriv (may be updated at runtime)
	getStatus      func() StatusInfo
	getPeers       PeersSnapshot
	getQuarantined QuarantinedSnapshot
	onReassignIP   ReassignIPFn
	onConfig       ConfigUpdateFn
	onDelegate     DelegateFn

	// OnPrivKeyUnlocked is called when a user successfully submits the
	// network private key via the unlock dialog.  The daemon registers
	// this callback to store the key for signing config updates.
	OnPrivKeyUnlocked func(ed25519.PrivateKey)

	// OnDaemonRestart is called when the user requests a daemon restart
	// via the WebUI.  The daemon registers this to cancel its context.
	OnDaemonRestart func()

	// OnChangeSelfIP is called when the user requests to change their own
	// virtual IP via the WebUI. The new IP is saved to config, gossiped, and
	// the daemon is restarted to apply the change.
	OnChangeSelfIP func(newIP string) error

	store    *store.Store // set by AddNetworkManagementRoutes
	mu       sync.Mutex
	sessions map[string]time.Time // token → expiry

	srv *http.Server
}

// New creates a WebUI server.
//   - bindIP is the .1 address string (e.g. "10.42.0.1")
//   - networkPriv may be nil if this peer is not the network authority
//   - st may be nil if network management routes are not needed
func New(
	bindIP string,
	cfgNode *config.Node,
	networkPub ed25519.PublicKey,
	networkPriv ed25519.PrivateKey,
	getStatus func() StatusInfo,
	getPeers PeersSnapshot,
	getQuarantined QuarantinedSnapshot,
	onReassignIP ReassignIPFn,
	onConfig ConfigUpdateFn,
	onDelegate DelegateFn,
	st *store.Store,
) *Server {
	return &Server{
		bindAddr:       net.JoinHostPort(bindIP, "80"),
		cfgNode:        cfgNode,
		networkPriv:    networkPriv,
		networkPub:     networkPub,
		getStatus:      getStatus,
		getPeers:       getPeers,
		getQuarantined: getQuarantined,
		onReassignIP:   onReassignIP,
		onConfig:       onConfig,
		onDelegate:     onDelegate,
		store:          st,
		sessions:       make(map[string]time.Time),
	}
}

// Start runs the HTTP server until ctx is cancelled.
func (s *Server) Start(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/peers", s.handlePeers)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/auth", s.handleAuth)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/whitelist/add", s.handleWhitelistAdd)
	mux.HandleFunc("/api/whitelist/remove", s.handleWhitelistRemove)
	mux.HandleFunc("/api/peers/reassign", s.handleReassignIP)
	mux.HandleFunc("/api/selfip", s.handleChangeSelfIP)
	mux.HandleFunc("/api/delegate/add", s.handleDelegateAdd)
	mux.HandleFunc("/api/delegate/remove", s.handleDelegateRemove)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/network-priv", s.handleNetworkPriv)
	mux.HandleFunc("/api/daemon/restart", s.handleDaemonRestart)
	// Register network management routes if a store is attached.
	if s.store != nil {
		mux.HandleFunc("/api/network/setup", s.handleNetworkSetup)
		mux.HandleFunc("/api/network/remove", s.handleNetworkRemove)
	}
	s.srv = &http.Server{
		Addr:         s.bindAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()

	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("[webui] error: %v\n", err)
	}
}

// ─── handlers ────────────────────────────────────────────────────────────────

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(uiHTML)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.getStatus())
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.cfgNode.Get())

	case http.MethodPost:
		if !s.isEditor(r) {
			jsonErr(w, "not authorized", http.StatusForbidden)
			return
		}
		var patch config.Network
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.onConfig(&patch); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := s.getPeers()
	type entry struct {
		PeerID      string `json:"peer_id"`
		IP          string `json:"ip"`
		Quarantined bool   `json:"quarantined"`
	}
	out := make([]entry, 0, len(peers))
	for id, ip := range peers {
		out = append(out, entry{PeerID: id, IP: ip.String(), Quarantined: false})
	}
	// Include quarantined peers (no IP assigned yet).
	if s.getQuarantined != nil {
		for _, id := range s.getQuarantined() {
			out = append(out, entry{PeerID: id, IP: "", Quarantined: true})
		}
	}
	writeJSON(w, out)
}

func (s *Server) handleReassignIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isEditor(r) {
		jsonErr(w, "not authorized", http.StatusForbidden)
		return
	}
	if s.onReassignIP == nil {
		jsonErr(w, "IP reassignment not supported", http.StatusNotImplemented)
		return
	}
	var body struct {
		PeerID string `json:"peer_id"`
		NewIP  string `json:"new_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.PeerID == "" {
		jsonErr(w, "peer_id is required", http.StatusBadRequest)
		return
	}
	newIP, err := s.onReassignIP(body.PeerID, body.NewIP)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "new_ip": newIP})
}

func (s *Server) handleChangeSelfIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isEditor(r) {
		jsonErr(w, "not authorized", http.StatusForbidden)
		return
	}
	if s.OnChangeSelfIP == nil {
		jsonErr(w, "self IP change not supported", http.StatusNotImplemented)
		return
	}
	var body struct {
		NewIP string `json:"new_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.NewIP == "" {
		jsonErr(w, "new_ip is required", http.StatusBadRequest)
		return
	}
	if err := s.OnChangeSelfIP(body.NewIP); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "new_ip": body.NewIP, "restarting": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"can_edit": s.isEditor(r),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	lines := vlog.RecentLines(200)
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, lines)
}

func (s *Server) handleNetworkPriv(w http.ResponseWriter, r *http.Request) {
	if !s.isEditor(r) {
		jsonErr(w, "not authorized", http.StatusForbidden)
		return
	}
	s.privMu.RLock()
	priv := s.networkPriv
	s.privMu.RUnlock()
	if priv == nil {
		writeJSON(w, map[string]interface{}{"ok": true, "priv_key": ""})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "priv_key": hex.EncodeToString(priv)})
}

func (s *Server) handleDaemonRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.OnDaemonRestart == nil {
		jsonErr(w, "restart not available", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "message": "Daemon restarting…"})
	go func() {
		time.Sleep(500 * time.Millisecond) // let HTTP response flush
		s.OnDaemonRestart()
	}()
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PrivKey string `json:"priv_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	privKey, err := s.verifyAndDecodePrivKey(body.PrivKey)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "can_edit": false, "error": err.Error()})
		return
	}

	// Store the verified private key so the daemon can sign config updates
	// and so future requests from this IP are auto-elevated.
	s.privMu.Lock()
	s.networkPriv = privKey
	s.privMu.Unlock()
	vlog.Logf("webui", "private key unlocked via WebUI — authority mode active")

	if s.OnPrivKeyUnlocked != nil {
		s.OnPrivKeyUnlocked(privKey)
	}

	token := s.issueSession()
	http.SetCookie(w, &http.Cookie{
		Name:     "p2pvpn_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400, // 24 h
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, map[string]interface{}{"ok": true, "can_edit": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("p2pvpn_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "p2pvpn_session", MaxAge: -1, Path: "/"})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if !s.isEditor(r) { jsonErr(w, "not authorized", 403); return }
	var body struct{ PeerID string `json:"peer_id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil { jsonErr(w, err.Error(), 400); return }

	cfg := s.cfgNode.Get()
	for _, id := range cfg.AllowedPeerIDs {
		if id == body.PeerID { writeJSON(w, map[string]bool{"ok": true}); return }
	}
	cfg.AllowedPeerIDs = append(cfg.AllowedPeerIDs, body.PeerID)
	if err := s.onConfig(cfg); err != nil { jsonErr(w, err.Error(), 500); return }
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if !s.isEditor(r) { jsonErr(w, "not authorized", 403); return }
	var body struct{ PeerID string `json:"peer_id"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil { jsonErr(w, err.Error(), 400); return }

	cfg := s.cfgNode.Get()
	kept := cfg.AllowedPeerIDs[:0]
	for _, id := range cfg.AllowedPeerIDs {
		if id != body.PeerID { kept = append(kept, id) }
	}
	cfg.AllowedPeerIDs = kept
	if err := s.onConfig(cfg); err != nil { jsonErr(w, err.Error(), 500); return }
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleDelegateAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if !s.isEditor(r) { jsonErr(w, "not authorized", 403); return }
	var body struct{ PubKey string `json:"pub_key"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil { jsonErr(w, err.Error(), 400); return }
	if err := s.onDelegate(body.PubKey, false); err != nil { jsonErr(w, err.Error(), 500); return }
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleDelegateRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if !s.isEditor(r) { jsonErr(w, "not authorized", 403); return }
	var body struct{ PubKey string `json:"pub_key"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil { jsonErr(w, err.Error(), 400); return }
	if err := s.onDelegate(body.PubKey, true); err != nil { jsonErr(w, err.Error(), 500); return }
	writeJSON(w, map[string]bool{"ok": true})
}

// ─── authorization ────────────────────────────────────────────────────────────

// isEditor returns true when the HTTP request is authorised to edit config:
//  1. The daemon has the network private key AND the request comes from the
//     daemon's own virtual IP (i.e. local loopback through TUN).
//  2. The request carries a valid session cookie issued by /api/auth.
//  3. The request source IP maps to a peer whose public key is a delegated admin.
func (s *Server) isEditor(r *http.Request) bool {
	// 1. Valid session cookie.
	if c, err := r.Cookie("p2pvpn_session"); err == nil {
		s.mu.Lock()
		exp, ok := s.sessions[c.Value]
		s.mu.Unlock()
		if ok && time.Now().Before(exp) {
			return true
		}
	}

	// 2. Auto-authorize if daemon has the private key and the request comes
	//    from a local address (loopback or the daemon's own virtual IP).
	s.privMu.RLock()
	hasPriv := s.networkPriv != nil
	s.privMu.RUnlock()
	if hasPriv {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if ip != nil && (ip.IsLoopback() || s.isLocalVPNAddr(ip)) {
			return true
		}
		vlog.Logf("webui", "auto-elevate: priv key present but remote %s is not local (assigned=%s bind=%s)",
			r.RemoteAddr, s.getStatus().AssignedIP, s.bindAddr)
	}

	// 3. Delegated peer: source IP in the peer map, whose pubkey is delegated.
	if s.isDelegatedPeer(r) {
		return true
	}

	return false
}

// isLocalVPNAddr returns true if ip is the daemon's own virtual interface address,
// the .1 config address that the WebUI is bound to, or any IP address assigned
// to a local network interface (covering LAN access from the same machine).
func (s *Server) isLocalVPNAddr(ip net.IP) bool {
	st := s.getStatus()
	localIP := net.ParseIP(st.AssignedIP)
	if localIP != nil && localIP.Equal(ip) {
		return true
	}
	// Also match the bind address (.1 config IP) — on Linux the kernel may
	// use the destination IP as the source IP for connections to a local
	// interface, so RemoteAddr can be the .1 address rather than the
	// peer's assigned IP.
	bindHost, _, _ := net.SplitHostPort(s.bindAddr)
	bindIP := net.ParseIP(bindHost)
	if bindIP != nil && bindIP.Equal(ip) {
		return true
	}
	// Check all local interface addresses — the user may be accessing the
	// WebUI via a LAN IP (e.g. 192.168.x.x) from the same machine.
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// isDelegatedPeer checks whether the peer whose virtual IP is the request source
// has been granted a delegation record.
func (s *Server) isDelegatedPeer(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	srcIP := net.ParseIP(host)
	if srcIP == nil {
		return false
	}
	peers := s.getPeers()
	for peerID, vip := range peers {
		if !vip.Equal(srcIP) {
			continue
		}
		// Try to get the peer's public key hex from its ID.
		pubHex, err := peerIDToPubKeyHex(peerID)
		if err != nil {
			continue
		}
		if s.cfgNode.IsDelegated(pubHex) {
			return true
		}
	}
	return false
}

// verifyAndDecodePrivKey verifies the supplied hex-encoded private key matches
// the network's public key and returns the decoded key. Purely local — the key
// never leaves this node.
func (s *Server) verifyAndDecodePrivKey(hexKey string) (ed25519.PrivateKey, error) {
	// Strip any whitespace (newlines, spaces) that may have been introduced when
	// copying a long key from a terminal that wrapped the line.
	hexKey = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, hexKey)
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: key must be a 128-character hex string")
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("wrong key length (%d bytes, expected 64): make sure you're using the private key, not the public key", len(raw))
	}
	priv := ed25519.PrivateKey(raw)
	derived := priv.Public().(ed25519.PublicKey)
	if !derived.Equal(s.networkPub) {
		return nil, fmt.Errorf("private key does not match this network's public key")
	}
	return priv, nil
}

// issueSession creates a random session token valid for 24 hours.
func (s *Server) issueSession() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(24 * time.Hour)
	// Prune expired sessions while we hold the lock.
	now := time.Now()
	for t, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, t)
		}
	}
	s.mu.Unlock()
	return token
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": msg})
}

// peerIDToPubKeyHex extracts the hex-encoded public key from a libp2p peer ID.
// libp2p embeds the public key in the peer ID for Ed25519 keys.
func peerIDToPubKeyHex(peerIDStr string) (string, error) {
	// Import is done via the auth package's dependency on libp2p, but to avoid
	// a circular import we perform the extraction using a local helper that
	// mirrors what p2p.PeerPubKeyHex does.  The webui package intentionally does
	// not import the p2p package directly to keep the dependency graph clean.
	// If the public key cannot be extracted (e.g. identity hash), return an error.
	pubKeyExtractor, ok := globalPeerPubKeyExtractor(peerIDStr)
	if !ok {
		return "", fmt.Errorf("cannot extract public key from peer ID %s", peerIDStr)
	}
	return pubKeyExtractor, nil
}

// globalPeerPubKeyExtractor is set by the daemon during startup, providing a
// closure that can extract hex public keys from peer ID strings without
// importing the p2p package here.
var globalPeerPubKeyExtractor = func(string) (string, bool) { return "", false }

// SetPeerPubKeyExtractor registers the peer-ID-to-pubkey function.
// Called once at daemon startup.
func SetPeerPubKeyExtractor(fn func(string) (string, bool)) {
	globalPeerPubKeyExtractor = fn
}

// ─── Setup Mode Server ──────────────────────────────────────────────────────

// SetupServer serves the WebUI in "setup mode" — a minimal HTTP server on
// 0.0.0.0 (port 8080 by default, auto-increments if busy) that accepts a
// network config from the user before the full VPN daemon starts.
type SetupServer struct {
	st              *store.Store
	OnSetupComplete func() // called after config is persisted
	BoundAddr       string // actual address the server bound to (set after ListenAndServe starts)
}

// NewSetupServer creates a setup-mode HTTP server.
func NewSetupServer(st *store.Store) *SetupServer {
	return &SetupServer{st: st}
}

// ListenAndServe starts the setup HTTP server.  It blocks until ctx is
// cancelled or an unrecoverable error occurs.
func (ss *SetupServer) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(uiHTML)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"setup_mode": true,
			"peer_id":    "",
			"assigned_ip": "",
			"tun_name":   "",
			"network_id": "",
		})
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		// In setup mode everyone is an editor.
		writeJSON(w, map[string]interface{}{"can_edit": true})
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{})
	})
	mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []interface{}{})
	})
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		lines := vlog.RecentLines(200)
		if lines == nil {
			lines = []string{}
		}
		writeJSON(w, lines)
	})
	mux.HandleFunc("/api/network/setup", ss.handleSetup)
	mux.HandleFunc("/api/network/create", ss.handleCreate)

	// Try ports 8080-8090 to find an available one.
	var ln net.Listener
	var err error
	for port := 8080; port <= 8090; port++ {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			ss.BoundAddr = addr
			break
		}
	}
	if ln == nil {
		// All preferred ports busy — let the OS pick one.
		ln, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("setup server: no available port: %w", err)
		}
		ss.BoundAddr = ln.Addr().String()
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return ctx.Err()
}

// handleSetup accepts either:
//   - JSON body: {"network_pub":"<hex>", "network_priv":"<hex>", "cidr":"..."}
//   - Multipart form: file field "config" containing a .conf file
func (ss *SetupServer) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ct := r.Header.Get("Content-Type")

	var nc netconf.NetConf

	if strings.HasPrefix(ct, "multipart/") {
		// File upload.
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			jsonErr(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		f, _, err := r.FormFile("config")
		if err != nil {
			jsonErr(w, "missing 'config' file field", http.StatusBadRequest)
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			jsonErr(w, "reading uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Write to a temp file so we can use netconf.Load.
		tmp := ss.st.SavedConfPath() + ".upload"
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			jsonErr(w, "saving upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmp)
		loaded, err := netconf.Load(tmp)
		if err != nil {
			jsonErr(w, "invalid config file: "+err.Error(), http.StatusBadRequest)
			return
		}
		nc = *loaded
	} else {
		// JSON body.
		var body struct {
			NetworkPub  string `json:"network_pub"`
			NetworkPriv string `json:"network_priv"`
			CIDR        string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if body.NetworkPub == "" {
			jsonErr(w, "network_pub is required", http.StatusBadRequest)
			return
		}
		nc.NetworkPubKey = body.NetworkPub
		nc.NetworkPrivKey = body.NetworkPriv
		nc.CIDR = body.CIDR
	}

	if nc.CIDR == "" {
		nc.CIDR = "10.42.0.0/24"
	}

	// Persist to saved.conf.
	if err := nc.Save(ss.st.SavedConfPath()); err != nil {
		jsonErr(w, "saving config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vlog.Logf("setup", "saved network config to %s", ss.st.SavedConfPath())

	writeJSON(w, map[string]bool{"ok": true})

	// Signal the setup is done (daemon will restart).
	if ss.OnSetupComplete != nil {
		go func() {
			time.Sleep(500 * time.Millisecond) // let the HTTP response flush
			ss.OnSetupComplete()
		}()
	}
}

// handleCreate generates a new Ed25519 network keypair, saves the resulting
// config to saved.conf, and signals that setup is complete.
func (ss *SetupServer) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		CIDR string `json:"cidr"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // optional body
	if body.CIDR == "" {
		body.CIDR = "10.42.0.0/24"
	}

	// Generate Ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		jsonErr(w, "generating keypair: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nc := netconf.NetConf{
		NetworkPubKey:  hex.EncodeToString(pub),
		NetworkPrivKey: hex.EncodeToString(priv),
		CIDR:           body.CIDR,
	}

	if err := nc.Save(ss.st.SavedConfPath()); err != nil {
		jsonErr(w, "saving config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vlog.Logf("setup", "created new network %s", nc.NetworkPubKey)

	writeJSON(w, map[string]interface{}{
		"ok":          true,
		"network_pub": nc.NetworkPubKey,
	})

	if ss.OnSetupComplete != nil {
		go func() {
			time.Sleep(500 * time.Millisecond)
			ss.OnSetupComplete()
		}()
	}
}

// ─── Network management endpoints (for running daemon) ──────────────────────

func (s *Server) handleNetworkSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isEditor(r) {
		jsonErr(w, "not authorized", http.StatusForbidden)
		return
	}

	ct := r.Header.Get("Content-Type")
	var nc netconf.NetConf

	if strings.HasPrefix(ct, "multipart/") {
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			jsonErr(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		f, _, err := r.FormFile("config")
		if err != nil {
			jsonErr(w, "missing 'config' file field", http.StatusBadRequest)
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			jsonErr(w, "reading uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		tmp := s.store.SavedConfPath() + ".upload"
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			jsonErr(w, "saving upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmp)
		loaded, err := netconf.Load(tmp)
		if err != nil {
			jsonErr(w, "invalid config file: "+err.Error(), http.StatusBadRequest)
			return
		}
		nc = *loaded
	} else {
		var body struct {
			NetworkPub  string `json:"network_pub"`
			NetworkPriv string `json:"network_priv"`
			CIDR        string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if body.NetworkPub == "" {
			jsonErr(w, "network_pub is required", http.StatusBadRequest)
			return
		}
		nc.NetworkPubKey = body.NetworkPub
		nc.NetworkPrivKey = body.NetworkPriv
		nc.CIDR = body.CIDR
	}

	if nc.CIDR == "" {
		nc.CIDR = "10.42.0.0/24"
	}

	if err := nc.Save(s.store.SavedConfPath()); err != nil {
		jsonErr(w, "saving config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "message": "Config saved. Restart daemon to apply."})
}

func (s *Server) handleNetworkRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.isEditor(r) {
		jsonErr(w, "not authorized", http.StatusForbidden)
		return
	}
	if s.store == nil {
		jsonErr(w, "store not available", http.StatusInternalServerError)
		return
	}
	if err := s.store.RemoveSavedConf(); err != nil {
		jsonErr(w, "removing config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "message": "Network config removed. Restart daemon to enter setup mode."})
}


