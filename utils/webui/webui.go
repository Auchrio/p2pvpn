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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "embed"

	"p2pvpn/utils/config"
)

//go:embed ui.html
var uiHTML []byte

// PeerLookup returns the virtual IP of a given peer ID, or nil.
type PeerLookup func(peerID string) net.IP

// PeersSnapshot returns a map of peerID → virtualIP for all connected peers.
type PeersSnapshot func() map[string]net.IP

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

	cfgNode     *config.Node
	networkPriv ed25519.PrivateKey // nil on non-authority peers
	networkPub  ed25519.PublicKey
	getStatus   func() StatusInfo
	getPeers    PeersSnapshot
	onConfig    ConfigUpdateFn
	onDelegate  DelegateFn

	mu       sync.Mutex
	sessions map[string]time.Time // token → expiry

	srv *http.Server
}

// New creates a WebUI server.
//   - bindIP is the .1 address string (e.g. "10.42.0.1")
//   - networkPriv may be nil if this peer is not the network authority
func New(
	bindIP string,
	cfgNode *config.Node,
	networkPub ed25519.PublicKey,
	networkPriv ed25519.PrivateKey,
	getStatus func() StatusInfo,
	getPeers PeersSnapshot,
	onConfig ConfigUpdateFn,
	onDelegate DelegateFn,
) *Server {
	return &Server{
		bindAddr:    net.JoinHostPort(bindIP, "80"),
		cfgNode:     cfgNode,
		networkPriv: networkPriv,
		networkPub:  networkPub,
		getStatus:   getStatus,
		getPeers:    getPeers,
		onConfig:    onConfig,
		onDelegate:  onDelegate,
		sessions:    make(map[string]time.Time),
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
	mux.HandleFunc("/api/delegate/add", s.handleDelegateAdd)
	mux.HandleFunc("/api/delegate/remove", s.handleDelegateRemove)

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
		PeerID string `json:"peer_id"`
		IP     string `json:"ip"`
	}
	out := make([]entry, 0, len(peers))
	for id, ip := range peers {
		out = append(out, entry{PeerID: id, IP: ip.String()})
	}
	writeJSON(w, out)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"can_edit": s.isEditor(r),
	})
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

	ok, err := s.verifyPrivKey(body.PrivKey)
	if err != nil || !ok {
		reason := "invalid private key"
		if err != nil {
			reason = err.Error()
		}
		writeJSON(w, map[string]interface{}{"ok": false, "can_edit": false, "error": reason})
		return
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
	if s.networkPriv != nil {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if ip != nil && (ip.IsLoopback() || s.isLocalVPNAddr(ip)) {
			return true
		}
	}

	// 3. Delegated peer: source IP in the peer map, whose pubkey is delegated.
	if s.isDelegatedPeer(r) {
		return true
	}

	return false
}

// isLocalVPNAddr returns true if ip is the daemon's own virtual interface address.
func (s *Server) isLocalVPNAddr(ip net.IP) bool {
	st := s.getStatus()
	localIP := net.ParseIP(st.AssignedIP)
	return localIP != nil && localIP.Equal(ip)
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

// verifyPrivKey checks that the supplied hex-encoded private key matches the
// network's public key. This is purely local — the key never leaves this node.
func (s *Server) verifyPrivKey(hexKey string) (bool, error) {
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
		return false, fmt.Errorf("invalid hex: key must be a 128-character hex string")
	}
	if len(raw) != ed25519.PrivateKeySize {
		return false, fmt.Errorf("wrong key length (%d bytes, expected 64): make sure you're using the private key, not the public key", len(raw))
	}
	priv := ed25519.PrivateKey(raw)
	derived := priv.Public().(ed25519.PublicKey)
	return derived.Equal(s.networkPub), nil
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


