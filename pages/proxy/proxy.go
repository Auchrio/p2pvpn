// Package proxy implements the /p2pvpn-proxy/1.0.0 libp2p stream protocol.
//
// This protocol allows browser-based peers (connected via WebTransport) to
// reach TCP services running on VPN peers without requiring a kernel TUN
// device. The daemon peer holding live TUN routes acts as the TCP exit node.
//
// Frame format (identical to the VPN wire format):
//
//	2-byte big-endian length prefix + JSON payload
//
// Message types (browser → daemon):
//
//	CONNECT   { type, id, host, port }
//	DATA      { type, id, b64 }          base64-encoded TCP bytes
//	CLOSE     { type, id }
//
// Message types (daemon → browser):
//
//	CONNECTED { type, id }
//	ERROR     { type, id, reason }
//	DATA      { type, id, b64 }
//	CLOSE     { type, id }
//
// Multiple connections are multiplexed over a single libp2p stream using the
// "id" field. The browser opens one /p2pvpn-proxy/1.0.0 stream and reuses it
// for all outbound connections.
package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	lnetwork "github.com/libp2p/go-libp2p/core/network"

	"p2pvpn/utils/config"
	"p2pvpn/utils/vlog"
	"p2pvpn/utils/whitelist"
)

// Protocol is the libp2p stream protocol ID for browser TCP-proxy connections.
const Protocol = "/p2pvpn-proxy/1.0.0"

// Frame is a single proxy protocol message.
type Frame struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	B64    string `json:"b64,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Proxy handles incoming /p2pvpn-proxy/1.0.0 streams.
type Proxy struct {
	cfgNode  *config.Node
	enforcer *whitelist.Enforcer
}

// New creates a Proxy handler backed by the given config node and whitelist enforcer.
func New(cfgNode *config.Node, enforcer *whitelist.Enforcer) *Proxy {
	return &Proxy{cfgNode: cfgNode, enforcer: enforcer}
}

// proxyConn wraps a net.Conn with mutex-guarded write and single-close semantics.
type proxyConn struct {
	conn net.Conn
	mu   sync.Mutex
	done bool
}

func (pc *proxyConn) write(data []byte) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if !pc.done {
		_ = pc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, _ = pc.conn.Write(data)
	}
}

// close closes the underlying conn exactly once.  Returns true if this call
// performed the close.
func (pc *proxyConn) close() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.done {
		return false
	}
	pc.done = true
	_ = pc.conn.Close()
	return true
}

// HandleStream is the libp2p stream handler registered for ProxyProtocol.
// It is called by the p2p.Node whenever a remote peer opens a proxy stream.
func (p *Proxy) HandleStream(s lnetwork.Stream) {
	peerID := s.Conn().RemotePeer().String()
	vlog.Logf("proxy", "incoming proxy stream from %s", peerID)

	// Re-check whitelist at stream-open time (defence in depth).
	if !p.enforcer.Allow(peerID) {
		vlog.Logf("proxy", "refusing proxy stream from quarantined peer %s", peerID)
		_ = s.Reset()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	writeCh := make(chan Frame, 256)

	// Per-stream connection table.
	var connsMu sync.Mutex
	conns := make(map[string]*proxyConn)

	closeConn := func(id string, notify bool) {
		connsMu.Lock()
		pc, ok := conns[id]
		if ok {
			delete(conns, id)
		}
		connsMu.Unlock()
		if !ok {
			return
		}
		if pc.close() && notify {
			select {
			case writeCh <- Frame{Type: "CLOSE", ID: id}:
			case <-ctx.Done():
			}
		}
	}

	send := func(f Frame) {
		select {
		case writeCh <- f:
		case <-ctx.Done():
		}
	}

	// Writer goroutine — serialises all outbound frames onto the stream.
	go func() {
		defer cancel()
		for {
			select {
			case f := <-writeCh:
				if err := writeFrame(s, f); err != nil {
					vlog.Logf("proxy", "write error to %s: %v", peerID, err)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Cleanup when the reader loop exits.
	defer func() {
		cancel()
		_ = s.Close()
		connsMu.Lock()
		for id, pc := range conns {
			pc.close()
			delete(conns, id)
		}
		connsMu.Unlock()
		vlog.Logf("proxy", "proxy session from %s ended", peerID)
	}()

	// Reader loop — dispatches incoming frames.
	for {
		var f Frame
		if err := readFrame(s, &f); err != nil {
			if err != io.EOF {
				vlog.Logf("proxy", "read error from %s: %v", peerID, err)
			}
			return
		}

		switch f.Type {

		case "CONNECT":
			// Dial the target in a goroutine so slow connections don't block the loop.
			go func(frame Frame) {
				cfg := p.cfgNode.Get()
				target := net.ParseIP(frame.Host)
				if target == nil {
					send(Frame{Type: "ERROR", ID: frame.ID, Reason: "invalid host address"})
					return
				}
				_, cidr, err := net.ParseCIDR(cfg.IPRange)
				if err != nil || !cidr.Contains(target) {
					send(Frame{
						Type:   "ERROR",
						ID:     frame.ID,
						Reason: fmt.Sprintf("host %s is outside VPN CIDR %s", frame.Host, cfg.IPRange),
					})
					return
				}
				if frame.Port <= 0 || frame.Port > 65535 {
					send(Frame{Type: "ERROR", ID: frame.ID, Reason: "invalid port"})
					return
				}

				dialCtx, dCancel := context.WithTimeout(ctx, 15*time.Second)
				defer dCancel()
				addr := fmt.Sprintf("%s:%d", frame.Host, frame.Port)
				conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
				if dialErr != nil {
					send(Frame{Type: "ERROR", ID: frame.ID, Reason: dialErr.Error()})
					return
				}

				pc := &proxyConn{conn: conn}
				connsMu.Lock()
				conns[frame.ID] = pc
				connsMu.Unlock()

				send(Frame{Type: "CONNECTED", ID: frame.ID})
				vlog.Logf("proxy", "CONNECT %s OK (id=%s, peer=%s)", addr, frame.ID, peerID)

				// Forward data from TCP target → browser frames.
				defer closeConn(frame.ID, true)
				buf := make([]byte, 32*1024)
				for {
					n, readErr := conn.Read(buf)
					if n > 0 {
						b64 := base64.StdEncoding.EncodeToString(buf[:n])
						send(Frame{Type: "DATA", ID: frame.ID, B64: b64})
					}
					if readErr != nil {
						return
					}
				}
			}(f)

		case "DATA":
			if f.B64 == "" {
				continue
			}
			data, err := base64.StdEncoding.DecodeString(f.B64)
			if err != nil {
				vlog.Logf("proxy", "bad base64 data from %s id=%s: %v", peerID, f.ID, err)
				continue
			}
			connsMu.Lock()
			pc, ok := conns[f.ID]
			connsMu.Unlock()
			if ok {
				pc.write(data)
			}

		case "CLOSE":
			closeConn(f.ID, false)
		}
	}
}

// ─── frame codec ─────────────────────────────────────────────────────────────

// writeFrame serialises f as a 2-byte big-endian length prefix + JSON payload.
func writeFrame(w io.Writer, f Frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(data) > 0xFFFF {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}
	hdr := [2]byte{byte(len(data) >> 8), byte(len(data))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readFrame reads a frame from r (2-byte length prefix + JSON payload).
func readFrame(r io.Reader, f *Frame) error {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n == 0 || n > 0xFFFF {
		return fmt.Errorf("invalid frame length: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, f)
}
