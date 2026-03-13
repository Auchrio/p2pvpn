# p2pvpn Web Bridge — Technical Concept

A browser-native client that joins a p2pvpn network as a lightweight peer, requires
no installed software, and provides:

1. **Seamless HTTP proxy** — access web services running on `10.42.x.x` inside the
   VPN directly from a browser tab.
2. **Interactive SSH shell** — a full terminal (xterm.js) connected to any peer on
   the network via an in-protocol SSH relay.
3. **Static delivery** — the entire client is a single `bridge.html` file served from
   a plain HTTP server (or even opened from disk). No bundler, no build step, no CDN
   dependency at runtime.

---

## 1. What Already Exists (No Changes Needed)

Before listing new work, it is worth noting what the daemon already provides for free:

| Existing feature | Why it matters for the bridge |
|---|---|
| WebTransport listener on every port (`/ip4/…/udp/%d/quic-v1/webtransport`) in `utils/p2p/p2p.go` line ~210 | Browsers can connect natively without any transport changes to the daemon |
| Ed25519 peer identity stored per-node | Browser generates its own keypair → gets a real libp2p peer ID → can be whitelisted exactly like a daemon peer |
| DHT rendezvous on network public key | Browser runs `js-libp2p` DHT, announces on same topic, discovers peers automatically |
| Whitelist enforcer operates on peer IDs | Browser peer ID is whitelisted via the existing `/api/whitelist/add` WebUI endpoint — no new ACL system needed |
| Length-prefixed framing on `/p2pvpn/1.0.0` streams (2-byte big-endian + payload) | The frame format can be re-used verbatim for the proxy sub-protocol |
| Gossip layer distributes config (CIDR, allowed peers) | Browser can receive the current peer map without a custom API |

---

## 2. The Fundamental Limit and How to Work Around It

### Why raw `/p2pvpn/1.0.0` is not enough for a browser

The current VPN protocol carries **raw IPv4 packets**:

```
handleStream → onPacket → tunIface.Write(rawIPv4Packet)
tunReadLoop  → dstIP lookup → SendPacket(rawIPv4Packet)
```

Browsers have no `TUN` file descriptor. They cannot inject or receive kernel-level IP
packets. Even with a working WebTransport connection, a browser peer cannot
participate in IP-layer routing.

### The solution: a second libp2p protocol

Define a new stream protocol alongside `/p2pvpn/1.0.0`:

```
/p2pvpn-proxy/1.0.0
```

This protocol carries **application-layer TCP proxy frames** (HTTP CONNECT semantics)
instead of raw IP. A daemon peer that accepts this protocol acts as the TUN exit node
on behalf of the browser — it receives a `CONNECT host:port` frame, opens a TCP
connection to `host:port` on the virtual network, and splices the byte streams. The
browser never needs a TUN.

Because the rendezvous and peer identity are shared, the same whitelist enforcement
applies automatically: if the browser peer ID is not in `allowed-peers`, the daemon
will not accept (or open) any stream to it.

---

## 3. New Protocol: `/p2pvpn-proxy/1.0.0`

### Frame format (same 2-byte big-endian length prefix as the VPN protocol)

```
┌─────────────────────────────────────────────────────────┐
│  2 bytes  │  N bytes                                     │
│  length   │  JSON payload                                │
└─────────────────────────────────────────────────────────┘
```

All frames are JSON to keep the browser implementation trivial.

### Request frame (browser → daemon)

```json
{
  "type": "CONNECT",
  "host": "10.42.0.3",
  "port": 80,
  "id":   "req-1"
}
```

`host` must be within the VPN CIDR. The daemon validates this before opening a
connection.

### Response frame (daemon → browser)

```json
{ "type": "CONNECTED", "id": "req-1" }
```

or on failure:

```json
{ "type": "ERROR", "id": "req-1", "reason": "connection refused" }
```

### Data frame (both directions, after CONNECTED)

```json
{ "type": "DATA", "id": "req-1", "b64": "<base64-encoded bytes>" }
```

### Close frame

```json
{ "type": "CLOSE", "id": "req-1" }
```

Multiple connections are **multiplexed** on a single proxy stream using the `id` field.
The browser opens one `/p2pvpn-proxy/1.0.0` stream to its chosen proxy peer and reuses
it for all outbound connections.

---

## 4. Changes Required to the Daemon

### 4.1 `utils/p2p/p2p.go` — Register the proxy protocol handler

```go
// ProxyProtocol is the libp2p stream protocol for browser proxy connections.
const ProxyProtocol = "/p2pvpn-proxy/1.0.0"
```

Register a handler next to the existing VPN handler:

```go
// In New(), after:  h.SetStreamHandler(VPNProtocol, n.handleStream)
h.SetStreamHandler(ProxyProtocol, n.handleProxyStream)
```

Add `proxyHandler ProxyHandler` to the `Node` struct, and a setter
`SetProxyHandler(fn ProxyHandler)` so the daemon can wire it up after construction
(same pattern as `SetPacketHandler`).

```go
type ProxyHandler func(stream network.Stream)
```

`handleProxyStream` simply calls the registered handler, or if none is set, resets the
stream with a "not supported" error. This keeps `p2p.go` agnostic of proxy logic.

### 4.2 New file: `utils/proxy/proxy.go`

Owns the proxy frame codec and the per-connection goroutines. The daemon wires in:

```go
proxyLayer := proxy.New(d.cfgNode, d.wlEnforcer, d.ipMgr)
d.p2pNode.SetProxyHandler(proxyLayer.HandleStream)
```

`proxy.New` takes:
- `cfgNode` — to read the VPN CIDR and reject out-of-range targets
- `wlEnforcer` — to re-check `Allow(peerID)` before each `CONNECT` (defense in depth)
- `ipMgr` — optional; used to resolve peer virtual IPs for human-readable error messages

Core loop inside `proxy.HandleStream`:

```go
func (p *Proxy) HandleStream(s network.Stream) {
    peerID := s.Conn().RemotePeer().String()
    if !p.wlEnforcer.Allow(peerID) {
        _ = s.Reset()
        return
    }
    // read frames in a loop, dispatch CONNECT / DATA / CLOSE per conn ID
}
```

Internal connection table: `map[string]*proxyConn` keyed on frame `id`.

Each `proxyConn` has:
- `net.Conn` — the TCP connection to the VPN target
- write goroutine: reads from `net.Conn`, emits `DATA` frames back to the browser stream
- close goroutine: sends `CLOSE` on EOF or error

### 4.3 `utils/daemon/daemon.go` — Wire up proxy layer

In `daemon.Start()`, after `p2pNode.SetPacketHandler(d.onPacket)`:

```go
proxyLayer := proxy.New(cfgNode, wlEnforcer, ipMgr)
p2pNode.SetProxyHandler(proxyLayer.HandleStream)
```

No other changes to the daemon are needed.

### 4.4 `utils/p2p/p2p.go` — Expose a peer list endpoint for the browser

The browser needs to know which peer to connect to as its proxy exit node. Add a
`ConnectedVPNPeers() []peer.AddrInfo` method that returns the multiaddresses of all
peers that have an active `/p2pvpn/1.0.0` stream. The browser picks any of these as its
proxy peer. The method is trivially implemented using the existing `streams` map.

### 4.5 `utils/webui/webui.go` — New API endpoints

Add two endpoints so the static `bridge.html` can bootstrap:

| Endpoint | Method | Response |
|---|---|---|
| `/api/bridge/config` | GET | `{ "cidr": "10.42.0.0/24", "network_id": "abc...", "peers": [{ "id": "...", "addrs": [...] }] }` |
| `/api/bridge/whitelist-self` | POST `{ "peer_id": "..." }` | Adds the browser's peer ID to the whitelist (editor-only, i.e. requires session cookie or private key) |

The existing `/api/whitelist/add` endpoint already does the second one — expose a
convenience alias that accepts the browser's self-generated peer ID directly.

---

## 5. Browser Client — Architecture

The entire client fits in a single HTML file with inline JavaScript. No build step.
All cryptography and networking is handled by `js-libp2p` loaded from a CDN ESM
import (or bundled inline for fully offline use).

### 5.1 URL scheme

```
https://bridge.example/bridge.html#<networkPubKeyHex>|<userPrivKeyHex>
```

The fragment (`#…`) is **never sent to any server**. The page reads it via
`window.location.hash` and the private key never leaves the browser process.

- `networkPubKeyHex` — 64-char hex Ed25519 public key. Used as the DHT rendezvous
  topic, exactly as in `utils/p2p/p2p.go` (`rendezvous = networkPubKeyHex`).
- `userPrivKeyHex` — optional 128-char hex Ed25519 private key. If supplied and it
  matches the network public key (i.e. it _is_ the network authority key), the user
  is automatically granted editor access on the WebUI. Can also be a separate
  **browser identity key** that the user has pre-shared with a network admin to get
  whitelisted without needing authority access.

### 5.2 Initialisation sequence

```
1. Parse #networkPubKeyHex|userPrivKeyHex from fragment
2. Generate (or load from localStorage) an Ed25519 browser keypair
3. Derive libp2p peer ID from the browser public key
4. Show "Your peer ID: <id> — ask an admin to whitelist you, or scan QR code"
5. Create js-libp2p node:
     - Transport:   @libp2p/webtransport
     - Discovery:   @libp2p/kad-dht (rendezvous = networkPubKeyHex)
     - Bootstrap:   IPFS public bootstrap nodes (same as daemon)
6. Advertise on DHT topic (same topic as daemon peers)
7. Wait for a daemon peer to appear in peer discovery
8. Open /p2pvpn-proxy/1.0.0 stream to the first reachable daemon peer
9. Unlock UI panels (HTTP proxy, SSH terminal)
```

If `userPrivKeyHex` is set and matches the network, after step 8 the browser can
POST to `10.42.0.1:80/api/auth` through the proxy stream with the private key to
auto-elevate to editor (the existing auth flow is unchanged).

### 5.3 HTTP proxy (seamless web access)

The browser installs a **`fetch` interceptor** using a Service Worker:

```js
// sw.js — installed once, persists across page reloads
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  // Intercept requests to any host within the VPN CIDR
  if (isVPNHost(url.hostname)) {
    event.respondWith(proxyFetch(event.request));
  }
});
```

`proxyFetch` does:
1. Send a `CONNECT` frame over the open proxy stream for `host:80` (or whatever port)
2. Await the `CONNECTED` response frame
3. Serialise the HTTP request to bytes and send as `DATA` frames
4. Collect `DATA` frames back and reconstruct the HTTP response
5. Return a `Response` object to the browser

**Result:** The user navigates to `http://10.42.0.3/` in an `<iframe>` inside
`bridge.html`. The Service Worker intercepts the request, tunnels it through the
proxy stream, and returns the page content. To the iframe it looks like a normal HTTP
response with the correct URL and cookies. No browser extension needed.

For hostnames instead of raw IPs, the bridge can expose a simple peer-name resolver:
`<peerShortName>.vpn` resolves to the peer's virtual IP using the gossip-distributed
peer map from `/api/bridge/config`.

### 5.4 SSH terminal (xterm.js + Web Serial/WebSocket hybrid)

SSH over a `/p2pvpn-proxy/1.0.0` CONNECT frame to `targetPeer:22`:

```js
async function openSSH(targetIP) {
  const id = crypto.randomUUID();
  sendFrame({ type: 'CONNECT', host: targetIP, port: 22, id });
  await waitForConnected(id);
  // attach xterm.js, pipe DATA frames bidirectionally
  const term = new Terminal({ cursorBlink: true });
  term.open(document.getElementById('terminal'));
  term.onData(data => sendFrame({ type: 'DATA', id, b64: btoa(data) }));
  onFrame(id, 'DATA', frame => term.write(atob(frame.b64)));
  onFrame(id, 'CLOSE', () => term.writeln('\r\n[connection closed]'));
}
```

The SSH handshake and session encryption are handled entirely by the SSH daemon
running on the target peer — the bridge only carries the raw TCP byte stream.
**No SSH credentials are visible to the bridge or to any intermediate peer.**

The xterm.js addon `@xterm/addon-fit` handles resize, and `@xterm/addon-web-links`
makes URLs in terminal output clickable, opening them in the HTTP proxy.

### 5.5 Whitelisting flow for new users

When a user visits the bridge URL before being whitelisted:

1. The browser generates its keypair, derives its peer ID, and shows it prominently.
2. An **invite QR code** is rendered: `p2pvpn:add-peer/<peerID>` deep-link. An admin
   with the network private key can scan this with the WebUI from any whitelisted
   device and click "Add to whitelist" — no typing of a 52-character peer ID.
3. Once whitelisted (gossip distributes the config update within seconds) the daemon
   peer's whitelist enforcer calls `OnPeerPromoted`, assigns an IP, and installs the
   TUN route. The next `/p2pvpn-proxy/1.0.0` CONNECT attempt from the browser will
   succeed.
4. The bridge polls `/api/bridge/config` (proxied through the proxy stream itself once
   connected) to detect its own IP assignment and then unlocks the full UI.

If the `userPrivKeyHex` in the URL hash _is_ the network authority key, the browser
can self-whitelist immediately by calling `POST /api/bridge/whitelist-self` through the
proxy stream, skipping the admin approval step.

---

## 6. Component Summary

### New Go files

| File | Purpose |
|---|---|
| `utils/proxy/proxy.go` | `/p2pvpn-proxy/1.0.0` handler, frame codec, per-connection goroutines |
| `utils/proxy/proxy_test.go` | Unit tests: frame round-trip, CIDR gating, whitelist re-check |

### Modified Go files

| File | Change |
|---|---|
| `utils/p2p/p2p.go` | `ProxyProtocol` constant; `proxyHandler` field + setter; `handleProxyStream`; `ConnectedVPNPeers()` method |
| `utils/daemon/daemon.go` | Construct `proxyLayer`, wire `SetProxyHandler` |
| `utils/webui/webui.go` | `/api/bridge/config` and `/api/bridge/whitelist-self` endpoints |

### New static files

| File | Purpose |
|---|---|
| `utils/webui/bridge.html` | Entire browser client — js-libp2p bootstrap, proxy runtime, xterm.js terminal, HTTP proxy Service Worker logic (inlined as a `Blob` URL to avoid needing a separate `sw.js` file) |

The `bridge.html` is embedded in the binary alongside `ui.html` via `//go:embed` and
served from the existing WebUI at `http://10.42.0.1/bridge`.

---

## 7. Security Considerations

| Risk | Mitigation |
|---|---|
| Private key in URL fragment | Fragment is not sent to any server; still warn user to not share URLs, clear hash after reading, store key in `localStorage` with a user-chosen passphrase using `SubtleCrypto.deriveKey` |
| Browser peer proxying traffic for all VPN targets | Daemon proxy handler validates every `CONNECT` target IP is within the VPN CIDR; ports can be restricted to an allowlist in `proxy.go` config |
| Unapproved browser peers reaching the proxy | `wlEnforcer.Allow(peerID)` is checked at stream open time **and** before each `CONNECT` frame; quarantine timeout applies identically to browser peers |
| Service Worker intercepting non-VPN traffic | SW only intercepts requests whose hostname resolves to a VPN CIDR address; all other requests pass through unmodified |
| SSH credential exposure | The proxy is a raw TCP tunnel; SSH end-to-end encryption is unaffected. The bridge process never sees decrypted SSH traffic |
| Proxy peer compromised | Browser client can pin specific proxy peer IDs; compromise of one proxy peer does not affect other VPN peers or the network key |

---

## 8. What This Looks Like End-to-End

```
User opens bridge.html#<networkID>|<privKey>
            │
            ▼
Browser libp2p node (js-libp2p + WebTransport)
            │  DHT discovery on networkID topic
            │  discovers daemon peer at /ip4/1.2.3.4/udp/7777/quic-v1/webtransport
            │
            ▼
/p2pvpn-proxy/1.0.0 stream  ←──────────────────────────────┐
            │                                               │
  CONNECT 10.42.0.3:80 ──► daemon proxy.go                 │
            │                 │ TCP connect 10.42.0.3:80    │
            │                 ▼                             │
            │           nginx on 10.42.0.3 ◄─ VPN TUN ─── │
            │                 │                             │
  DATA frames ◄──────────────┘  (HTTP response bytes)      │
            │                                               │
Service Worker reconstructs HTTP response                   │
            │                                               │
  <iframe src="http://10.42.0.3/"> renders the page ───────┘
                                                            │
  CONNECT 10.42.0.5:22 ──► proxy.go ──► TCP → sshd         │
  xterm.js ◄─── DATA frames ◄──── sshd stdout ─────────────┘
```

---

## 9. Open Questions / Future Extensions

- **Peer-to-peer proxy selection**: if multiple daemon peers are reachable, prefer the
  one with the lowest observed round-trip time to minimise proxy latency.
- **UDP proxy**: the current CONNECT model is TCP-only. VoIP or game traffic over the
  VPN would need a separate `CONNECT_UDP` frame type and a UDP socket on the daemon
  side (not a TUN, just a bound socket).
- **Browser-to-browser**: two browser peers could, in principle, open proxy streams to
  each other if both are whitelisted, creating a fully peer-to-peer web proxy without
  any daemon involvement. Requires both sides to implement `proxy.HandleStream`.
- **Offline QR invite**: the invite QR code could encode a one-time token signed by the
  network authority key, so the bridge can self-whitelist without having the full
  authority private key.
