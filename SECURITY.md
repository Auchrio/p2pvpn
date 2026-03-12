# Security Analysis: Relay Circuit Usage in p2pvpn

## Executive Summary

When two p2pvpn peers communicate through a relay node (due to NAT/CGNAT/firewall restrictions), **all VPN data remains end-to-end encrypted** and the relay node cannot inspect or modify peer traffic. The relay only sees:
- Encrypted libp2p Noise frames
- Peer multiaddresses and connectivity metadata
- Bandwidth (total bytes, not content)

This document analyzes the security implications of relay usage in detail.

## Encryption Architecture

### End-to-End Encryption (Noise Protocol)

All p2pvpn peer-to-peer communication uses the **Noise protocol** (confidentiality + integrity + authentication) with 256-bit keys. The encryption happens at the application layer, *before* frames are sent through any transport (direct or relay).

**Encryption always occurs before transport, regardless of whether peers are directly connected or using a relay:**

```
┌──────────────────────────────────────────────────────────────┐
│ Plaintext VPN packet (IP header + payload)                   │
└──────────────────┬───────────────────────────────────────────┘
                   │
        (Noise AEAD encryption with peer session key)
                   │
┌────────────────▼──────────────────────────────────────────────┐
│ Encrypted Noise frame (ciphertext + 16-byte Poly1305 MAC)    │
│ This encryption is APPLICATION-LAYER and uses the Peer-A ↔  │
│ Peer-B session key, which the relay does NOT possess.        │
└─────────────────┬──────────────────────────────────────────────┘
                  │
        (libp2p stream framing)
                  │
┌────────────────▼──────────────────────────────────────────────┐
│ Stream frame (demux info + encrypted payload)                 │
│ Relay can read this to demux, but cannot read the payload    │
└─────────────────┬──────────────────────────────────────────────┘
                  │
    ┌─────────────┴──────────────┐
    │                            │
 DIRECT                        VIA RELAY
    │                            │
    ↓                            ↓
┌─────────────────┐    ┌──────────────────────────────┐
│ Direct TCP/QUIC │    │ Relay v2 Circuit             │
│ (P2P encrypted) │    │ ├─ Relay decrypts/re-encrypts│
│ Relay N/A       │    │ │   Layer 3 (relay envelope) │
│                 │    │ ├─ Relay CANNOT read Layer 1 │
│                 │    │ │   (peer payload)           │
│                 │    │ └─ Forwarded encrypted to    │
│                 │    │    peer via relay connection │
└─────────────────┘    └──────────────────────────────┘
```

**Key property:** Whether peers are directly connected or connected via a relay circuit, the Noise encryption between the two peers is **end-to-end** and cannot be read by the relay. The relay only sees connection-level metadata and the encrypted stream envelope.

### Session Key Derivation

Noise session keys are derived via ECDH (Elliptic Curve Diffie-Hellman) with peer pubkeys:
```
session_key = KDF(ECDH(peer_A_privkey, peer_B_pubkey))
```

The relay is **not** a party to this exchange. Session keys are negotiated between peers directly (even if the relay is in the path).

### Relay Circuit Encryption (Detailed Flow)

When two peers communicate via libp2p relay v2 circuits, encryption happens in **multiple layers**. Understanding this layering is critical to verifying that relay operators cannot intercept traffic.

#### Connection Establishment Through a Relay

```
┌─────────────────────────────────────────────────────────────┐
│ Peer A (initiator)                                          │
│ ├─ Establishes connection to relay (direct, encrypted Noise)│
│ ├─ Sends relay/v2 RESERVE message (hop reservation)        │
│ └─ Obtains a /p2p-circuit multiaddr pointing to Peer B    │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ Relay (passive ForwardingService listener)                  │
│ ├─ Receives Peer B RESERVE (from Peer B directly)          │
│ ├─ Stores reservation state in memory                       │
│ └─ Does NOT decrypt or parse application traffic           │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ Peer B (listener)                                           │
│ ├─ Establishes connection to relay (direct, encrypted Noise)│
│ ├─ Sends relay/v2 RESERVE message (hop reservation)        │
│ └─ Waits for inbound circuits                              │
└─────────────────────────────────────────────────────────────┘
```

The relay's involvement ends at the RESERVE protocol level. All subsequent traffic is end-to-end encrypted.

#### The Three Encryption Layers

When Peer A sends data to Peer B through a relay, three distinct encryption layers are involved:

**Layer 1: Noise Encrypted Data (Peer A ↔ Peer B)**
```
Raw VPN packet (plaintext IP)
    ↓ [encrypt with Noise session key]
Encrypted Noise frame (ciphertext + 16-byte Poly1305 MAC)
    ↓ [add relay circuit wrapper]
libp2p relay frame (contains encrypted data + relay metadata)
```
- **Key:** Derived from Noise handshake between Peer A and Peer B exclusively
- **Relay visibility:** NONE — cannot decrypt or verify the MAC

**Layer 2: libp2p Stream Framing (Peer A ↔ Relay ↔ Peer B)**
```
Encrypted Noise frame (Layer 1)
    ↓ [wrap in libp2p stream protocol]
Stream frame: [flags] [stream_id] [data_length] [data]
    ↓ [multiplex with other streams/protocols]
Multiple streams on same connection
```
- **Stream ID:** Identifies which peer pair + application stream
- **Relay visibility:** Sees stream IDs and frame boundaries, but not stream content (Layer 1 encrypted)

**Layer 3: libp2p Connection Encryption (Relay ↔ Peer)**
```
Stream frame (Layer 2)
    ↓ [encrypt with per-relay Noise session key]
Encrypted connection frame (ciphertext + MAC)
    ↓ [send via TCP/QUIC/etc.]
TCP/QUIC transport
```
- **Key:** Derived from separate Noise handshake between (Peer A ↔ Relay) and (Peer B ↔ Relay)
- **Relay sees:** Only the connection-level encryption. It reads Layer 2 (the forwarding envelope) but cannot read Layer 1 (the VPN payload)

#### What the Relay Actually Sees

When operating the ForwardingService on incoming relay circuits:

| Level | Data | Access | Used For |
|-------|------|--------|----------|
| Transport (TCP/QUIC) | Packets, headers, connection state | ✓ Direct | Routing circuits, counting bytes |
| Connection Encryption (Layer 3) | Per-relay Noise session | ✓ Has key | Encryption/decryption between relay ↔ peer |
| Stream Framing (Layer 2) | Stream IDs, frame types, lengths | ✓ Can read | Demuxing circuits to correct destination |
| Noise Application Payload (Layer 1) | Encrypted VPN frames, ciphertext | ✗ No key | The actual VPN traffic content |

**Concrete example:**

```
Relay receives bytes from Peer A:
  [0x14] [frame_type_reserved_data] [length=256] [<256 bytes of ciphertext from Layer 1>]
  
Relay decrypts this with its own Noise session key (Layer 3):
  ✓ Yields the stream frame and 256 bytes of Layer 1 ciphertext
  
Relay demuxes the stream frame:
  ✓ Learns this is for stream_id=0x05 (Peer A ↔ Peer B circuit)
  ✓ Routes the 256 bytes to Peer B
  
Relay sends to Peer B:
  [encrypted with Relay ↔ Peer B Noise key]
  
Relay CANNOT access the 256 bytes of Layer 1 ciphertext:
  ✗ Has no key to decrypt AES-256-GCM Layer 1 encryption
  ✗ Cannot read: Peer A's peer ID certificate, stream protocol, VPN packet content
```

#### Noise Session Keys in Relay Scenarios

Three independent Noise sessions exist when using relays:

```
Session A-Relay:
  ├─ Key = KDF(ECDH(A_priv, Relay_pub))
  ├─ Established during A ↔ Relay connection
  └─ Used to encrypt Layer 3 (connection level)

Session B-Relay:
  ├─ Key = KDF(ECDH(B_priv, Relay_pub))
  ├─ Established during B ↔ Relay connection
  └─ Used to encrypt Layer 3 (connection level)

Session A-B (DIRECT, never sent through relay):
  ├─ Key = KDF(ECDH(A_priv, B_pub)) 
  ├─ Negotiated via relay /p2p-circuit but key computation is LOCAL
  └─ Used to encrypt Layer 1 (application payload)
```

**Key insight:** The relay never sees, computes, or has access to the A-B session key. The relay only ever uses its own per-connection Noise keys (A-Relay and B-Relay), which cannot decrypt A-B traffic.

#### Authentication Through Relays

The Noise protocol includes authentication:
- Each Noise frame has a 16-byte **Poly1305 MAC** derived from the session key
- Modified frames fail MAC verification and are dropped
- The relay cannot forge packets because it lacks the A-B session key

```
If relay modifies 1 byte of Layer 1 ciphertext:
  ├─ MAC fails at Peer B's side
  └─ Frame is dropped silently (authentication failure)

If relay replays a captured frame:
  ├─ Peer B expects an incrementing message counter (Noise feature)
  ├─ Replayed frame has old counter
  └─ Frame is dropped (replay protection)
```

#### Relay Performance vs. Security Trade-offs

The relay must:
1. Receive Layer 3 encrypted data
2. Decrypt with relay's Noise key (learning Layer 2 demux info)
3. Re-encrypt with peer's Noise key (re-wrapping for relay-to-peer)

This is **computationally expensive** (~2 AES-256-GCM ops per frame in each direction) but is the security boundary that keeps Layer 1 protected.

## Threat Model: What the Relay Can See

### ✓ Observable (Cannot Be Hidden)

| Data | Impact | Severity |
|------|--------|----------|
| **Packet volume (bytes/sec)** | Relay operator can profile traffic size and timing patterns | Medium |
| **Peer identities (libp2p peer IDs)** | Which peers communicated (per relay reservation) | Medium |
| **Connection duration** | How long peers stay connected | Low |
| **Public IP addresses** | Source/destination IPs (visible at IP layer on relay) | Medium |
| **Relay selection** | Which relay nodes are used between which peers | Low |
| **DHT metadata** | Peer multiaddresses, bootstrap peers | Low |

### ✗ Not Observable (Encrypted)

| Data | Reason |
|------|--------|
| **VPN packet content** | Encrypted with Noise AEAD |
| **Peer source/destination IPs on VPN** (10.42.0.x) | VPN layer data inside encrypted Noise frames |
| **Application data** | TCP/HTTP/DNS/etc. inside encrypted VPN packets |
| **Packet headers** (TCP flags, ports) | Inside encrypted Noise frames |
| **Session keys** | Never transmitted; derived via ECDH |

## Attack Scenarios & Mitigations

### Scenario 1: Relay Operator Performs Traffic Analysis

**Attack:** Operator observes packet sizes and inter-arrival times to infer application type (VoIP, video, HTTP, etc.).

**Impact:** 
- Attackers can correlate traffic patterns with known applications
- Timing side-channels may leak information about user activity

**Mitigation:**
- **Recommended:** Use a relay node you operate or trust (e.g., your own VPS)
- **Default:** No built-in traffic padding (would increase bandwidth 2-10x). Operators can add this if needed
- **Practical:** Most attacks require millions of packets; short bursts are hard to analyze

**Your responsibility:** Choose honest relay operators. This is a policy/social problem, not a crypto problem.

### Scenario 2: Relay Operator Attempts to Modify Traffic

**Attack:** Operator intercepts encrypted frames and modifies bytes.

**Impact:** IMPOSSIBLE — Noise includes a 16-byte authentication tag (Poly1305 MAC). Modified frames fail authentication and are dropped.

```
Encrypted frame = [ciphertext (variable)] + [tag (16 bytes)]

If relay modifies ANY byte:
  → Receiver computes MAC on received ciphertext
  → MAC doesn't match stored tag
  → Frame dropped (authentication failure)
```

**Conclusion:** Relay cannot modify VPN traffic. Attempting to do so breaks the connection.

### Scenario 3: Relay Attempts to Decrypt Traffic

**Attack:** Operator uses cryptanalysis or computation to recover session keys.

**Impact:** IMPRACTICAL — Noise uses 256-bit keys derived from ECDH (2^256 security). No known polynomial-time attack.

**Relevant for:** AES-256 is considered post-quantum resistant and is not vulnerable to known algebraic attacks.

**Relay context:** Even if a relay operator somehow recovered the 256-bit session key through cryptanalysis, they would only recover:
- The Relay ↔ Peer session key (used for Layer 3 connection encryption between relay and one peer)
- NOT the Peer A ↔ Peer B session key (Layer 1, used for VPN payload)

The relay never handles the Peer A ↔ Peer B key in plaintext at any point. The key is derived by each peer locally using ECDH:
```
Peer A computes: session_key = KDF(ECDH(A_private, B_public))
Peer B computes: session_key = KDF(ECDH(B_private, A_public))
Relay NEVER sees or computes this key.
```

Even if the relay breaks its own connection key (A-Relay or B-Relay), it only reads Layer 2 (stream framing), not Layer 1 (actual VPN packets).

**Conclusion:** Relay cannot decrypt VPN traffic with feasible computation.

### Scenario 4: Relay Operator Monitors Bandwidth Over Time

**Attack:** Operator notes which peers consistently exchange large amounts of data.

**Impact:** 
- Correlates peer pairs with heavy communication
- Could infer organizational structure or group memberships

**Mitigation:**
- **Encrypt metadata:** Keep your relay selection private (don't advertise which peer uses which relay)
- **Diversify relays:** Rotate relay nodes periodically
- **Your responsibility:** If privacy from relay operators is critical, run your own relay or use multiple independent relays

**Conclusion:** This is a limitation of any relay architecture (including VPNs, Tor, etc.). Encrypted relays can't fully hide metadata.

### Scenario 5: Relay Attempts to Hijack or Replay Circuit Traffic

**Attack:** Relay captures encrypted frames on a circuit and either:
1. Replays them later (replay attack)
2. Reorders frames to corrupt the stream (reordering attack)
3. Injects forged frames with crafted ciphertexts

**Impact:** IMPOSSIBLE — Noise includes built-in counter and MAC protections:

**Anti-replay:**
```
Each Noise message has an incrementing counter (n = 0, 1, 2, ...).
If relay replays frame with n=42 twice:
  ├─ Peer receives first frame, counter = 42, accepted
  ├─ Peer receives duplicate with n=42, counter not incremented
  └─ MAC verification fails (counter doesn't match), frame dropped
```

**Anti-forgery:**
```
Each encrypted frame ends with a 16-byte Poly1305 MAC computed as:
  MAC = Poly1305(key, nonce, ciphertext, counter)
  
If relay modifies even 1 bit of ciphertext:
  ├─ Receiver recomputes MAC on received ciphertext
  ├─ New MAC ≠ received MAC
  └─ Frame dropped immediately (authentication failure, no decryption)
```

**No key material leaked by modification attempt:**
Attempting to forge frames does not leak information about the session key — MAC failures are silent.

**Conclusion:** Relay cannot hijack, replay, or forge peer traffic without possession of the session key.

### Scenario 6: Multiple Relays or Relay ↔ Relay Communication

**Attack:** Two or more organizations operating relays share observed traffic patterns to re-identify peers.

**Impact:** Can correlate traffic across relay boundaries to identify peer pairs with high confidence.

**Mitigation:**
- **Defense in depth:** Use TLS/QUIC on the relay path (provides additional encryption layer)
- **Onion-like relays:** Use multi-hop relay chains (p2pvpn does NOT support this currently)
- **Your responsibility:** Choose geographically diverse, non-colluding relays

**Conclusion:** No single relay can fully hide this; requires architectural changes (multi-hop relays) for stronger privacy.

### Scenario 7: ISP or Network Observer (Not the Relay)

**Attack:** An observer on the network path between you and the relay (ISP, WiFi operator, etc.) monitors traffic.

**Impact:** 
- Sees your IP address connecting to a relay node
- Sees encrypted frames but not content
- Can count bytes and infer activity

**Mitigation:**
- **Relay itself adds no new risk** — ISP sees relay traffic regardless
- **Use QUIC/WebTransport:** Harder to block/filter than raw TCP
- **Default p2pvpn behavior:** Listens on TCP + QUIC + WebTransport. ISP can block TCP port but QUIC usually passes.

**Conclusion:** Relay doesn't make this worse. ISP privacy concerns are orthogonal.

## Relay Selection & Trust Model

### How Relays Are Chosen

p2pvpn selects relay nodes in priority order:

1. **Connected peers that advertise relay v2 support** — highest priority
2. **DHT routing table peers** (may support relay, uncertain)
3. **IPFS bootstrap peers** — fallback (well-known public infra)

The daemon will attempt multiple relays until one accepts a reservation.

### Who Should Run Relays?

**Trusted scenarios:**
- Your own VPS (you control the operator)
- Community-run relay clusters (known operators, audited code)
- CDN providers (Cloudflare, Akamai relay infrastructure)
- Organizations with strong privacy policies

**Be cautious:**
- Unknown operators on public DHT
- Relays with no reputation or audit trail
- Shared relay infrastructure without Terms of Service

### Bootstrapping Trust

p2pvpn doesn't include a trust-on-first-use (TOFU) mechanism for relays (unlike Tor guards). Instead:

1. You can specify trusted bootstrap peers via config file
2. Those peers can advertise relay nodes they trust
3. You inherit trust transitively

**Best practice:** Run your own relay or use `--peer` flags to specify explicit bootstrap nodes.

## Practical Security Recommendations

### For Home/Small Office Networks

✓ **Recommended:**
- Enable hole-punching (default behavior)
- Use a free public relay (low risk for household VPN traffic)
- Monitor relay diagnostics: `[nat] peerSource: N relay-capable candidates`

✗ **Not recommended:**
- Disable NAT traversal (forces relay usage for all CGNAT scenarios)
- Use unknown relay operators for sensitive data

### For Enterprise VPNs

✓ **Recommended:**
- Deploy your own relay node on a VPS you control
- Whitelist relay nodes in config files: restrict to your infrastructure only
- Use network segmentation: isolate relay traffic from other infra
- Monitor relay metrics: connections, bandwidth, error rates
- Regularly rotate relay nodes (prevents long-term correlation)

Example config:
```ini
# Only use relays we operate
BOOTSTRAP_PEERS=/ip4/203.0.113.45/tcp/7777/p2p/QmOurRelay...
BOOTSTRAP_PEERS=/ip4/198.51.100.1/tcp/7777/p2p/QmOurRelay2...
```

✗ **Not recommended:**
- Relay top-secret data through public IPFS infrastructure
- Use default IPFS bootstrap relays for classified networks
- Allow peers to auto-discover relays without approval

### For High-Privacy Scenarios

✓ **Recommended:**
- Run your own relay infrastructure
- Use WebTransport (harder to block/categorize)
- Diversify relay providers geographically
- Add traffic shaping / padding at application layer (outside p2pvpn)
- Consider Tor integration at network layer (separate project)

✗ **Not recommended:**
- Rely on default public relays for truly sensitive data
- Use relay without end-to-end encryption (p2pvpn always encrypts, but verify locally)

## Whitelist Mode: Peer Capabilities Before Approval

When `whitelist-mode` is enabled, new peers are placed in a **quarantine** state immediately upon connecting. The whitelist enforcer (`whitelist.Enforcer`) checks every packet at two chokepoints — `tunReadLoop` (outbound to peer) and `onPacket` (inbound from peer) — and silently drops traffic for quarantined peers.

### Security Hardening (v1.3.0)

As of v1.3.0, whitelist mode includes significant security improvements to prevent resource exhaustion and information leakage from quarantined peers:

| Protection | Implementation |
|-----------|----------------|
| **No IP assignment for quarantined peers** | `onPeerConnect` checks whitelist status *before* calling `ipMgr.AssignDeterministic()`. Quarantined peers do not consume addresses from the virtual CIDR pool. |
| **No TUN route installation** | Routes are only installed when a peer is whitelisted, preventing `/32` route accumulation for unapproved peers. |
| **Quarantine timeout (2 minutes)** | Peers that remain quarantined for more than 2 minutes are automatically disconnected. This prevents indefinite resource consumption (file descriptors, memory, DHT slots). |
| **Config sanitization** | When whitelist mode is enabled, `PublishState()` uses `MarshalPublic()` which strips `allowed-peers`, `delegated-peers`, and `delegations` from the gossip payload. Quarantined peers cannot enumerate the whitelist. |
| **Deferred promotion** | When a quarantined peer is later added to the whitelist, `OnPeerPromoted` callback triggers immediate IP assignment and route installation without requiring reconnection. |

### What a Quarantined (Pre-whitelist) Peer CAN Do

| Capability | Detail |
|-----------|--------|
| **DHT participation** | The peer fully joins the Kademlia DHT, contributes to routing table population, and can look up arbitrary keys. Whitelist enforcement is entirely above the DHT layer. |
| **mDNS discovery** | The peer is visible to and can discover all other nodes advertising the same network tag on the local network segment. |
| **Relay reservation** | The peer can obtain circuit relay reservations through any relay in the network and expose reachable multiaddresses on the DHT. |
| **VPN stream establishment** | The peer can open a `/p2pvpn/1.0.0` protocol stream to any node. `handleStream` accepts all incoming streams without a whitelist check. |
| **GossipSub membership** | The peer joins the shared GossipSub topic and receives gossip messages. However, sensitive fields (allowed-peers, delegations) are stripped from state syncs when whitelist mode is active. |
| **Basic config visibility** | The peer can see non-sensitive config fields: IP range, hold duration, `whitelist-mode` flag, max-peers, allowed-ports. |

### What a Quarantined Peer CANNOT Do

| Blocked action | Enforcement point |
|---------------|------------------|
| **Consume virtual IPs** | `onPeerConnect` — whitelist check happens *before* IP assignment |
| **Install TUN routes** | `onPeerConnect` — routes only installed for whitelisted peers |
| **Send VPN packets** | `onPacket` — first line drops packets from quarantined peers before they reach the TUN |
| **Receive VPN packets** | `tunReadLoop` — `wlEnforcer.Allow()` is checked before `SendPacket`; packet is dropped if peer is quarantined |
| **Reach services at virtual IPs** | Follows from the above — no IP traffic can flow to/from the quarantined peer's virtual address |
| **Access the WebUI** | The WebUI binds to the `.1` config IP on the TUN. Inbound VPN packets from quarantined peers are dropped in `onPacket` |
| **Enumerate the whitelist** | `MarshalPublic()` strips `allowed-peers` and `delegations` when whitelist mode is enabled |
| **Stay connected indefinitely** | Quarantine timeout (2 min) auto-disconnects unapproved peers |

### Remaining Attack Surface

Even with v1.3.0 hardening, quarantined peers can still:

1. **Participate in DHT** — Cannot be prevented without breaking libp2p fundamentals
2. **Consume some resources** — DHT routing table slots, GossipSub mesh slots (limited by timeout)
3. **See non-sensitive config** — IP range, hold duration, whitelist mode flag
4. **Observe signed config updates** — Signed updates from authority nodes contain full config (required for signature validation)

For maximum security in adversarial environments, consider:
- Using larger CIDRs to absorb potential IP exhaustion
- Running separate networks for different trust levels
- Monitoring quarantine events via logs

### Promotion

A quarantined peer is promoted to full VPN access the moment an authority node runs `p2pvpn whitelist add <peerID>` (or the equivalent WebUI action). This publishes a signed config update via gossip; every node's `onConfigUpdate` calls `wlEnforcer.Refresh()`, which triggers `OnPeerPromoted` for matching quarantined peers. The callback assigns an IP and installs routes immediately without requiring reconnection.

## Comparison with Other VPN Solutions

| Property | p2pvpn via Relay | Tailscale (DERP) | Wireguard (VPN provider) | Tor |
|----------|---|---|---|---|
| **End-to-end encryption** | ✓ (Noise) | ✓ (WireGuard) | ✓ (WireGuard) | ✓ (multi-hop) |
| **Relay sees traffic content** | ✗ | ✗ | ✗ | ✗ |
| **Relay sees packet sizes** | ✓ | ✓ | ✓ | ✓ (with padding) |
| **Relay sees peer IDs** | ✓ | ✓ | ✓ | ✗ (ephemeral) |
| **Operator trust required** | Yes | Yes (Tailscale Inc.) | Yes (VPN provider) | Distributed (exit nodes) |
| **Multi-hop available** | ✗ (future) | ✗ | ✗ | ✓ |
| **Self-hosted relay** | ✓ | ✗ | N/A | ✗ (requires Tor network) |

**Key insight:** p2pvpn relay security is **equivalent to Tailscale DERP** for encrypted payload, but with more control over relay selection (you can self-host).

## Known Limitations & Future Work

### Current Limitations

1. **No traffic padding** — Packet sizes leak information about VPN workload
2. **Single-hop relays** — Cannot chain relays for stronger privacy (like Tor)
3. **No onion routing** — Relay operator can see which peers communicated
4. **QUIC plaintext** — QUIC header (connection ID, packet numbers) visible in cleartext, can aid fingerprinting

### Future Enhancements (Potential)

- [ ] Traffic padding option (`--pad-packets`) to add dummy frames
- [ ] Multi-hop relay chains for Tor-like privacy
- [ ] QUIC encryption options (requires libp2p upstream work)
- [ ] Relay reputation tracking (choose relays with privacy policies)
- [ ] Automatic relay rotation (switch relays periodically)

## Compliance & Regulatory Notes

### Data Residency
Relay nodes may be located in any jurisdiction. If you operate relays in the EU (GDPR), consider:
- Relay nodes log who connected (peer IDs) → may be personal data
- Implement data retention policies: delete connection logs after N days
- Document lawful processing basis

### Network Monitoring
Some jurisdictions restrict encryption strength. p2pvpn uses AES-256 (legal in most places), but check local regulations.

### Liability
If you operate a relay, consider:
- **Abuse terms of service** — can you deny service to abusive peers?
- **Copyright/DMCA** — relay operator liability for transit traffic (usually protected as common carrier)
- **DDoS mitigation** — will you rate-limit or block known attacks?

Consult legal counsel if operating relays in regulated environments.

## Testing & Verification

### How to Verify End-to-End Encryption

1. **Capture relay traffic with tcpdump:**
   ```bash
   sudo tcpdump -i any -n 'host <relay_ip>' -w relay.pcap
   ```

2. **Analyze with Wireshark:**
   - All application data is ciphertext (random-looking bytes)
   - TCP/QUIC headers are visible (connection setup)
   - Payload is NOT decryptable

3. **Confirm with p2p logs:**
   ```bash
   sudo p2pvpn daemon start -v 2>&1 | grep -i relay
   # Should show: [nat] ✓ Relay active — peers can reach us via circuit relay
   ```

### How to Verify Replay Attack Resistance

Each Noise frame includes a counter (message number) that increments per frame. Relayed frames cannot be replayed because:
1. Receiver expects monotonic increasing counter
2. Duplicate frame number → authentication failure

This is built into the Noise protocol; no special verification needed.

### How to Verify Relay Trustworthiness

**Red flags:**
- Relay operator cannot provide uptime/capability info
- No documentation of privacy practices
- Relay crashes or has high error rates
- Operator unwilling to discuss security

**Green flags:**
- Operator provides SLA documentation
- Code audit trail (if open-source relay)
- Privacy policy on packet retention
- Contact info for abuse reporting

## Conclusion

Using relay circuits in p2pvpn is **cryptographically safe** — the relay cannot decrypt or modify encrypted VPN data. However, relay operators can observe:
- Traffic metadata (volume, peer identities, timing)
- Peer associations (which peers communicated)

**Security depends on:**
1. **Trusting relay operator** — choose operators carefully
2. **End-to-end encryption** — always enabled in p2pvpn (Noise protocol)
3. **Diversifying relays** — use multiple independent relays to prevent correlation attacks
4. **Operational security** — don't leak peer identities outside of p2pvpn

For sensitive workloads, running your own relay (or using trusted community relays) is the best practice. For typical use cases, default behavior is secure.

---

**Last updated:** March 2026  
**Maintainers:** p2pvpn team
