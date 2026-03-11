# Security Analysis: Relay Circuit Usage in p2pvpn

## Executive Summary

When two p2pvpn peers communicate through a relay node (due to NAT/CGNAT/firewall restrictions), **all VPN data remains end-to-end encrypted** and the relay node cannot inspect or modify peer traffic. The relay only sees:
- Encrypted libp2p Noise frames
- Peer multiaddresses and connectivity metadata
- Bandwidth (total bytes, not content)

This document analyzes the security implications of relay usage in detail.

## Encryption Architecture

### End-to-End Encryption (Noise Protocol)

All p2pvpn peer-to-peer communication uses the **Noise protocol** (confidentiality + integrity + authentication) with 256-bit keys. The encryption happens at the application layer, *before* frames are sent to the relay.

```
┌──────────────────────────────────────────────────────────────┐
│ Plaintext VPN packet (IP header + payload)                   │
└──────────────────┬───────────────────────────────────────────┘
                   │
        (Noise AEAD encryption)
                   │
┌────────────────▼──────────────────────────────────────────────┐
│ Encrypted Noise frame (ciphertext + tag)                      │
│ (libp2p stream framing layer)                                 │
└─────────────────┬──────────────────────────────────────────────┘
                  │
         (Either direct TCP/QUIC OR relay circuit)
                  │
┌────────────────▼──────────────────────────────────────────────┐
│ Transport layer (TCP/QUIC/relay)                              │
│ Relay sees ONLY encrypted frames                              │
└──────────────────────────────────────────────────────────────┘
```

**Key property:** The relay node cannot decrypt frames because it never receives the Noise session keys.

### Session Key Derivation

Noise session keys are derived via ECDH (Elliptic Curve Diffie-Hellman) with peer pubkeys:
```
session_key = KDF(ECDH(peer_A_privkey, peer_B_pubkey))
```

The relay is **not** a party to this exchange. Session keys are negotiated between peers directly (even if the relay is in the path).

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

**Conclusion:** Relay cannot decrypt traffic with feasible computation.

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

### Scenario 5: Multiple Colluding Relays

**Attack:** Two or more organizations operating relays share observed traffic patterns to re-identify peers.

**Impact:** Can correlate traffic across relay boundaries to identify peer pairs with high confidence.

**Mitigation:**
- **Defense in depth:** Use TLS/QUIC on the relay path (provides additional encryption layer)
- **Onion-like relays:** Use multi-hop relay chains (p2pvpn does NOT support this currently)
- **Your responsibility:** Choose geographically diverse, non-colluding relays

**Conclusion:** No single relay can fully hide this; requires architectural changes (multi-hop relays) for stronger privacy.

### Scenario 6: ISP or Network Observer (Not the Relay)

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
