// Package vlog provides a global verbose-logging facility for p2pvpn.
// When enabled via Enable(), all Logf calls print timestamped, tag-prefixed
// messages to stderr. When disabled (default), calls are no-ops.
package vlog

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
)

var enabled int32 // atomic; 0 = off, 1 = on

// Enable turns verbose logging on.
func Enable() { atomic.StoreInt32(&enabled, 1) }

// Enabled reports whether verbose logging is active.
func Enabled() bool { return atomic.LoadInt32(&enabled) != 0 }

// Logf prints a timestamped message with a tag prefix when verbose mode is on.
//
//	vlog.Logf("p2p", "opened stream to %s", peerID)
//	→ [2026-03-11T20:00:01Z] [p2p] opened stream to Qm...
func Logf(tag, format string, args ...interface{}) {
	if atomic.LoadInt32(&enabled) == 0 {
		return
	}
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, tag, msg)
}

// PacketSummary returns a concise human-readable summary of an IPv4 packet
// header: "TCP 10.42.0.2:443 → 10.42.0.5:56780 len=1420" or similar.
// Falls back to a hex dump of the first bytes for non-IPv4 packets.
func PacketSummary(pkt []byte) string {
	if len(pkt) < 20 {
		return fmt.Sprintf("short-pkt (%d bytes)", len(pkt))
	}
	version := pkt[0] >> 4
	if version != 4 {
		return fmt.Sprintf("non-IPv4 (version=%d, %d bytes)", version, len(pkt))
	}

	proto := pkt[9]
	srcIP := net.IP(pkt[12:16])
	dstIP := net.IP(pkt[16:20])
	totalLen := int(pkt[2])<<8 | int(pkt[3])

	protoName := fmt.Sprintf("proto-%d", proto)
	switch proto {
	case 1:
		protoName = "ICMP"
	case 6:
		protoName = "TCP"
	case 17:
		protoName = "UDP"
	}

	ihl := int(pkt[0]&0x0f) * 4
	if proto == 6 || proto == 17 {
		if len(pkt) >= ihl+4 {
			srcPort := int(pkt[ihl])<<8 | int(pkt[ihl+1])
			dstPort := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
			extra := ""
			if proto == 6 && len(pkt) >= ihl+14 {
				flags := pkt[ihl+13]
				var flagNames []byte
				if flags&0x02 != 0 {
					flagNames = append(flagNames, 'S')
				}
				if flags&0x10 != 0 {
					flagNames = append(flagNames, 'A')
				}
				if flags&0x01 != 0 {
					flagNames = append(flagNames, 'F')
				}
				if flags&0x04 != 0 {
					flagNames = append(flagNames, 'R')
				}
				if flags&0x08 != 0 {
					flagNames = append(flagNames, 'P')
				}
				if len(flagNames) > 0 {
					extra = fmt.Sprintf(" [%s]", string(flagNames))
				}
			}
			return fmt.Sprintf("%s %s:%d → %s:%d len=%d%s",
				protoName, srcIP, srcPort, dstIP, dstPort, totalLen, extra)
		}
	}

	if proto == 1 && len(pkt) >= ihl+2 {
		icmpType := pkt[ihl]
		icmpCode := pkt[ihl+1]
		return fmt.Sprintf("ICMP type=%d code=%d %s → %s len=%d",
			icmpType, icmpCode, srcIP, dstIP, totalLen)
	}

	return fmt.Sprintf("%s %s → %s len=%d", protoName, srcIP, dstIP, totalLen)
}
