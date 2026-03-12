// Package vlog provides a global verbose-logging facility for p2pvpn.
// When enabled via Enable(), all Logf calls print timestamped, tag-prefixed
// messages to stderr. When disabled (default), calls are no-ops.
package vlog

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var enabled int32 // atomic; 0 = off, 1 = on

// ── ring buffer for recent log lines ─────────────────────────────────────────

const ringSize = 500 // max log lines kept in memory

var (
	ringMu  sync.Mutex
	ring    [ringSize]string
	ringPos int  // next write index
	ringN   int  // total lines written (for wraparound detection)
)

// RecentLines returns the last n log lines (most-recent last).
// If fewer than n lines exist, returns all available lines.
func RecentLines(n int) []string {
	ringMu.Lock()
	defer ringMu.Unlock()

	avail := ringN
	if avail > ringSize {
		avail = ringSize
	}
	if n > avail {
		n = avail
	}
	if n == 0 {
		return nil
	}

	out := make([]string, n)
	start := (ringPos - n + ringSize) % ringSize
	for i := 0; i < n; i++ {
		out[i] = ring[(start+i)%ringSize]
	}
	return out
}

func pushLine(line string) {
	ringMu.Lock()
	ring[ringPos] = line
	ringPos = (ringPos + 1) % ringSize
	ringN++
	ringMu.Unlock()
}

// Enable turns verbose logging on.
func Enable() { atomic.StoreInt32(&enabled, 1) }

// Enabled reports whether verbose logging is active.
func Enabled() bool { return atomic.LoadInt32(&enabled) != 0 }

// Logf prints a timestamped message with a tag prefix when verbose mode is on.
// The line is always added to the in-memory ring buffer (for the web console)
// regardless of whether verbose stderr output is enabled.
//
//	vlog.Logf("p2p", "opened stream to %s", peerID)
//	→ [2026-03-11T20:00:01Z] [p2p] opened stream to Qm...
func Logf(tag, format string, args ...interface{}) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] [%s] %s", ts, tag, msg)

	// Always push to ring buffer for the web console.
	pushLine(line)

	if atomic.LoadInt32(&enabled) != 0 {
		fmt.Fprintln(os.Stderr, line)
	}
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
