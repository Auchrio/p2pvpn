//go:build !linux

// Package netmon monitors the host's network interfaces for changes.
// This is a stub for unsupported platforms.
package netmon

import (
	"context"
	"net"
)

// Change describes a network event that was detected.
type Change struct {
	Reason string
}

// Monitor watches for host network changes.  On unsupported platforms this
// is a no-op.
type Monitor struct {
	C <-chan Change
}

// New returns a no-op Monitor on unsupported platforms.
func New(_ context.Context, _ string) *Monitor {
	ch := make(chan Change) // never sends
	return &Monitor{C: ch}
}

// Stop is a no-op on unsupported platforms.
func (m *Monitor) Stop() {}

// String implements fmt.Stringer.
func (c Change) String() string { return c.Reason }

// IsPhysicalChange always returns false on unsupported platforms.
func (c Change) IsPhysicalChange() bool { return false }

// IgnoreIP is a no-op on unsupported platforms.
func IgnoreIP(_ net.IP, _ string) bool { return false }
