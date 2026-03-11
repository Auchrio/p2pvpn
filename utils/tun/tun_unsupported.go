//go:build !linux && !windows

// Package tun stub for unsupported platforms.
package tun

import (
	"fmt"
	"net"
	"runtime"
)

type stubTUN struct{}

// Create returns an error on unsupported platforms.
func Create(name, localIP, cidrStr string) (Iface, error) {
	return nil, fmt.Errorf("TUN interfaces are not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (s *stubTUN) Read([]byte) (int, error)           { return 0, fmt.Errorf("unsupported") }
func (s *stubTUN) Write([]byte) (int, error)          { return 0, fmt.Errorf("unsupported") }
func (s *stubTUN) Close() error                       { return nil }
func (s *stubTUN) AddRoute(net.IP) error              { return fmt.Errorf("unsupported") }
func (s *stubTUN) DelRoute(net.IP) error              { return fmt.Errorf("unsupported") }
func (s *stubTUN) AddAddr(net.IP, net.IPMask) error   { return fmt.Errorf("unsupported") }
func (s *stubTUN) GetName() string                    { return "" }
func (s *stubTUN) GetIP() net.IP                      { return nil }
func (s *stubTUN) GetCIDR() *net.IPNet                { return nil }
