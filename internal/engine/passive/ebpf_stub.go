//go:build !linux

package passive

import (
	"context"
	"fmt"
)

// EBPFObserver provides passive kernel-level flow monitoring on Linux systems.
type EBPFObserver struct {
	Interface string
}

// NewEBPFObserver initializes an eBPF observer stub on non-Linux architectures.
func NewEBPFObserver(iface string) *EBPFObserver {
	return &EBPFObserver{Interface: iface}
}

// Start on non-Linux platforms indicates eBPF kernel telemetry requires Linux.
func (eo *EBPFObserver) Start(ctx context.Context, onFlow func(srcIP, dstIP string, srcPort, dstPort int, proto string)) error {
	return fmt.Errorf("eBPF kernel telemetry is only supported on Linux kernels (use socket-level passive listeners on Windows/macOS)")
}
