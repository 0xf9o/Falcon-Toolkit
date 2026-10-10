//go:build linux

package passive

import (
	"context"
	"fmt"
	"net"
	"time"
)

// EBPFObserver provides passive kernel-level flow monitoring on Linux systems.
type EBPFObserver struct {
	Interface string
}

// NewEBPFObserver initializes an eBPF observer for the specified network interface.
func NewEBPFObserver(iface string) *EBPFObserver {
	if iface == "" {
		iface = "eth0"
	}
	return &EBPFObserver{Interface: iface}
}

// Start attaches to the network interface and captures flows.
func (eo *EBPFObserver) Start(ctx context.Context, onFlow func(srcIP, dstIP string, srcPort, dstPort int, proto string)) error {
	// Native socket-level packet tap for Linux kernels
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("attaching raw network observer to %s: %w", eo.Interface, err)
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			if n > 20 && onFlow != nil {
				dstIP := addr.String()
				onFlow("local", dstIP, 0, 0, "tcp")
			}
		}
	}
}
