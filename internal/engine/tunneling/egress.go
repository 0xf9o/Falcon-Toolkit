package tunneling

import (
	"context"
	"fmt"
	"net"
	"time"
)

// EgressPortResult represents the reachability of an outbound egress port.
type EgressPortResult struct {
	Port      int           `json:"port"`
	Protocol  string        `json:"protocol"`
	Open      bool          `json:"open"`
	Latency   time.Duration `json:"latency"`
	FilterMsg string        `json:"filter_msg,omitempty"`
}

// EgressValidator tests egress filtering permissiveness and tunnel MTU stability.
type EgressValidator struct {
	Timeout time.Duration
}

// NewEgressValidator creates an outbound egress verification engine.
func NewEgressValidator(timeout time.Duration) *EgressValidator {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &EgressValidator{Timeout: timeout}
}

// CheckEgressPorts tests if outgoing connections can be established to external destinations on standard ports.
func (ev *EgressValidator) CheckEgressPorts(ctx context.Context, targetHost string, ports []int) []EgressPortResult {
	if targetHost == "" {
		targetHost = "1.1.1.1" // Default reliable test target
	}

	var results []EgressPortResult
	for _, port := range ports {
		start := time.Now()
		addr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", port))

		dialer := &net.Dialer{Timeout: ev.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		elapsed := time.Since(start)

		if err != nil {
			results = append(results, EgressPortResult{
				Port:      port,
				Protocol:  "tcp",
				Open:      false,
				Latency:   elapsed,
				FilterMsg: err.Error(),
			})
			continue
		}
		_ = conn.Close()

		results = append(results, EgressPortResult{
			Port:     port,
			Protocol: "tcp",
			Open:     true,
			Latency:  elapsed,
		})
	}
	return results
}

// DiscoverPathMTU probes the effective path MTU by sending UDP probe packets with decreasing buffer sizes.
func (ev *EgressValidator) DiscoverPathMTU(targetHost string, targetPort int) (int, error) {
	if targetHost == "" {
		targetHost = "8.8.8.8"
	}
	if targetPort <= 0 {
		targetPort = 53
	}

	addr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
	conn, err := net.DialTimeout("udp", addr, ev.Timeout)
	if err != nil {
		return 0, fmt.Errorf("dialing MTU target: %w", err)
	}
	defer conn.Close()

	// Binary search or stepped probe down from 1500 to 576
	mtuSizes := []int{1500, 1492, 1472, 1400, 1360, 1280, 1024, 576}
	for _, size := range mtuSizes {
		payload := make([]byte, size-28) // Subtract 20-byte IP header + 8-byte UDP header
		_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
		_, err := conn.Write(payload)
		if err == nil {
			return size, nil
		}
	}

	return 576, nil // Minimum IPv4 MTU standard
}
