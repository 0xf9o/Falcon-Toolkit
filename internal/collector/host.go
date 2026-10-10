package collector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
)

// HostCollector verifies host reachability, latency, and basic network identity.
type HostCollector struct{}

// NewHostCollector creates a new host verification collector.
func NewHostCollector() *HostCollector {
	return &HostCollector{}
}

func (c *HostCollector) Name() string {
	return "host-discovery"
}

func (c *HostCollector) Description() string {
	return "Verifies host reachability, address family, and network latency"
}

func (c *HostCollector) Supports(target domain.Target) bool {
	switch target.Type {
	case domain.TargetIPv4, domain.TargetIPv6, domain.TargetHostname, domain.TargetDomain, domain.TargetURL:
		return true
	default:
		return false
	}
}

func (c *HostCollector) Run(ctx context.Context, target domain.Target, opts CollectorOptions) ([]ResultObservation, error) {
	now := time.Now().UTC()
	var observations []ResultObservation

	host := target.NormalizedValue
	if target.Type == domain.TargetURL {
		trimmed := strings.TrimPrefix(host, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		host = strings.Split(parts[0], ":")[0]
	}

	parsedIP := net.ParseIP(host)
	addrFamily := "unknown"
	if parsedIP != nil {
		if parsedIP.To4() != nil {
			addrFamily = "IPv4"
		} else {
			addrFamily = "IPv6"
		}
	}

	probePorts := []int{80, 443, 22, 53, 445, 8080}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	reachable := false
	var minLatency time.Duration = -1
	var successfulPort int

	for _, port := range probePorts {
		select {
		case <-ctx.Done():
			return observations, ctx.Err()
		default:
		}

		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			latency := time.Since(start)
			conn.Close()
			reachable = true
			if minLatency < 0 || latency < minLatency {
				minLatency = latency
				successfulPort = port
			}
			break
		}
	}

	if reachable {
		obs := ResultObservation{
			Collector:  c.Name(),
			SourceID:   fmt.Sprintf("host-verify-%s", host),
			Target:     target,
			Timestamp:  now,
			Confidence: domain.ConfidenceHigh,
			Kind:       "host",
			Host: &observation.HostObservation{
				IPAddress:  host,
				ObservedAt: now,
				SourceID:   c.Name(),
				Tags:       []string{"verified-reachable", addrFamily},
			},
			Metadata: map[string]string{
				"reachable":      "true",
				"latency_ms":     fmt.Sprintf("%.2f", float64(minLatency.Microseconds())/1000.0),
				"probe_port":     fmt.Sprintf("%d", successfulPort),
				"address_family": addrFamily,
				"verification":   "tcp_handshake",
			},
			RawData: fmt.Sprintf("Host %s verified reachable via TCP/%d (latency: %v, family: %s)", host, successfulPort, minLatency, addrFamily),
		}
		observations = append(observations, obs)
	}

	return observations, nil
}
