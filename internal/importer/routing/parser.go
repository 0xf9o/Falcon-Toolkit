// Package routing provides routing table parser for route and network segment discovery.
package routing

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/observation"
)

// RouteEntry represents an IP route entry.
type RouteEntry struct {
	Destination string
	Gateway     string
	Interface   string
}

// Parse parses route table output from standard `ip route` or `route print`.
func Parse(r io.Reader) ([]RouteEntry, error) {
	var entries []RouteEntry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "=") || strings.HasPrefix(line, "IPv4 Route Table") || strings.HasPrefix(line, "Network Destination") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Linux format: 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10
			// or default via 192.168.1.1 dev eth0
			if fields[0] == "default" && len(fields) >= 3 && fields[1] == "via" {
				entries = append(entries, RouteEntry{
					Destination: "0.0.0.0/0",
					Gateway:     fields[2],
				})
			} else if strings.Contains(fields[0], "/") || strings.Contains(fields[0], ".") {
				entries = append(entries, RouteEntry{
					Destination: fields[0],
				})
			}
		}
	}

	return entries, scanner.Err()
}

// ParseFile reads routing entries from a file.
func ParseFile(path string) ([]RouteEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening routing file %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ConvertToObservations converts routing table entries to network observations.
func ConvertToObservations(entries []RouteEntry, sourceID string) []observation.NetworkObservation {
	if sourceID == "" {
		sourceID = "routing-import"
	}
	t := time.Now().UTC()
	var observations []observation.NetworkObservation
	for _, e := range entries {
		if strings.Contains(e.Destination, "/") {
			observations = append(observations, observation.NetworkObservation{
				CIDR:        e.Destination,
				Name:        "Discovered Route",
				Description: fmt.Sprintf("Route destination %s via gateway %s", e.Destination, e.Gateway),
				ObservedAt:  t,
				SourceID:    sourceID,
			})
		}
	}
	return observations
}
