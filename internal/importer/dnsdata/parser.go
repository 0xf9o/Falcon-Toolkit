// Package dnsdata provides DNS record parsing (hosts format and standard zone files).
package dnsdata

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/observation"
)

// DNSRecord represents a resolved hostname to IP mapping.
type DNSRecord struct {
	Hostname string
	IP       string
}

// Parse parses lines from a hosts-style or simple DNS text file.
func Parse(r io.Reader) ([]DNSRecord, error) {
	var records []DNSRecord
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			// Format 1: IP Hostname (hosts file style)
			// Format 2: Hostname IP (simple record style)
			ip := fields[0]
			host := fields[1]

			// Check if fields[0] is IP
			if strings.Contains(ip, ".") || strings.Contains(ip, ":") {
				records = append(records, DNSRecord{
					IP:       ip,
					Hostname: host,
				})
			}
		}
	}

	return records, scanner.Err()
}

// ParseFile reads DNS records from a file path.
func ParseFile(path string) ([]DNSRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening DNS file %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ConvertToObservations converts DNS records to host observations.
func ConvertToObservations(records []DNSRecord, sourceID string) []observation.HostObservation {
	if sourceID == "" {
		sourceID = "dns-import"
	}
	t := time.Now().UTC()
	var observations []observation.HostObservation
	for _, r := range records {
		observations = append(observations, observation.HostObservation{
			IPAddress:  r.IP,
			Hostname:   r.Hostname,
			ObservedAt: t,
			SourceID:   sourceID,
		})
	}
	return observations
}
