// Package arp provides ARP table output parsing.
package arp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/observation"
)

// ARPEntry represents an IP to MAC mapping.
type ARPEntry struct {
	IP  string
	MAC string
}

var (
	macRegex = regexp.MustCompile(`(?i)[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}`)
	ipRegex  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// Parse parses ARP table output from standard `arp -a` or `/proc/net/arp`.
func Parse(r io.Reader) ([]ARPEntry, error) {
	var entries []ARPEntry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Interface:") || strings.HasPrefix(line, "IP Address") {
			continue
		}

		ipMatch := ipRegex.FindString(line)
		macMatch := macRegex.FindString(line)

		if ipMatch != "" && macMatch != "" {
			entries = append(entries, ARPEntry{
				IP:  ipMatch,
				MAC: strings.ReplaceAll(macMatch, "-", ":"),
			})
		}
	}

	return entries, scanner.Err()
}

// ParseFile reads ARP entries from a file.
func ParseFile(path string) ([]ARPEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ARP file %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ConvertToObservations converts ARP entries to host observations.
func ConvertToObservations(entries []ARPEntry, sourceID string) []observation.HostObservation {
	if sourceID == "" {
		sourceID = "arp-import"
	}
	t := time.Now().UTC()
	var observations []observation.HostObservation
	for _, e := range entries {
		observations = append(observations, observation.HostObservation{
			IPAddress:  e.IP,
			MACAddress: e.MAC,
			ObservedAt: t,
			SourceID:   sourceID,
		})
	}
	return observations
}
