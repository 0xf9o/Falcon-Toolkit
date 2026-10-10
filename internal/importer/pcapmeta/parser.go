// Package pcapmeta provides flow metadata parsing from PCAP analysis tools.
package pcapmeta

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/protocol"
)

// PCAPFlow represents a recorded network session / flow summary.
type PCAPFlow struct {
	SourceIP   string `json:"source_ip"`
	SourcePort int    `json:"source_port"`
	DestIP     string `json:"dest_ip"`
	DestPort   int    `json:"dest_port"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
}

// PCAPDocument represents a JSON container of flows.
type PCAPDocument struct {
	Flows []PCAPFlow `json:"flows"`
}

// Parse parses PCAP flow metadata JSON from an io.Reader.
func Parse(r io.Reader) (*PCAPDocument, error) {
	var doc PCAPDocument
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding PCAP JSON: %w", err)
	}
	return &doc, nil
}

// ParseFile parses PCAP flow metadata from disk.
func ParseFile(path string) (*PCAPDocument, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening PCAP meta file %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ConvertToObservations converts PCAP flows to host and service observations.
func (doc *PCAPDocument) ConvertToObservations(sourceID string) []observation.HostObservation {
	if sourceID == "" {
		sourceID = "pcap-meta"
	}
	now := time.Now().UTC()

	hostMap := make(map[string]*observation.HostObservation)

	for _, flow := range doc.Flows {
		t := now
		if flow.Timestamp != "" {
			if parsed, err := time.Parse(time.RFC3339, flow.Timestamp); err == nil {
				t = parsed
			}
		}

		// Record Server/Destination Host & Service
		if flow.DestIP != "" {
			host, exists := hostMap[flow.DestIP]
			if !exists {
				host = &observation.HostObservation{
					IPAddress:  flow.DestIP,
					ObservedAt: t,
					SourceID:   sourceID,
				}
				hostMap[flow.DestIP] = host
			}

			if flow.DestPort > 0 {
				svcName := flow.Service
				if svcName == "" {
					identifier := protocol.NewIdentifier()
					protoRes := identifier.Identify(protocol.ProbeContext{
						Port:     flow.DestPort,
						Protocol: flow.Protocol,
					})
					if protoRes.Protocol != "" {
						svcName = strings.ToLower(protoRes.Protocol)
					}
				}
				host.Services = append(host.Services, observation.ServiceObservation{
					Protocol:    flow.Protocol,
					Port:        flow.DestPort,
					State:       domain.ServiceStateOpen,
					ServiceName: svcName,
				})
			}
		}

		// Record Client/Source Host
		if flow.SourceIP != "" {
			if _, exists := hostMap[flow.SourceIP]; !exists {
				hostMap[flow.SourceIP] = &observation.HostObservation{
					IPAddress:  flow.SourceIP,
					ObservedAt: t,
					SourceID:   sourceID,
				}
			}
		}
	}

	var results []observation.HostObservation
	for _, h := range hostMap {
		results = append(results, *h)
	}
	return results
}
