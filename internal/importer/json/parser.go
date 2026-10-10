// Package jsonparser provides JSON format parsing for the Falcon ingestion pipeline.
package jsonparser

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
)

// JSONDocument represents the root structure of a Falcon JSON observation document.
type JSONDocument struct {
	Version   string        `json:"version"`
	Source    string        `json:"source"`
	Timestamp string        `json:"timestamp"`
	Hosts     []JSONHost    `json:"hosts"`
	Networks  []JSONNetwork `json:"networks"`
}

// JSONHost represents a host entity in a JSON document.
type JSONHost struct {
	IPAddress  string        `json:"ip_address"`
	MACAddress string        `json:"mac_address,omitempty"`
	Hostname   string        `json:"hostname,omitempty"`
	Services   []JSONService `json:"services,omitempty"`
	Tags       []string      `json:"tags,omitempty"`
}

// JSONService represents a service on a host in a JSON document.
type JSONService struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	State       string `json:"state"`
	ServiceName string `json:"service_name,omitempty"`
	Technology  string `json:"technology,omitempty"`
	Version     string `json:"version,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

// JSONNetwork represents a network segment in a JSON document.
type JSONNetwork struct {
	CIDR        string `json:"cidr"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Parse parses a Falcon JSON file from an io.Reader.
func Parse(r io.Reader) (*JSONDocument, error) {
	var doc JSONDocument
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding JSON observation: %w", err)
	}
	return &doc, nil
}

// ParseFile parses a Falcon JSON file from disk.
func ParseFile(path string) (*JSONDocument, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ConvertToObservations converts a parsed JSONDocument into domain observations.
func (doc *JSONDocument) ConvertToObservations() ([]observation.HostObservation, []observation.NetworkObservation) {
	sourceID := doc.Source
	if sourceID == "" {
		sourceID = "json-import"
	}

	t := time.Now().UTC()
	if doc.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, doc.Timestamp); err == nil {
			t = parsed
		}
	}

	var hostObs []observation.HostObservation
	for _, h := range doc.Hosts {
		var services []observation.ServiceObservation
		for _, s := range h.Services {
			state := domain.ServiceStateOpen
			if s.State != "" {
				state = domain.ServiceState(s.State)
			}
			services = append(services, observation.ServiceObservation{
				Protocol:    s.Protocol,
				Port:        s.Port,
				State:       state,
				ServiceName: s.ServiceName,
				Technology:  s.Technology,
				Version:     s.Version,
				Description: s.Banner,
			})
		}

		hostObs = append(hostObs, observation.HostObservation{
			IPAddress:  h.IPAddress,
			MACAddress: h.MACAddress,
			Hostname:   h.Hostname,
			ObservedAt: t,
			SourceID:   sourceID,
			Services:   services,
			Tags:       h.Tags,
		})
	}

	var netObs []observation.NetworkObservation
	for _, n := range doc.Networks {
		netObs = append(netObs, observation.NetworkObservation{
			CIDR:        n.CIDR,
			Name:        n.Name,
			Description: n.Description,
			ObservedAt:  t,
			SourceID:    sourceID,
		})
	}

	return hostObs, netObs
}
