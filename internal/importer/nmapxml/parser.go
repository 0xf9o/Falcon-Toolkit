// Package nmapxml provides Nmap XML output parsing for the Falcon ingestion pipeline.
package nmapxml

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
)

// NmapRun represents the root of an Nmap XML output.
type NmapRun struct {
	XMLName string     `xml:"nmaprun"`
	Start   string     `xml:"start,attr"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a scanned host in Nmap XML.
type NmapHost struct {
	Status    NmapStatus     `xml:"status"`
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     []NmapPort     `xml:"ports>port"`
}

// NmapStatus represents host status (up/down).
type NmapStatus struct {
	State string `xml:"state,attr"`
}

// NmapAddress represents an IP or MAC address.
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// NmapHostname represents a resolved or user-specified hostname.
type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// NmapPort represents a port element.
type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// NmapState represents port state (open, closed, filtered).
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService represents service detection details.
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// Parse parses Nmap XML from an io.Reader.
func Parse(r io.Reader) (*NmapRun, error) {
	var run NmapRun
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&run); err != nil {
		return nil, fmt.Errorf("parsing Nmap XML: %w", err)
	}
	return &run, nil
}

// ParseFile parses Nmap XML from a file path.
func ParseFile(path string) (*NmapRun, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening Nmap XML %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ConvertToObservations translates NmapRun into domain observations.
func (run *NmapRun) ConvertToObservations(sourceID string) []observation.HostObservation {
	if sourceID == "" {
		sourceID = "nmap-xml"
	}

	t := time.Now().UTC()
	if startSec, err := strconv.ParseInt(run.Start, 10, 64); err == nil && startSec > 0 {
		t = time.Unix(startSec, 0).UTC()
	}

	var observations []observation.HostObservation

	for _, h := range run.Hosts {
		if h.Status.State != "up" && h.Status.State != "" {
			continue
		}

		var ip, mac string
		for _, addr := range h.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if ip == "" {
					ip = addr.Addr
				}
			case "mac":
				mac = addr.Addr
			}
		}

		var hostname string
		if len(h.Hostnames) > 0 {
			hostname = h.Hostnames[0].Name
		}

		var services []observation.ServiceObservation
		for _, p := range h.Ports {
			state := domain.ServiceStateOpen
			switch p.State.State {
			case "open":
				state = domain.ServiceStateOpen
			case "closed":
				state = domain.ServiceStateClosed
			case "filtered":
				state = domain.ServiceStateFiltered
			default:
				state = domain.ServiceStateUnknown
			}

			services = append(services, observation.ServiceObservation{
				Protocol:    p.Protocol,
				Port:        p.PortID,
				State:       state,
				ServiceName: p.Service.Name,
				Technology:  p.Service.Product,
				Version:     p.Service.Version,
			})
		}

		observations = append(observations, observation.HostObservation{
			IPAddress:  ip,
			MACAddress: mac,
			Hostname:   hostname,
			ObservedAt: t,
			SourceID:   sourceID,
			Services:   services,
		})
	}

	return observations
}
