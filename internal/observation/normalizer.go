// Package observation provides the ingestion, normalization, and identity resolution pipeline.
package observation

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Normalizer standardizes network addresses, ports, and protocols.
type Normalizer struct{}

// NewNormalizer creates a new Normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeIP parses and canonicalizes an IP address (IPv4 or IPv6).
func (n *Normalizer) NormalizeIP(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	// Clean up potential IPv4 leading zeros (e.g. 192.168.001.010 -> 192.168.1.10)
	if strings.Contains(raw, ".") && !strings.Contains(raw, ":") {
		parts := strings.Split(raw, ".")
		if len(parts) == 4 {
			var cleanParts []string
			for _, p := range parts {
				val, err := strconv.Atoi(p)
				if err != nil || val < 0 || val > 255 {
					return "", false
				}
				cleanParts = append(cleanParts, fmt.Sprintf("%d", val))
			}
			raw = strings.Join(cleanParts, ".")
		}
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

// NormalizeCIDR parses and canonicalizes a CIDR notation string.
func (n *Normalizer) NormalizeCIDR(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		normIP, ok := n.NormalizeIP(raw)
		if !ok {
			return "", false
		}
		ip := net.ParseIP(normIP)
		if ip.To4() != nil {
			return normIP + "/32", true
		}
		return normIP + "/128", true
	}
	return ipNet.String(), true
}

// NormalizeMAC standardizes MAC address format to lowercase colon-delimited (aa:bb:cc:dd:ee:ff).
func (n *Normalizer) NormalizeMAC(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	hw, err := net.ParseMAC(raw)
	if err != nil {
		return "", false
	}
	return hw.String(), true
}

// NormalizePort parses and validates a port number string or int.
func (n *Normalizer) NormalizePort(raw interface{}) (int, bool) {
	switch v := raw.(type) {
	case int:
		if v >= 1 && v <= 65535 {
			return v, true
		}
		return 0, false
	case float64:
		port := int(v)
		if port >= 1 && port <= 65535 {
			return port, true
		}
		return 0, false
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || p < 1 || p > 65535 {
			return 0, false
		}
		return p, true
	default:
		return 0, false
	}
}

// NormalizeProtocol standardizes protocol names to lowercase (e.g. "TCP" -> "tcp", "UDP" -> "udp").
func (n *Normalizer) NormalizeProtocol(raw string) string {
	proto := strings.ToLower(strings.TrimSpace(raw))
	switch proto {
	case "tcp", "udp", "icmp", "sctp", "gre", "ipsec":
		return proto
	default:
		if proto == "" {
			return "tcp"
		}
		return proto
	}
}

// NormalizeHostname lowercases and trims hostname string.
func (n *Normalizer) NormalizeHostname(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
