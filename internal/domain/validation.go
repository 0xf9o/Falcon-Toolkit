// Package domain provides validation utilities for domain types.
package domain

import (
	"fmt"
	"net"
	"strings"
)

// ValidateAddress checks if the given string is a valid IPv4 or IPv6 address.
func ValidateAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address is empty")
	}
	if ip := net.ParseIP(addr); ip == nil {
		return fmt.Errorf("invalid IP address: %s", addr)
	}
	return nil
}

// ValidateCIDR checks if the given string is a valid CIDR notation.
func ValidateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("CIDR is empty")
	}
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return nil
}

// ValidatePort checks if the given port number is within the valid range.
func ValidatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be 0-65535)", port)
	}
	return nil
}

// ValidateProtocol checks if the protocol is a recognized value.
func ValidateProtocol(proto string) error {
	proto = strings.ToLower(proto)
	switch proto {
	case "tcp", "udp", "sctp", "icmp":
		return nil
	default:
		return fmt.Errorf("unknown protocol: %s", proto)
	}
}

// NormalizeProtocol returns the canonical lowercase form of a protocol.
func NormalizeProtocol(proto string) string {
	return strings.ToLower(strings.TrimSpace(proto))
}

// NormalizeAddress returns the canonical form of an IP address.
func NormalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return addr
}

// NormalizeCIDR returns the canonical form of a CIDR block.
func NormalizeCIDR(cidr string) string {
	cidr = strings.TrimSpace(cidr)
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return network.String()
}

// NormalizeHostname returns the canonical lowercase form of a hostname.
func NormalizeHostname(h string) string {
	return strings.ToLower(strings.TrimSpace(h))
}

// AddressInCIDR checks if an address falls within a CIDR block.
func AddressInCIDR(addr, cidr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}
