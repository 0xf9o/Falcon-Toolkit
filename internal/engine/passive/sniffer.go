package passive

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DiscoveredNode encapsulates a host discovered silently through broadcast/multicast traffic.
type DiscoveredNode struct {
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Protocol  string    `json:"protocol"`
	Timestamp time.Time `json:"timestamp"`
}

// PassiveSniffer listens passively on standard discovery ports without generating active probes.
type PassiveSniffer struct {
	mu          sync.RWMutex
	discovered  map[string]DiscoveredNode
	onDiscovery func(node DiscoveredNode)
}

// NewPassiveSniffer initializes the passive listening engine.
func NewPassiveSniffer(callback func(node DiscoveredNode)) *PassiveSniffer {
	return &PassiveSniffer{
		discovered:  make(map[string]DiscoveredNode),
		onDiscovery: callback,
	}
}

// Start begins real background listeners on LLMNR, mDNS, and NetBIOS.
func (ps *PassiveSniffer) Start(ctx context.Context) error {
	var wg sync.WaitGroup

	// 1. LLMNR Listener (UDP 5355 on 224.0.0.252)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ps.listenMulticast(ctx, "224.0.0.252:5355", "LLMNR", parseLLMNRName)
	}()

	// 2. mDNS Listener (UDP 5353 on 224.0.0.251)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ps.listenMulticast(ctx, "224.0.0.251:5353", "mDNS", parseMDNSName)
	}()

	// 3. NetBIOS Name Service (UDP 137 on 0.0.0.0)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ps.listenUDP(ctx, "0.0.0.0:137", "NetBIOS-NS", parseNetBIOSName)
	}()

	return nil
}

func (ps *PassiveSniffer) listenMulticast(ctx context.Context, addrStr string, proto string, nameParser func([]byte) string) {
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		return
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		// Fallback to standard UDP listen on port if multicast binding fails
		ps.listenUDP(ctx, fmt.Sprintf("0.0.0.0:%d", addr.Port), proto, nameParser)
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			hostname := nameParser(buf[:n])
			ps.recordDiscovery(src.IP.String(), hostname, proto)
		}
	}
}

func (ps *PassiveSniffer) listenUDP(ctx context.Context, addrStr string, proto string, nameParser func([]byte) string) {
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			hostname := nameParser(buf[:n])
			ps.recordDiscovery(src.IP.String(), hostname, proto)
		}
	}
}

func (ps *PassiveSniffer) recordDiscovery(ip, hostname, proto string) {
	if ip == "" || ip == "0.0.0.0" {
		return
	}

	ps.mu.Lock()
	node := DiscoveredNode{
		IP:        ip,
		Hostname:  hostname,
		Protocol:  proto,
		Timestamp: time.Now().UTC(),
	}
	ps.discovered[ip] = node
	ps.mu.Unlock()

	if ps.onDiscovery != nil {
		ps.onDiscovery(node)
	}
}

// GetDiscoveredNodes returns all passively observed nodes.
func (ps *PassiveSniffer) GetDiscoveredNodes() []DiscoveredNode {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var nodes []DiscoveredNode
	for _, n := range ps.discovered {
		nodes = append(nodes, n)
	}
	return nodes
}

// parseLLMNRName extracts the requested query name from an LLMNR packet header.
func parseLLMNRName(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	// Skip 12-byte header, parse DNS question label sequence
	offset := 12
	var labels []string
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			break
		}
		offset++
		if offset+length > len(data) {
			break
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".")
}

// parseMDNSName extracts mDNS instance name.
func parseMDNSName(data []byte) string {
	return parseLLMNRName(data)
}

// parseNetBIOSName decodes the encoded NetBIOS name from a Name Query packet.
func parseNetBIOSName(data []byte) string {
	if len(data) < 50 {
		return ""
	}
	// Question section starts at offset 12
	offset := 12
	if offset >= len(data) || data[offset] != 32 {
		return ""
	}
	offset++ // Skip 32-byte label length marker
	if offset+32 > len(data) {
		return ""
	}

	// NetBIOS name encoding: each character is split into two nibbles + 0x41 ('A')
	var decoded strings.Builder
	for i := 0; i < 32; i += 2 {
		ch1 := data[offset+i] - 'A'
		ch2 := data[offset+i+1] - 'A'
		char := (ch1 << 4) | ch2
		if char >= 32 && char <= 126 {
			decoded.WriteByte(char)
		}
	}
	return strings.TrimSpace(decoded.String())
}
