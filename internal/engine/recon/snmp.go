package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// SNMPInfo represents enterprise metadata discovered via SNMP MIB querying.
type SNMPInfo struct {
	SysDescr    string `json:"sys_descr,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	Community   string `json:"community,omitempty"`
}

// ProbeSNMPDeep queries SNMPv1/v2c for standard MIB-2 System objects.
func ProbeSNMPDeep(ctx context.Context, host string, timeout time.Duration) (*SNMPInfo, error) {
	communities := []string{"public", "private", "snmp", "community"}

	for _, comm := range communities {
		info, err := querySNMPCommunity(ctx, host, comm, timeout)
		if err == nil && info != nil && info.SysDescr != "" {
			return info, nil
		}
	}

	return nil, fmt.Errorf("SNMP query yielded no response across tested communities")
}

func querySNMPCommunity(ctx context.Context, host, community string, timeout time.Duration) (*SNMPInfo, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, "161"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Construct SNMPv1 GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr)
	// OID: 1.3.6.1.2.1.1.1.0 -> 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00
	oidBytes := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	commBytes := []byte(community)

	var varbind []byte
	varbind = append(varbind, 0x30) // Sequence
	varbind = append(varbind, byte(len(oidBytes)+4))
	varbind = append(varbind, 0x06, byte(len(oidBytes))) // OID
	varbind = append(varbind, oidBytes...)
	varbind = append(varbind, 0x05, 0x00) // Null value

	var varbindList []byte
	varbindList = append(varbindList, 0x30, byte(len(varbind)))
	varbindList = append(varbindList, varbind...)

	var pdu []byte
	pdu = append(pdu, 0xa0) // GetRequest PDU
	pdu = append(pdu, byte(4+3+3+len(varbindList)))
	pdu = append(pdu, 0x02, 0x01, 0x01) // Request ID: 1
	pdu = append(pdu, 0x02, 0x01, 0x00) // Error: 0
	pdu = append(pdu, 0x02, 0x01, 0x00) // Error Index: 0
	pdu = append(pdu, varbindList...)

	var packet []byte
	packet = append(packet, 0x30) // Top-level Sequence
	packetLen := 3 + (2 + len(commBytes)) + len(pdu)
	packet = append(packet, byte(packetLen))
	packet = append(packet, 0x02, 0x01, 0x00) // SNMP version: v1 (0)
	packet = append(packet, 0x04, byte(len(commBytes)))
	packet = append(packet, commBytes...)
	packet = append(packet, pdu...)

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return nil, err
	}

	rawResp := string(buf[:n])
	// Extract readable strings
	descr := extractPrintableString(buf[:n])
	if descr != "" {
		return &SNMPInfo{
			SysDescr:  descr,
			Community: community,
		}, nil
	}

	_ = rawResp
	return nil, fmt.Errorf("no printable sysDescr")
}

func extractPrintableString(data []byte) string {
	var printable []rune
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable = append(printable, rune(b))
		}
	}
	res := string(printable)
	// Look for typical OS / Vendor signatures
	for _, sig := range []string{"Linux", "Windows", "Cisco", "Juniper", "MikroTik", "Darwin", "FreeBSD", "HP", "Canon", "Dell"} {
		if idx := strings.Index(res, sig); idx != -1 {
			extracted := res[idx:]
			if len(extracted) > 120 {
				extracted = extracted[:120]
			}
			return strings.TrimSpace(extracted)
		}
	}
	if len(res) > 30 {
		return strings.TrimSpace(res[len(res)-60:])
	}
	return ""
}
