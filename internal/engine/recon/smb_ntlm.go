package recon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unicode/utf16"
)

// SMBTargetInfo holds enterprise metadata extracted from an unauthenticated SMB/NTLMSSP handshake.
type SMBTargetInfo struct {
	NetBIOSComputerName string `json:"netbios_computer_name,omitempty"`
	NetBIOSDomainName   string `json:"netbios_domain_name,omitempty"`
	DNSComputerName     string `json:"dns_computer_name,omitempty"`
	DNSDomainName       string `json:"dns_domain_name,omitempty"`
	ForestName          string `json:"forest_name,omitempty"`
	OSVersion           string `json:"os_version,omitempty"`
	SMBv1Enabled        bool   `json:"smbv1_enabled"`
}

// ProbeSMBTargetInfo connects to an SMB server (port 445) and parses the NTLMSSP challenge.
func ProbeSMBTargetInfo(ctx context.Context, host string, timeout time.Duration) (*SMBTargetInfo, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "445"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SMB2 Negotiate Protocol Request
	smb2Negotiate := []byte{
		0x00, 0x00, 0x00, 0x44, // NetBIOS session header (68 bytes)
		// SMB2 Header
		0xfe, 'S', 'M', 'B', // Protocol ID: \xFESMB
		0x40, 0x00, // Header length (64 bytes)
		0x00, 0x00, // Credit charge
		0x00, 0x00, // Status
		0x00, 0x00, // Command: NEGOTIATE (0)
		0x00, 0x00, // Credits requested
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next command
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID: 0
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// SMB2 Negotiate Request Body
		0x24, 0x00, // Structure size (36)
		0x02, 0x00, // Dialect count (2)
		0x01, 0x00, // Security mode (Signing enabled)
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Client start time
		0x02, 0x02, // Dialect: SMB 2.0.2
		0x10, 0x02, // Dialect: SMB 2.1
	}

	if _, err := conn.Write(smb2Negotiate); err != nil {
		return nil, fmt.Errorf("writing SMB negotiate: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 68 {
		return nil, fmt.Errorf("reading SMB negotiate response: %w", err)
	}

	// SMB2 Session Setup Request containing NTLMSSP NEGOTIATE
	ntlmsspNeg := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // Type 1 (Negotiate)
		0x05, 0xb2, 0x08, 0xa2, // Flags: Negotiate Unicode, OEM, Request Target, NTLM, Extended Security, Target Info
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain supplied (0)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation supplied (0)
		0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f, // OS Version: Windows 7 / Build 7601
	}

	secBlobLen := len(ntlmsspNeg)
	totalLen := 64 + 24 + secBlobLen // Header + SessionSetup body + SecurityBlob
	netbiosLen := totalLen

	var req bytes.Buffer
	// NetBIOS Session Header
	req.WriteByte(0x00)
	req.WriteByte(byte(netbiosLen >> 16))
	req.WriteByte(byte(netbiosLen >> 8))
	req.WriteByte(byte(netbiosLen))

	// SMB2 Header
	req.Write([]byte{0xfe, 'S', 'M', 'B'})
	req.Write([]byte{0x40, 0x00})                                     // Header len: 64
	req.Write([]byte{0x00, 0x00})                                     // Credit charge
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Status
	req.Write([]byte{0x01, 0x00})                                     // Command: SESSION_SETUP (1)
	req.Write([]byte{0x1f, 0x00})                                     // Credits requested
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Flags
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Next command
	req.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Message ID: 1
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Process ID
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Tree ID
	req.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Session ID
	req.Write(make([]byte, 16))                                       // Signature

	// SMB2 Session Setup Body
	req.Write([]byte{0x19, 0x00})                                     // Structure size: 25
	req.WriteByte(0x00)                                               // Flags
	req.WriteByte(0x01)                                               // Security Mode: USER
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Capabilities
	req.Write([]byte{0x00, 0x00, 0x00, 0x00})                         // Channel
	req.Write([]byte{0x58, 0x00})                                     // Security Buffer Offset: 88 (64 + 24)
	req.Write([]byte{byte(secBlobLen), byte(secBlobLen >> 8)})        // Security Buffer Length
	req.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Previous Session ID

	// Security Blob
	req.Write(ntlmsspNeg)

	if _, err := conn.Write(req.Bytes()); err != nil {
		return nil, fmt.Errorf("writing SMB session setup: %w", err)
	}

	respBuf := make([]byte, 4096)
	n, err = conn.Read(respBuf)
	if err != nil || n < 68 {
		return nil, fmt.Errorf("reading session setup response: %w", err)
	}

	return parseNTLMChallenge(respBuf[:n])
}

func parseNTLMChallenge(data []byte) (*SMBTargetInfo, error) {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx == -1 {
		return nil, fmt.Errorf("no NTLMSSP payload found in response")
	}

	ntlm := data[idx:]
	if len(ntlm) < 48 {
		return nil, fmt.Errorf("NTLM payload truncated")
	}

	// Message Type at offset 8 (must be Type 2 Challenge = 0x00000002)
	msgType := binary.LittleEndian.Uint32(ntlm[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("expected NTLMSSP Type 2 challenge, got type %d", msgType)
	}

	info := &SMBTargetInfo{}

	// OS Version at offset 48 (if present and flags support it)
	if len(ntlm) >= 56 {
		major := ntlm[48]
		minor := ntlm[49]
		build := binary.LittleEndian.Uint16(ntlm[50:52])
		if major > 0 {
			info.OSVersion = formatWindowsVersion(major, minor, build)
		}
	}

	// Target Info Buffer offset & length at offset 40:48
	targetInfoLen := binary.LittleEndian.Uint16(ntlm[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(ntlm[44:48])

	if int(targetInfoOffset+uint32(targetInfoLen)) <= len(ntlm) && targetInfoLen > 0 {
		tData := ntlm[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
		parseAVPairs(tData, info)
	}

	return info, nil
}

func parseAVPairs(data []byte, info *SMBTargetInfo) {
	offset := 0
	for offset+4 <= len(data) {
		avID := binary.LittleEndian.Uint16(data[offset : offset+2])
		avLen := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if avID == 0 || offset+avLen > len(data) {
			break // EOL or overflow
		}

		valBytes := data[offset : offset+avLen]
		offset += avLen

		strVal := decodeUTF16LE(valBytes)

		switch avID {
		case 1: // NetBIOS Computer Name
			info.NetBIOSComputerName = strVal
		case 2: // NetBIOS Domain Name
			info.NetBIOSDomainName = strVal
		case 3: // DNS Computer Name (FQDN)
			info.DNSComputerName = strVal
		case 4: // DNS Domain Name
			info.DNSDomainName = strVal
		case 5: // DNS Tree / Forest Name
			info.ForestName = strVal
		}
	}
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func formatWindowsVersion(major, minor byte, build uint16) string {
	base := fmt.Sprintf("Windows (Build %d)", build)
	if major == 10 && minor == 0 {
		if build >= 22000 {
			return fmt.Sprintf("Windows 11 / Server 2022 (Build %d)", build)
		}
		if build >= 17763 {
			return fmt.Sprintf("Windows 10 / Server 2019 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 10 / Server 2016 (Build %d)", build)
	}
	if major == 6 && minor == 3 {
		return fmt.Sprintf("Windows 8.1 / Server 2012 R2 (Build %d)", build)
	}
	if major == 6 && minor == 1 {
		return fmt.Sprintf("Windows 7 / Server 2008 R2 (Build %d)", build)
	}
	return fmt.Sprintf("%s %d.%d", base, major, minor)
}
