package recon

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ICSDeviceProfile represents industrial control system metadata.
type ICSDeviceProfile struct {
	Protocol    string `json:"protocol"`
	Vendor      string `json:"vendor,omitempty"`
	ProductCode string `json:"product_code,omitempty"`
	Revision    string `json:"revision,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	Details     string `json:"details,omitempty"`
}

// ProbeModbusDeviceID sends a Modbus-TCP Read Device Identification request (FC 43/14).
func ProbeModbusDeviceID(ctx context.Context, host string, timeout time.Duration) (*ICSDeviceProfile, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "502"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Modbus-TCP: Transaction ID (0x0001), Protocol (0x0000), Length (5), Unit ID (0x01)
	// Function Code: 0x2B (Encapsulated Interface Transport), MEI Type: 0x0E (Read Device Identification)
	// Read Device ID code: 0x01 (Basic), Object ID: 0x00 (VendorName)
	req := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID
		0x00, 0x05, // Length: 5 bytes
		0x01, // Unit ID
		0x2b, // Function Code (43)
		0x0e, // MEI Type (14)
		0x01, // Read Device ID code (Basic)
		0x00, // Object ID
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("writing Modbus request: %w", err)
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 10 {
		return nil, fmt.Errorf("reading Modbus response: %w", err)
	}

	profile := &ICSDeviceProfile{
		Protocol: "Modbus-TCP",
	}

	// Check function code in response (offset 7)
	if resp[7] == 0x2b && n > 14 {
		numObjects := int(resp[13])
		offset := 14
		for i := 0; i < numObjects && offset+2 < n; i++ {
			objID := resp[offset]
			objLen := int(resp[offset+1])
			offset += 2
			if offset+objLen <= n {
				val := string(resp[offset : offset+objLen])
				offset += objLen
				switch objID {
				case 0:
					profile.Vendor = val
				case 1:
					profile.ProductCode = val
				case 2:
					profile.Revision = val
				}
			}
		}
	}

	if profile.Vendor == "" && profile.ProductCode == "" {
		profile.Details = "Modbus-TCP Listener Active (Port 502)"
	} else {
		profile.Details = fmt.Sprintf("Vendor: %s | Model: %s | Rev: %s", profile.Vendor, profile.ProductCode, profile.Revision)
	}

	return profile, nil
}

// ProbeS7commPLC initiates a Siemens S7comm Setup Communication handshake on port 102.
func ProbeS7commPLC(ctx context.Context, host string, timeout time.Duration) (*ICSDeviceProfile, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "102"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: ISO on TCP Connection Request (COTP CR)
	cotpCR := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT Header (len 22)
		0x11,       // COTP Length
		0xe0,       // COTP CR (Connection Request)
		0x00, 0x00, // Destination Ref
		0x00, 0x01, // Source Ref
		0x00,                   // Class 0
		0xc1, 0x02, 0x01, 0x00, // Calling TSAP (Rack 0, Slot 2)
		0xc2, 0x02, 0x01, 0x02, // Called TSAP
		0xc0, 0x01, 0x09, // TPDU Size (512)
	}

	if _, err := conn.Write(cotpCR); err != nil {
		return nil, fmt.Errorf("writing S7 COTP CR: %w", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 7 || buf[5] != 0xd0 { // 0xD0 = COTP CC (Connection Confirm)
		return nil, fmt.Errorf("invalid COTP CC response")
	}

	// Step 2: S7comm Setup Communication Request
	s7Setup := []byte{
		0x03, 0x00, 0x00, 0x19, // TPKT Header (len 25)
		0x02, 0xf0, 0x80, // COTP DT (Data)
		0x32,       // S7 Protocol ID: 0x32
		0x01,       // Message Type: JOB (1)
		0x00, 0x00, // Reserved
		0x00, 0x01, // PDU Reference: 1
		0x00, 0x08, // Parameter Length: 8
		0x00, 0x00, // Data Length: 0
		// Parameter: Setup Communication (0xF0)
		0xf0, 0x00, // Function: 0xF0
		0x00, 0x01, // Max AMQ Caller: 1
		0x00, 0x01, // Max AMQ Callee: 1
		0x01, 0xe0, // PDU Length: 480
	}

	if _, err := conn.Write(s7Setup); err != nil {
		return nil, fmt.Errorf("writing S7 Setup request: %w", err)
	}

	n, err = conn.Read(buf)
	if err != nil || n < 19 || buf[7] != 0x32 {
		return nil, fmt.Errorf("invalid S7 Setup response")
	}

	pduLen := binary.BigEndian.Uint16(buf[17:19])
	return &ICSDeviceProfile{
		Protocol: "Siemens S7comm",
		Vendor:   "Siemens",
		Details:  fmt.Sprintf("Siemens Simatic S7 PLC (Max Negotiated PDU: %d bytes)", pduLen),
	}, nil
}

// ProbeBACnetWhoIs sends a standard BACnet/IP Who-Is broadcast query to port 47808 (BAC0).
func ProbeBACnetWhoIs(ctx context.Context, host string, timeout time.Duration) (*ICSDeviceProfile, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, "47808"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// BVLL (BACnet Virtual Link Layer) + NPDU + APDU (Who-Is Unconfirmed Request)
	whoIs := []byte{
		0x81, 0x0a, 0x00, 0x0c, // BVLL: Type BACnet/IP (0x81), Function Original-Unicast-NPDU (0x0A), Length 12
		0x01, 0x20, 0xff, 0xff, 0x00, 0xff, // NPDU: Version 1, Control (DNET=65535 broadcast), HopCount 255
		0x10, 0x08, // APDU: Unconfirmed Request (0x10), Service: Who-Is (0x08)
	}

	if _, err := conn.Write(whoIs); err != nil {
		return nil, fmt.Errorf("writing BACnet Who-Is: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return nil, fmt.Errorf("no BACnet response: %w", err)
	}

	if buf[0] == 0x81 {
		return &ICSDeviceProfile{
			Protocol: "BACnet/IP (Building Automation)",
			Details:  "BACnet Device Responding to Who-Is Discovery (Port 47808)",
		}, nil
	}

	return nil, fmt.Errorf("unrecognized BACnet packet")
}
