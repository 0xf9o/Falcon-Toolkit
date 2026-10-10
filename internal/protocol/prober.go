package protocol

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// Prober provides active, safe protocol verification probes.
type Prober struct {
	Timeout time.Duration
}

// NewProber creates a new safe protocol prober.
func NewProber(timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Prober{
		Timeout: timeout,
	}
}

// ProbeService probes an address and port, returning reachability state and probe context.
func (p *Prober) ProbeService(ctx context.Context, host string, port int) (ProbeContext, domain.ReachabilityState, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: p.Timeout}

	pCtx := ProbeContext{
		Port:     port,
		Protocol: "tcp",
		Headers:  make(map[string]string),
	}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		state := classifyDialError(err)
		pCtx.Reachability = state
		return pCtx, state, nil
	}
	defer conn.Close()

	pCtx.Reachability = domain.ReachReachable

	// Protocol-specific safe verification payloads
	_ = conn.SetDeadline(time.Now().Add(p.Timeout))

	switch port {
	case 6379: // Redis
		_, _ = conn.Write([]byte("PING\r\n"))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			pCtx.Banner = strings.TrimSpace(string(buf[:n]))
			pCtx.RawResponse = string(buf[:n])
		}

	case 502: // Modbus/TCP safe probe: Read Device Identification (Func 43/14)
		// MBAP Header (Transaction ID: 0001, Protocol: 0000, Length: 0005, Unit: 01) + Func 43
		modbusReq := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2b, 0x0e, 0x01, 0x00}
		_, _ = conn.Write(modbusReq)
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n >= 7 && buf[2] == 0x00 && buf[3] == 0x00 { // Valid Modbus protocol ID
			pCtx.RawResponse = "modbus"
			pCtx.Banner = "Modbus/TCP protocol response"
		}

	case 102: // S7 / COTP Connection Request
		// COTP Connection Request TPDU
		cotpCR := []byte{
			0x03, 0x00, 0x00, 0x16, // TPKT (len 22)
			0x11,       // COTP len 17
			0xe0,       // CR TPDU
			0x00, 0x00, // Dest ref
			0x00, 0x01, // Src ref
			0x00,                   // Class 0
			0xc1, 0x02, 0x01, 0x00, // Src TSAP
			0xc2, 0x02, 0x01, 0x02, // Dst TSAP
		}
		_, _ = conn.Write(cotpCR)
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n >= 4 && buf[0] == 0x03 && buf[1] == 0x00 { // TPKT response
			pCtx.RawResponse = "s7-cotp"
			pCtx.Banner = "Siemens S7 / COTP response"
		}

	case 4840: // OPC UA Hello (HEL)
		// OPC UA Message: "HEL" + MessageSize (32) + Version + ReceiveBuf + SendBuf + MaxMessageSize + MaxChunkCount + EndpointUrl
		opcuaHel := []byte{
			'H', 'E', 'L', 'F',
			0x20, 0x00, 0x00, 0x00, // Size 32
			0x00, 0x00, 0x00, 0x00, // Version
			0x00, 0x10, 0x00, 0x00, // RecvBuf
			0x00, 0x10, 0x00, 0x00, // SendBuf
			0x00, 0x00, 0x01, 0x00, // MaxMsgSize
			0x00, 0x00, 0x00, 0x00, // MaxChunkCount
			0x00, 0x00, 0x00, 0x00, // EndpointUrl length 0
		}
		_, _ = conn.Write(opcuaHel)
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n >= 4 && bytes.HasPrefix(buf, []byte("ACK")) {
			pCtx.RawResponse = "opcua"
			pCtx.Banner = "OPC UA protocol response (ACK)"
		}

	default:
		// Generic passive banner read (e.g. SSH, FTP, SMTP send banner automatically)
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			clean := strings.Map(func(r rune) rune {
				if r >= 32 && r < 127 {
					return r
				}
				return -1
			}, string(buf[:n]))
			pCtx.Banner = strings.TrimSpace(clean)
		}
	}

	return pCtx, domain.ReachReachable, nil
}

// classifyDialError maps net.Dial errors to precise ReachabilityState constants.
func classifyDialError(err error) domain.ReachabilityState {
	if err == nil {
		return domain.ReachReachable
	}

	errStr := strings.ToLower(err.Error())

	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "actively refused") {
		return domain.ReachRefused
	}
	if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "deadline exceeded") {
		return domain.ReachTimeout
	}
	if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
		return domain.ReachUnreachable
	}
	if strings.Contains(errStr, "host is down") {
		return domain.ReachNoResponse
	}

	return domain.ReachError
}
