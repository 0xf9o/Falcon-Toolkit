package active

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/engine/recon"
	"github.com/falcon-toolkit/falcon/internal/schema"
	"golang.org/x/time/rate"
)

// ActiveEngine orchestrates real L4 and L7 probing across targets.
type ActiveEngine struct {
	Timeout   time.Duration
	Workers   int
	RateLimit int
	Evasion   bool
}

// NewActiveEngine initializes a concurrency-safe active probing engine.
func NewActiveEngine(timeout time.Duration, workers, rateLimit int, evasion bool) *ActiveEngine {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if workers <= 0 {
		workers = 25
	}
	if rateLimit <= 0 {
		rateLimit = 100
	}
	return &ActiveEngine{
		Timeout:   timeout,
		Workers:   workers,
		RateLimit: rateLimit,
		Evasion:   evasion,
	}
}

// ProbeHost evaluates a list of ports on a target IP and returns detailed ServiceProbeResult entries.
func (e *ActiveEngine) ProbeHost(ctx context.Context, host string, ports []int) []schema.ServiceProbeResult {
	limiter := rate.NewLimiter(rate.Limit(e.RateLimit), 10)
	jobs := make(chan int, len(ports))
	results := make(chan schema.ServiceProbeResult, len(ports))

	var wg sync.WaitGroup
	workerCount := e.Workers
	if workerCount > len(ports) {
		workerCount = len(ports)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					_ = limiter.Wait(ctx)
					res := e.probeService(ctx, host, port)
					results <- res
				}
			}
		}()
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)

	wg.Wait()
	close(results)

	var output []schema.ServiceProbeResult
	for res := range results {
		output = append(output, res)
	}
	return output
}

// probeService attempts an actual socket connection and extracts banners/TLS info.
func (e *ActiveEngine) probeService(ctx context.Context, host string, port int) schema.ServiceProbeResult {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	result := schema.ServiceProbeResult{
		Protocol:    "tcp",
		Port:        port,
		ServiceName: defaultServiceName(port),
		State:       schema.StateFiltered,
		LatencyMs:   0,
	}

	dialer := &net.Dialer{
		Timeout: e.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = schema.StateFiltered
		} else if strings.Contains(err.Error(), "refused") {
			result.State = schema.StateIsolated
		} else {
			result.State = schema.StateFiltered
		}
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()

	result.State = schema.StateOpen
	result.LatencyMs = time.Since(start).Milliseconds()

	// 1. Inspect TLS if applicable or standard HTTPS/TLS port
	if isTLSPort(port) {
		tlsDetails := e.inspectTLS(addr)
		if len(tlsDetails) > 0 {
			result.TLSDetails = tlsDetails
			if cn, ok := tlsDetails["subject_cn"]; ok && cn != "" {
				result.Banner = fmt.Sprintf("TLS Certificate: %s (Issuer: %s)", cn, tlsDetails["issuer"])
			}
			return result
		}
	}

	// 2. Protocol Handshakes & Banner Grabbing
	banner := e.grabBanner(conn, port, host)
	if banner != "" {
		result.Banner = banner
		if detected := identifyFromBanner(port, banner); detected != "" {
			result.ServiceName = detected
		}
	}

	// 3. Deep Protocol Intelligence Extraction
	switch port {
	case 445:
		if smbInfo, err := recon.ProbeSMBTargetInfo(context.Background(), host, e.Timeout); err == nil && smbInfo != nil {
			var details []string
			if smbInfo.NetBIOSComputerName != "" {
				details = append(details, "NetBIOS: "+smbInfo.NetBIOSComputerName)
			}
			if smbInfo.DNSDomainName != "" {
				details = append(details, "Domain: "+smbInfo.DNSDomainName)
			}
			if smbInfo.OSVersion != "" {
				details = append(details, "OS: "+smbInfo.OSVersion)
			}
			if len(details) > 0 {
				result.Banner = strings.Join(details, " | ")
				result.ServiceName = "Microsoft-DS (SMB)"
			}
		}

	case 502:
		if ics, err := recon.ProbeModbusDeviceID(context.Background(), host, e.Timeout); err == nil && ics != nil {
			result.ServiceName = "Modbus-TCP (SCADA)"
			if ics.Details != "" {
				result.Banner = ics.Details
			}
		}

	case 102:
		if s7, err := recon.ProbeS7commPLC(context.Background(), host, e.Timeout); err == nil && s7 != nil {
			result.ServiceName = "Siemens-S7 (ICS)"
			if s7.Details != "" {
				result.Banner = s7.Details
			}
		}
	}

	return result
}

func (e *ActiveEngine) inspectTLS(addr string) map[string]string {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{Timeout: e.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	details := make(map[string]string)
	details["subject_cn"] = cert.Subject.CommonName
	details["issuer"] = cert.Issuer.CommonName
	details["valid_from"] = cert.NotBefore.Format(time.RFC3339)
	details["valid_to"] = cert.NotAfter.Format(time.RFC3339)
	if len(cert.DNSNames) > 0 {
		details["sans"] = strings.Join(cert.DNSNames, ", ")
	}
	if len(state.NegotiatedProtocol) > 0 {
		details["alpn"] = state.NegotiatedProtocol
	}

	return details
}

func (e *ActiveEngine) grabBanner(conn net.Conn, port int, host string) string {
	_ = conn.SetDeadline(time.Now().Add(e.Timeout))

	switch port {
	case 80, 8080, 8000, 8888, 3000, 5000:
		// Send HTTP GET request
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Falcon/4.0\r\nConnection: close\r\n\r\n", host)
		_, _ = conn.Write([]byte(req))

	case 21, 22, 25, 110, 143:
		// Passive read server greeting without write

	case 445:
		// Send SMBv2 Negotiate Protocol Request
		smbNegotiate := []byte{
			0x00, 0x00, 0x00, 0x44, // NetBIOS session header
			0xfe, 0x53, 0x4d, 0x42, // SMB2 Magic: \xFFSMB
			0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x24, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x02, 0x02, 0x10, 0x02, // Dialects: SMB 2.0.2, SMB 2.1
		}
		_, _ = conn.Write(smbNegotiate)

	default:
		// Send generic line break to trigger banner
		_, _ = conn.Write([]byte("\r\n"))
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	banner := strings.TrimSpace(string(buf[:n]))
	// Sanitize output for single-line display
	banner = strings.ReplaceAll(banner, "\r", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	for strings.Contains(banner, "  ") {
		banner = strings.ReplaceAll(banner, "  ", " ")
	}
	if len(banner) > 120 {
		banner = banner[:120] + "..."
	}
	return banner
}

// ProbeUDP targeted check for DNS, NTP, and SNMP.
func (e *ActiveEngine) ProbeUDP(ctx context.Context, host string, port int) schema.ServiceProbeResult {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	result := schema.ServiceProbeResult{
		Protocol:    "udp",
		Port:        port,
		ServiceName: defaultServiceName(port),
		State:       schema.StateFiltered,
		LatencyMs:   0,
	}

	conn, err := net.DialTimeout("udp", addr, e.Timeout)
	if err != nil {
		result.State = schema.StateIsolated
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(e.Timeout))

	var payload []byte
	switch port {
	case 53:
		// Real DNS Query for Root (.) A record
		txID := make([]byte, 2)
		_, _ = rand.Read(txID)
		payload = append(payload, txID...)
		payload = append(payload, []byte{
			0x01, 0x00, // Standard query
			0x00, 0x01, // 1 question
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00,       // Root domain
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
		}...)

	case 123:
		// Real NTP Client Request (Mode 3)
		payload = make([]byte, 48)
		payload[0] = 0x1B // LI=0, VN=3, Mode=3 (client)

	case 161:
		// Real SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) with community 'public'
		payload = []byte{
			0x30, 0x26, // SEQUENCE of 38 bytes
			0x02, 0x01, 0x00, // Version: 1
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: "public"
			0xa0, 0x19, // GetRequest-PDU
			0x02, 0x04, 0x01, 0x02, 0x03, 0x04, // Request ID
			0x02, 0x01, 0x00, // Error Status: 0
			0x02, 0x01, 0x00, // Error Index: 0
			0x30, 0x0b, // Variable Bindings
			0x30, 0x09,
			0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1
			0x05, 0x00, // NULL value
		}

	default:
		payload = []byte("\x00\x00\x00\x00")
	}

	_, err = conn.Write(payload)
	if err != nil {
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err == nil && n > 0 {
		result.State = schema.StateOpen
		result.LatencyMs = time.Since(start).Milliseconds()
		if port == 53 && n > 2 {
			result.Banner = "DNS Server responded to Root query"
		} else if port == 123 && n >= 48 {
			result.Banner = fmt.Sprintf("NTP Stratum %d server response", resp[1])
		} else if port == 161 {
			result.Banner = "SNMP agent active"
			if snmpInfo, err := recon.ProbeSNMPDeep(ctx, host, e.Timeout); err == nil && snmpInfo != nil {
				result.Banner = fmt.Sprintf("SNMP [%s]: %s", snmpInfo.Community, snmpInfo.SysDescr)
			}
		} else if port == 47808 {
			if bacnet, err := recon.ProbeBACnetWhoIs(ctx, host, e.Timeout); err == nil && bacnet != nil {
				result.Banner = bacnet.Details
				result.ServiceName = bacnet.Protocol
			}
		}
	}

	return result
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 636, 993, 995, 465, 5986:
		return true
	default:
		return false
	}
}

func defaultServiceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 88:
		return "kerberos"
	case 110:
		return "pop3"
	case 123:
		return "ntp"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 502:
		return "modbus"
	case 636:
		return "ldaps"
	case 1433:
		return "ms-sql-s"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "ms-wbt-server"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 5985:
		return "wsman-http"
	case 5986:
		return "wsman-https"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 9200:
		return "elasticsearch"
	default:
		return fmt.Sprintf("tcp-%d", port)
	}
}

var (
	sshRegex    = regexp.MustCompile(`(?i)^SSH-[\d.]+-(.+)`)
	apacheRegex = regexp.MustCompile(`(?i)Apache/([\d.]+)`)
	nginxRegex  = regexp.MustCompile(`(?i)nginx/([\d.]+)`)
	iisRegex    = regexp.MustCompile(`(?i)Microsoft-IIS/([\d.]+)`)
)

func identifyFromBanner(port int, banner string) string {
	if m := sshRegex.FindStringSubmatch(banner); len(m) > 1 {
		return fmt.Sprintf("OpenSSH (%s)", m[1])
	}
	if m := apacheRegex.FindStringSubmatch(banner); len(m) > 1 {
		return fmt.Sprintf("Apache HTTP Server %s", m[1])
	}
	if m := nginxRegex.FindStringSubmatch(banner); len(m) > 1 {
		return fmt.Sprintf("nginx %s", m[1])
	}
	if m := iisRegex.FindStringSubmatch(banner); len(m) > 1 {
		return fmt.Sprintf("Microsoft IIS %s", m[1])
	}
	return ""
}

// Suppress unused warning
var _ = binary.BigEndian
