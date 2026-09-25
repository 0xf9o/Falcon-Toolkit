package modules

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"falcon/internal/db"
	"falcon/internal/engine"
	"falcon/internal/ui"
)

// ScanOptions configures the port scanner behavior.
type ScanOptions struct {
	Target      string
	Ports       []int
	Workers     int
	TimeoutMs   int
	RateLimit   int
	Workspace   string
	Store       *db.Store
	OnOpenFound func(db.PortRecord)
}

// Common service ports mapping for initial identification
var wellKnownPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	135:  "RPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MSSQL",
	1521: "Oracle",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	6379: "Redis",
	8080: "HTTP-Proxy",
	8443: "HTTPS-Alt",
	27017: "MongoDB",
}

// RunPortScan orchestrates high-speed concurrent port scanning against a target.
func RunPortScan(ctx context.Context, opts ScanOptions) ([]db.PortRecord, error) {
	if opts.Workers <= 0 {
		opts.Workers = 50
	}
	if opts.TimeoutMs <= 0 {
		opts.TimeoutMs = 1000
	}

	var limiter engine.RateLimiter
	if opts.RateLimit > 0 {
		tb := engine.NewTokenBucketLimiter(opts.RateLimit, opts.RateLimit/2+1)
		defer tb.Stop()
		limiter = tb
	}

	poolCfg := engine.Config{
		Workers:     opts.Workers,
		QueueSize:   opts.Workers * 2,
		TaskTimeout: time.Duration(opts.TimeoutMs) * time.Millisecond,
		Limiter:     limiter,
	}

	taskFn := func(taskCtx context.Context, port int) (*db.PortRecord, error) {
		return probePort(taskCtx, opts.Target, port, opts.TimeoutMs)
	}

	pool, err := engine.NewPool(ctx, poolCfg, taskFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create worker pool: %w", err)
	}

	// Producer
	go func() {
		for _, port := range opts.Ports {
			select {
			case <-ctx.Done():
				return
			default:
				_ = pool.Submit(ctx, port)
			}
		}
		pool.Stop()
	}()

	var openPorts []db.PortRecord

	// Consumer
	for res := range pool.Results() {
		if res.Err != nil || res.Value == nil {
			continue
		}
		rec := *res.Value
		if rec.State == "open" {
			openPorts = append(openPorts, rec)
			if opts.Store != nil && opts.Workspace != "" {
				_ = opts.Store.SavePort(opts.Workspace, rec)
			}
			if opts.OnOpenFound != nil {
				opts.OnOpenFound(rec)
			}
		}
	}

	return openPorts, nil
}

// probePort tests connection to a specific port and extracts banner/headers.
func probePort(ctx context.Context, host string, port int, timeoutMs int) (*db.PortRecord, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	timeout := time.Duration(timeoutMs) * time.Millisecond

	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	if err != nil {
		return nil, nil // Port closed or unreachable
	}
	defer conn.Close()

	rec := &db.PortRecord{
		Target:    host,
		Port:      port,
		Protocol:  "tcp",
		State:     "open",
		LatencyMs: elapsed.Milliseconds(),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if srv, ok := wellKnownPorts[port]; ok {
		rec.Service = srv
	}

	// Try Banner grab / HTTP inspection
	banner := inspectBanner(conn, host, port, timeout)
	if banner != "" {
		rec.Banner = ui.Truncate(banner, 80)
		if strings.HasPrefix(banner, "HTTP/") {
			rec.Service = "HTTP"
		}
	}

	// If HTTP or HTTPS and no banner yet, attempt HTTP request
	if rec.Banner == "" && (port == 80 || port == 443 || port == 8080 || port == 8443) {
		rec.Banner = probeHTTP(host, port, timeout)
	}

	return rec, nil
}

// inspectBanner reads initial bytes from the open connection.
func inspectBanner(conn net.Conn, host string, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(350 * time.Millisecond))
	
	// For potential HTTP ports, send a minimal HEAD request
	if port == 80 || port == 8080 {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		firstLine := strings.Split(string(buf[:n]), "\r\n")[0]
		return strings.TrimSpace(firstLine)
	}
	return ""
}

// probeHTTP makes an explicit HTTP/HTTPS call to grab the Server header and Status.
func probeHTTP(host string, port int, timeout time.Duration) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	client := &http.Client{
		Timeout: 500 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Falcon/3.0 (+https://github.com/falcon)")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	if server != "" {
		return fmt.Sprintf("%s %s (Server: %s)", resp.Proto, resp.Status, server)
	}

	// Read small snippet to extract <title>
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), "<title>") {
			parts := strings.Split(line, "<title>")
			if len(parts) > 1 {
				title := strings.Split(parts[1], "</title>")[0]
				return fmt.Sprintf("%s %s [Title: %s]", resp.Proto, resp.Status, strings.TrimSpace(title))
			}
		}
	}

	return fmt.Sprintf("%s %s", resp.Proto, resp.Status)
}

// ParsePortList parses comma-separated lists and ranges ("80,443", "1-100").
func ParsePortList(spec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid range boundaries: %s", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}
