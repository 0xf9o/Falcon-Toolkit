// Package probe provides low-level, context-aware network connectivity primitives.
// It implements TCP/UDP health checks, TLS handshake fingerprinting, and
// HTTP/HTTPS header extraction — all operating as pure Go without any
// external system dependencies.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// PortState describes whether a scanned network port is open, closed, or filtered.
type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
)

// Protocol identifies the layer-4 transport used for the probe.
type Protocol string

const (
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

// Target represents a network endpoint to probe.
type Target struct {
	Host     string
	Port     int
	Protocol Protocol
}

// Address formats the host:port dial address.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
}

// Result holds the diagnostic outcome of a network port probe.
type Result struct {
	Target    Target        `json:"target"`
	State     PortState     `json:"state"`
	Latency   time.Duration `json:"latency"`
	Banner    string        `json:"banner,omitempty"`
	TLSInfo   *TLSInfo      `json:"tls,omitempty"`
	HTTPInfo  *HTTPInfo     `json:"http,omitempty"`
	ErrorMsg  string        `json:"error,omitempty"`
}

// TLSInfo holds extracted TLS handshake metadata.
type TLSInfo struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	CommonName  string   `json:"common_name,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
}

// HTTPInfo captures HTTP response metadata extracted during banner grabbing.
type HTTPInfo struct {
	StatusCode int    `json:"status_code"`
	Proto      string `json:"proto"`
	Server     string `json:"server,omitempty"`
	Title      string `json:"title,omitempty"`
	Location   string `json:"location,omitempty"`
	PoweredBy  string `json:"powered_by,omitempty"`
}

// TCPProbe performs a fast TCP connectivity test with context-aware cancellation and banner grabbing.
// It attempts a banner grab on the established connection with a short (300 ms) read deadline,
// preventing slow-service probe hang-ups from blocking the worker pool.
func TCPProbe(ctx context.Context, target Target) (Result, error) {
	addr := target.Address()
	start := time.Now()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	if err != nil {
		state := StateClosed
		if ctx.Err() != nil {
			state = StateFiltered
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			state = StateFiltered
		}
		return Result{
			Target:   target,
			State:    state,
			Latency:  elapsed,
			ErrorMsg: err.Error(),
		}, nil
	}
	defer conn.Close()

	res := Result{
		Target:  target,
		State:   StateOpen,
		Latency: elapsed,
	}

	// Non-blocking banner grab (300 ms deadline — fast fail for silent services)
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Banner = sanitizeBanner(string(buf[:n]))
	}

	return res, nil
}

// TLSProbe performs a TCP connection followed by a TLS handshake against the target,
// extracting cipher suite, protocol version, and certificate metadata.
func TLSProbe(ctx context.Context, target Target) (Result, error) {
	addr := target.Address()
	start := time.Now()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — intentional: we are inspecting, not trusting
			MinVersion:         tls.VersionTLS10,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	if err != nil {
		state := StateClosed
		if ctx.Err() != nil || (func() bool {
			if netErr, ok := err.(net.Error); ok {
				return netErr.Timeout()
			}
			return false
		}()) {
			state = StateFiltered
		}
		return Result{
			Target:   target,
			State:    state,
			Latency:  elapsed,
			ErrorMsg: err.Error(),
		}, nil
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return Result{Target: target, State: StateOpen, Latency: elapsed}, nil
	}

	cs := tlsConn.ConnectionState()
	info := &TLSInfo{
		Version:     tlsVersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
	}

	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		info.CommonName = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.NotAfter = cert.NotAfter.Format("2006-01-02")
		info.SANs = cert.DNSNames
	}

	return Result{
		Target:  target,
		State:   StateOpen,
		Latency: elapsed,
		TLSInfo: info,
	}, nil
}

// HTTPProbe sends a HEAD (then GET fallback) HTTP request to extract response metadata
// including status code, server header, page title, and redirect location.
func HTTPProbe(ctx context.Context, target Target) (Result, error) {
	scheme := "http"
	if target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s/", scheme, target.Address())
	start := time.Now()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow — capture redirect info
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Result{Target: target, State: StateClosed, ErrorMsg: err.Error()}, nil
	}
	req.Header.Set("User-Agent", "Falcon/3.0 Network-Probe (+https://github.com/falcon-toolkit/falcon)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		state := StateClosed
		if ctx.Err() != nil {
			state = StateFiltered
		}
		return Result{
			Target:   target,
			State:    state,
			Latency:  elapsed,
			ErrorMsg: err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	httpInfo := &HTTPInfo{
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		Server:     resp.Header.Get("Server"),
		Location:   resp.Header.Get("Location"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
	}

	// Extract <title> tag from response body (read ≤ 8 KB to stay fast)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 8192), 8192)
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		if idx := strings.Index(lower, "<title>"); idx != -1 {
			rest := line[idx+7:]
			if end := strings.Index(strings.ToLower(rest), "</title>"); end != -1 {
				httpInfo.Title = strings.TrimSpace(rest[:end])
			}
			break
		}
	}

	banner := fmt.Sprintf("%s %d", resp.Proto, resp.StatusCode)
	if httpInfo.Server != "" {
		banner += " [" + httpInfo.Server + "]"
	}

	return Result{
		Target:   target,
		State:    StateOpen,
		Latency:  elapsed,
		Banner:   banner,
		HTTPInfo: httpInfo,
	}, nil
}

// sanitizeBanner normalises raw bytes from a banner grab into a printable single-line string.
func sanitizeBanner(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\r\n", " | ")
	raw = strings.ReplaceAll(raw, "\n", " | ")
	raw = strings.ReplaceAll(raw, "\r", "")

	// Trim at first pipe after 200 chars so we see the first line cleanly
	if len(raw) > 200 {
		raw = raw[:197] + "..."
	}
	return raw
}

// tlsVersionName maps uint16 TLS version identifiers to readable names.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", v)
	}
}
