package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTCPProbe_ClosedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Port 1 is reliably closed/filtered on virtually every host
	target := Target{Host: "127.0.0.1", Port: 1, Protocol: ProtoTCP}
	res, err := TCPProbe(ctx, target)
	if err != nil {
		t.Fatalf("unexpected error from TCPProbe: %v", err)
	}
	if res.State == StateOpen {
		t.Errorf("expected non-open state for port 1, got %s", res.State)
	}
}

func TestTCPProbe_OpenPort(t *testing.T) {
	ln, err := newLocalTCPListener(t)
	if err != nil {
		t.Skipf("could not bind local listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			_, _ = conn.Write([]byte("HELLO FALCON\r\n"))
			conn.Close()
		}
	}()

	_, port, _ := parseHostPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	target := Target{Host: "127.0.0.1", Port: port, Protocol: ProtoTCP}
	res, err := TCPProbe(ctx, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.State != StateOpen {
		t.Errorf("expected StateOpen, got %s", res.State)
	}
	if res.Banner == "" {
		t.Error("expected non-empty banner from echo server")
	}
	if !strings.Contains(res.Banner, "HELLO FALCON") {
		t.Errorf("expected banner to contain 'HELLO FALCON', got: %q", res.Banner)
	}
}

func TestTCPProbe_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately before dialling

	// 192.0.2.x is TEST-NET (RFC 5737) — unreachable but not immediately refused
	target := Target{Host: "192.0.2.1", Port: 9999, Protocol: ProtoTCP}
	res, err := TCPProbe(ctx, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should never be open when context is pre-cancelled
	if res.State == StateOpen {
		t.Errorf("should not be open when context is already cancelled")
	}
}

func TestHTTPProbe_LocalServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Falcon Test</title></head><body>OK</body></html>"))
	}))
	defer ts.Close()

	_, port, err := parseHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("could not parse test server address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := Target{Host: "127.0.0.1", Port: port, Protocol: ProtoTCP}
	res, err := HTTPProbe(ctx, target)
	if err != nil {
		t.Fatalf("unexpected HTTPProbe error: %v", err)
	}
	if res.State != StateOpen {
		t.Errorf("expected StateOpen, got %s (error: %s)", res.State, res.ErrorMsg)
	}
	if res.HTTPInfo == nil {
		t.Fatal("expected HTTPInfo to be populated")
	}
	if res.HTTPInfo.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.HTTPInfo.StatusCode)
	}
	if res.HTTPInfo.Server != "TestServer/1.0" {
		t.Errorf("expected Server 'TestServer/1.0', got %q", res.HTTPInfo.Server)
	}
	if res.HTTPInfo.Title != "Falcon Test" {
		t.Errorf("expected title 'Falcon Test', got %q", res.HTTPInfo.Title)
	}
}

func TestHTTPProbe_RedirectCapture(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
	}))
	defer ts.Close()

	_, port, err := parseHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("could not parse test server address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := Target{Host: "127.0.0.1", Port: port, Protocol: ProtoTCP}
	res, err := HTTPProbe(ctx, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.HTTPInfo == nil {
		t.Fatal("expected HTTPInfo")
	}
	if res.HTTPInfo.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", res.HTTPInfo.StatusCode)
	}
	if res.HTTPInfo.Location == "" {
		t.Error("expected non-empty Location header")
	}
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"SSH-2.0-OpenSSH_8.9\r\nProtocol mismatch.\r\n", "SSH-2.0-OpenSSH_8.9"},
		{"220 ftp.example.com FTP ready\r\n", "220 ftp.example.com"},
		{"Short", "Short"},
	}

	for _, tc := range tests {
		got := sanitizeBanner(tc.input)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("sanitizeBanner(%q) = %q; want it to contain %q", tc.input, got, tc.contains)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLSv1.0"},
		{tls.VersionTLS11, "TLSv1.1"},
		{tls.VersionTLS12, "TLSv1.2"},
		{tls.VersionTLS13, "TLSv1.3"},
		{0xFFFF, "Unknown(0xFFFF)"},
	}
	for _, tc := range cases {
		got := tlsVersionName(tc.version)
		if got != tc.want {
			t.Errorf("tlsVersionName(0x%04X) = %q; want %q", tc.version, got, tc.want)
		}
	}
}

// --- Test helpers ---

func newLocalTCPListener(t *testing.T) (*net.TCPListener, error) {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", addr)
}

func parseHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	return host, port, err
}
