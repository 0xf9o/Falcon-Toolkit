package modules

import (
	"testing"
)

func TestSignatureEngine_DefaultSignatures(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("failed to initialize signature engine: %v", err)
	}

	if engine.Count() < 5 {
		t.Errorf("expected at least 5 default signatures, got %d", engine.Count())
	}

	// Test SSH banner identification
	sshBanner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
	res := engine.Identify(sshBanner, 22)
	if !res.Matched {
		t.Errorf("expected SSH banner to match OpenSSH signature")
	}
	if res.Product != "OpenSSH" {
		t.Errorf("expected Product 'OpenSSH', got '%s'", res.Product)
	}
	if res.Version != "8.9p1" {
		t.Errorf("expected Version '8.9p1', got '%s'", res.Version)
	}
	if res.SignatureID != "ssh-openssh" {
		t.Errorf("expected SignatureID 'ssh-openssh', got '%s'", res.SignatureID)
	}

	// Test Nginx header identification
	nginxBanner := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: Fri, 25 Sep 2026 12:00:00 GMT"
	resHttp := engine.Identify(nginxBanner, 80)
	if !resHttp.Matched {
		t.Errorf("expected Nginx banner to match")
	}
	if resHttp.Product != "Nginx" {
		t.Errorf("expected Product 'Nginx', got '%s'", resHttp.Product)
	}
	if resHttp.Version != "1.24.0" {
		t.Errorf("expected Version '1.24.0', got '%s'", resHttp.Version)
	}

	// Test Redis error response
	redisBanner := "-ERR unknown command 'HEAD'"
	resRedis := engine.Identify(redisBanner, 6379)
	if !resRedis.Matched || resRedis.Service != "Redis" {
		t.Errorf("expected Redis match, got %+v", resRedis)
	}
}

func TestSignatureEngine_NoMatch(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	res := engine.Identify("totally-unknown-gibberish-$$@!!", 9999)
	if res.Matched {
		t.Errorf("expected no match for unknown banner, got signature: %s", res.SignatureID)
	}
}

func TestSignatureEngine_EmptyBanner(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	res := engine.Identify("", 80)
	if res.Matched {
		t.Errorf("expected no match for empty banner")
	}
}

func TestSignatureEngine_WhitespaceBanner(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	res := engine.Identify("   \t\n  ", 443)
	if res.Matched {
		t.Errorf("expected no match for whitespace-only banner")
	}
}

func TestSignatureEngine_FTPIdentification(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	ftpBanner := "220 (vsftpd 3.0.5)"
	res := engine.Identify(ftpBanner, 21)
	if !res.Matched {
		t.Errorf("expected FTP vsftpd match")
	}
	if res.Service != "FTP" {
		t.Errorf("expected Service 'FTP', got %q", res.Service)
	}
}

func TestSignatureEngine_SMTPIdentification(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	smtpBanner := "220 mail.example.com ESMTP Postfix (Ubuntu)"
	res := engine.Identify(smtpBanner, 25)
	if !res.Matched {
		t.Errorf("expected SMTP Postfix match")
	}
	if res.Service != "SMTP" {
		t.Errorf("expected Service 'SMTP', got %q", res.Service)
	}
}

func TestSignatureEngine_PostgreSQLIdentification(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	pgBanner := "FATAL:  password authentication failed for user \"admin\""
	res := engine.Identify(pgBanner, 5432)
	if !res.Matched {
		t.Errorf("expected PostgreSQL match")
	}
}

func TestSignatureEngine_LoadYAMLString(t *testing.T) {
	engine := &SignatureEngine{}
	customYAML := `
- id: custom-test-svc
  name: Custom Test Service
  protocol: tcp
  ports: [19999]
  matches:
    - regex: "^CUSTOM_([A-Z]+)_BANNER"
      service: CustomSvc
      product: TestProduct
      version_group: 1
`
	if err := engine.LoadYAMLString(customYAML); err != nil {
		t.Fatalf("LoadYAMLString error: %v", err)
	}

	if engine.Count() != 1 {
		t.Errorf("expected 1 loaded signature, got %d", engine.Count())
	}

	res := engine.Identify("CUSTOM_ALPHA_BANNER extra data", 19999)
	if !res.Matched {
		t.Errorf("expected custom signature to match")
	}
	if res.Version != "ALPHA" {
		t.Errorf("expected version group 'ALPHA', got %q", res.Version)
	}
}

func TestSignatureEngine_LoadYAMLString_InvalidRegex(t *testing.T) {
	engine := &SignatureEngine{}
	badYAML := `
- id: bad-regex
  name: Bad Regex Test
  protocol: tcp
  matches:
    - regex: "[invalid("
      service: BadSvc
`
	err := engine.LoadYAMLString(badYAML)
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestSignatureEngine_PortFiltering(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	// SSH banner on wrong port — port filtering should prevent match
	sshBanner := "SSH-2.0-OpenSSH_8.9p1"
	res := engine.Identify(sshBanner, 9999) // SSH sig only matches ports [22, 2222]
	if res.Matched {
		t.Errorf("SSH banner should not match on port 9999 due to port filtering")
	}
}

func TestSignatureEngine_Signatures_Returns_Slice(t *testing.T) {
	engine, err := NewSignatureEngine()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	sigs := engine.Signatures()
	if len(sigs) == 0 {
		t.Error("Signatures() returned empty slice")
	}
	for _, sig := range sigs {
		if sig.ID == "" {
			t.Errorf("signature has empty ID: %+v", sig)
		}
		if sig.Name == "" {
			t.Errorf("signature %q has empty name", sig.ID)
		}
	}
}

func TestParsePortList(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		wantErr  bool
	}{
		{"80,443", []int{80, 443}, false},
		{"1-5", []int{1, 2, 3, 4, 5}, false},
		{"22,80,443,1-3", []int{22, 80, 443, 1, 2, 3}, false},
		{"0", nil, true},       // port 0 is invalid
		{"65536", nil, true},   // port > 65535
		{"abc", nil, true},     // non-numeric
		{"10-5", nil, true},    // reversed range
		{"80,80", []int{80}, false}, // deduplication
	}

	for _, tc := range tests {
		ports, err := ParsePortList(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePortList(%q): expected error, got nil (ports: %v)", tc.input, ports)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortList(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if !intSliceEqual(ports, tc.expected) {
			t.Errorf("ParsePortList(%q) = %v; want %v", tc.input, ports, tc.expected)
		}
	}
}

// intSliceEqual checks if two int slices have the same elements (order-sensitive).
func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[int]int)
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}
