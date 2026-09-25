package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MatchRule represents a single detection rule inside a signature definition.
type MatchRule struct {
	Regex        string `yaml:"regex"`
	compiledRe   *regexp.Regexp
	Service      string `yaml:"service,omitempty"`
	Product      string `yaml:"product,omitempty"`
	VersionGroup int    `yaml:"version_group,omitempty"`
}

// Signature defines a service/protocol fingerprint template.
type Signature struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Protocol    string      `yaml:"protocol"` // tcp, udp, http
	Ports       []int       `yaml:"ports,omitempty"`
	Matches     []MatchRule `yaml:"matches"`
	Description string      `yaml:"description,omitempty"`
}

// IdentificationResult encapsulates the matched service details.
type IdentificationResult struct {
	Matched     bool
	SignatureID string
	Service     string
	Product     string
	Version     string
	Description string
}

// SignatureEngine manages loaded signatures and executes regex pattern matching.
type SignatureEngine struct {
	signatures []Signature
}

// defaultEmbeddedSignatures provides built-in protocol and service signatures.
var defaultEmbeddedSignatures = `
- id: ssh-openssh
  name: OpenSSH Server
  protocol: tcp
  ports: [22, 2222]
  matches:
    - regex: "^SSH-[0-9.]+-OpenSSH_([0-9a-zA-Z.]+)"
      service: SSH
      product: OpenSSH
      version_group: 1

- id: http-nginx
  name: Nginx Web Server
  protocol: http
  ports: [80, 443, 8080, 8443]
  matches:
    - regex: "(?i)Server:\\s*nginx(?:/([0-9.]+))?"
      service: HTTP
      product: Nginx
      version_group: 1

- id: http-apache
  name: Apache HTTP Server
  protocol: http
  ports: [80, 443, 8080]
  matches:
    - regex: "(?i)Server:\\s*Apache(?:/([0-9.]+))?"
      service: HTTP
      product: Apache
      version_group: 1

- id: http-caddy
  name: Caddy Web Server
  protocol: http
  ports: [80, 443]
  matches:
    - regex: "(?i)Server:\\s*Caddy"
      service: HTTP
      product: Caddy

- id: db-redis
  name: Redis In-Memory Store
  protocol: tcp
  ports: [6379]
  matches:
    - regex: "(?i)(?:-ERR unknown command|redis_version:([0-9.]+))"
      service: Redis
      product: Redis
      version_group: 1

- id: db-mysql
  name: MySQL Database
  protocol: tcp
  ports: [3306]
  matches:
    - regex: "(?i)([0-9.]+-MariaDB|[0-9.]+-MySQL|[0-9.]+)"
      service: MySQL
      product: MySQL
      version_group: 1

- id: db-postgres
  name: PostgreSQL Server
  protocol: tcp
  ports: [5432]
  matches:
    - regex: "(?i)(?:PostgreSQL|FATAL:\\s*password authentication failed)"
      service: PostgreSQL
      product: PostgreSQL

- id: ftp-vsftpd
  name: vsftpd FTP Server
  protocol: tcp
  ports: [21]
  matches:
    - regex: "(?i)^220.*vsftpd(?:\\s+([0-9.]+))?"
      service: FTP
      product: vsftpd
      version_group: 1

- id: mail-smtp
  name: SMTP Mail Transfer Agent
  protocol: tcp
  ports: [25, 587]
  matches:
    - regex: "(?i)^220\\s+([a-zA-Z0-9.-]+)\\s+(?:ESMTP|Postfix|Sendmail)"
      service: SMTP
      product: SMTP Server
      version_group: 1
`

// NewSignatureEngine initializes an engine pre-loaded with default embedded signatures.
func NewSignatureEngine() (*SignatureEngine, error) {
	engine := &SignatureEngine{}
	if err := engine.LoadYAMLString(defaultEmbeddedSignatures); err != nil {
		return nil, fmt.Errorf("failed to load default signatures: %w", err)
	}
	return engine, nil
}

// LoadYAMLString parses and compiles signatures from a YAML formatted string.
func (e *SignatureEngine) LoadYAMLString(yamlData string) error {
	var sigs []Signature
	if err := yaml.Unmarshal([]byte(yamlData), &sigs); err != nil {
		return err
	}

	for _, sig := range sigs {
		if err := e.addSignature(sig); err != nil {
			return err
		}
	}
	return nil
}

// LoadDirectory loads all .yaml or .yml signature files from a filesystem directory.
func (e *SignatureEngine) LoadDirectory(dirPath string) (int, error) {
	count := 0
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				if loadErr := e.LoadYAMLString(string(data)); loadErr == nil {
					count++
				}
			}
		}
		return nil
	})
	return count, err
}

func (e *SignatureEngine) addSignature(sig Signature) error {
	for i := range sig.Matches {
		compiled, err := regexp.Compile(sig.Matches[i].Regex)
		if err != nil {
			return fmt.Errorf("invalid regex '%s' in signature '%s': %w", sig.Matches[i].Regex, sig.ID, err)
		}
		sig.Matches[i].compiledRe = compiled
	}
	e.signatures = append(e.signatures, sig)
	return nil
}

// Count returns the total number of compiled signatures loaded in the engine.
func (e *SignatureEngine) Count() int {
	return len(e.signatures)
}

// Signatures returns the loaded signature descriptors.
func (e *SignatureEngine) Signatures() []Signature {
	return e.signatures
}

// Identify evaluates a raw banner/header response against all matching signatures.
func (e *SignatureEngine) Identify(banner string, port int) IdentificationResult {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return IdentificationResult{Matched: false}
	}

	for _, sig := range e.signatures {
		// If signature specifies ports, check port relevance first
		if len(sig.Ports) > 0 {
			portMatch := false
			for _, p := range sig.Ports {
				if p == port {
					portMatch = true
					break
				}
			}
			if !portMatch {
				continue
			}
		}

		for _, match := range sig.Matches {
			if match.compiledRe == nil {
				continue
			}

			submatches := match.compiledRe.FindStringSubmatch(banner)
			if len(submatches) > 0 {
				version := ""
				if match.VersionGroup > 0 && match.VersionGroup < len(submatches) {
					version = submatches[match.VersionGroup]
				}

				service := match.Service
				if service == "" {
					service = sig.Name
				}
				product := match.Product
				if product == "" {
					product = sig.Name
				}

				return IdentificationResult{
					Matched:     true,
					SignatureID: sig.ID,
					Service:     service,
					Product:     product,
					Version:     version,
					Description: sig.Description,
				}
			}
		}
	}

	return IdentificationResult{Matched: false}
}
