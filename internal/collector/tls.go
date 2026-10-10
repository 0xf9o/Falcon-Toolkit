package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/protocol"
)

// TLSCollector performs TLS handshake and extracts certificate and cipher suite intelligence.
type TLSCollector struct{}

// NewTLSCollector creates a new TLS collector.
func NewTLSCollector() *TLSCollector {
	return &TLSCollector{}
}

func (c *TLSCollector) Name() string {
	return "tls"
}

func (c *TLSCollector) Description() string {
	return "Performs TLS handshake to collect TLS version, cipher suite, certificate SANs, issuer, and validity"
}

func (c *TLSCollector) Supports(target domain.Target) bool {
	switch target.Type {
	case domain.TargetDomain, domain.TargetHostname, domain.TargetIPv4, domain.TargetIPv6, domain.TargetURL:
		return true
	default:
		return false
	}
}

func tlsVersionString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", ver)
	}
}

func (c *TLSCollector) Run(ctx context.Context, target domain.Target, opts CollectorOptions) ([]ResultObservation, error) {
	now := time.Now().UTC()
	var observations []ResultObservation

	host := target.NormalizedValue
	if target.Type == domain.TargetURL {
		trimmed := strings.TrimPrefix(host, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		host = strings.Split(parts[0], ":")[0]
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	ports := []int{443}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return observations, ctx.Err()
		default:
		}

		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		dialer := &net.Dialer{
			Timeout: timeout,
		}

		tlsConf := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
		if err != nil {
			continue
		}

		cs := conn.ConnectionState()
		conn.Close()

		tlsVer := tlsVersionString(cs.Version)
		cipherName := tls.CipherSuiteName(cs.CipherSuite)
		alpn := cs.NegotiatedProtocol

		meta := map[string]string{
			"tls_version":  tlsVer,
			"cipher_suite": cipherName,
			"alpn":         alpn,
			"sni":          host,
			"port":         fmt.Sprintf("%d", port),
		}

		var certNames []string
		var relationships []domain.Relationship

		if len(cs.PeerCertificates) > 0 {
			leaf := cs.PeerCertificates[0]
			subjectCN := leaf.Subject.CommonName
			subjectOrg := strings.Join(leaf.Subject.Organization, ", ")
			issuerCN := leaf.Issuer.CommonName
			issuerOrg := strings.Join(leaf.Issuer.Organization, ", ")
			sans := leaf.DNSNames
			for _, ip := range leaf.IPAddresses {
				sans = append(sans, ip.String())
			}

			notBefore := leaf.NotBefore.UTC().Format(time.RFC3339)
			notAfter := leaf.NotAfter.UTC().Format(time.RFC3339)
			isExpired := time.Now().After(leaf.NotAfter)

			meta["cert_subject"] = subjectCN
			if subjectOrg != "" {
				meta["cert_subject_org"] = subjectOrg
			}
			meta["cert_issuer"] = issuerCN
			if issuerOrg != "" {
				meta["cert_issuer_org"] = issuerOrg
			}
			meta["cert_sans"] = strings.Join(sans, ", ")
			meta["cert_not_before"] = notBefore
			meta["cert_not_after"] = notAfter
			meta["cert_expired"] = fmt.Sprintf("%v", isExpired)
			meta["cert_sig_algo"] = leaf.SignatureAlgorithm.String()
			meta["cert_pubkey_algo"] = leaf.PublicKeyAlgorithm.String()

			certNames = append(certNames, subjectCN)
			certNames = append(certNames, sans...)

			// Define graph relationships
			// Certificate identifies hostname
			if subjectCN != "" {
				relationships = append(relationships, domain.Relationship{
					SourceType: "certificate",
					SourceID:   leaf.SerialNumber.String(),
					TargetType: "domain",
					TargetID:   subjectCN,
					Type:       domain.RelIdentifies,
					CreatedAt:  now,
				})
			}
			// Certificate issued by issuer
			if issuerCN != "" {
				relationships = append(relationships, domain.Relationship{
					SourceType: "certificate",
					SourceID:   leaf.SerialNumber.String(),
					TargetType: "issuer",
					TargetID:   issuerCN,
					Type:       domain.RelIssuedBy,
					CreatedAt:  now,
				})
			}
		}

		idRes := protocol.NewIdentifier().Identify(protocol.ProbeContext{
			Port:       port,
			TLSSubject: meta["cert_subject"],
		})

		svcObs := observation.ServiceObservation{
			Protocol:    "tcp",
			Port:        port,
			State:       domain.ServiceStateOpen,
			ServiceName: "https",
			Technology:  idRes.Technology,
			Version:     idRes.Version,
			Description: fmt.Sprintf("%s, Cipher: %s, ALPN: %s, Cert: %s", tlsVer, cipherName, alpn, meta["cert_subject"]),
		}

		obs := ResultObservation{
			Collector:     c.Name(),
			SourceID:      fmt.Sprintf("tls-%s-%d", host, port),
			Target:        target,
			Timestamp:     now,
			Confidence:    domain.ConfidenceHigh,
			Kind:          "tls",
			Relationships: relationships,
			Host: &observation.HostObservation{
				IPAddress:  host,
				ObservedAt: now,
				SourceID:   c.Name(),
				Services:   []observation.ServiceObservation{svcObs},
				Tags:       []string{"tls-enabled", strings.ToLower(strings.ReplaceAll(tlsVer, " ", "-"))},
			},
			Metadata: meta,
			RawData:  fmt.Sprintf("TLS Handshake on %s:%d - %s, %s, ALPN=%s, Subject=%s, Issuer=%s, SANs=[%s]", host, port, tlsVer, cipherName, alpn, meta["cert_subject"], meta["cert_issuer"], meta["cert_sans"]),
		}
		observations = append(observations, obs)
	}

	return observations, nil
}
