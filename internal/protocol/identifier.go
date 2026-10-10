package protocol

import (
	"fmt"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// ProbeContext provides all evidentiary signals collected from a target service.
type ProbeContext struct {
	Port         int
	Protocol     string
	Banner       string
	Headers      map[string]string
	StatusCode   int
	HTMLTitle    string
	TLSSubject   string
	TLSIssuer    string
	TLSSANs      []string
	RawResponse  string
	Reachability domain.ReachabilityState
}

// IdentificationResult encapsulates the evidence-backed classification.
type IdentificationResult struct {
	Protocol           string                 `json:"protocol"`
	ProtocolConfidence domain.ConfidenceLevel `json:"protocol_confidence"`
	Technology         string                 `json:"technology,omitempty"`
	Version            string                 `json:"version,omitempty"`
	TechConfidence     domain.ConfidenceLevel `json:"tech_confidence,omitempty"`
	Evidence           string                 `json:"evidence"`
	Category           TechCategory           `json:"category,omitempty"`
	IsOT               bool                   `json:"is_ot"`
}

// Identifier evaluates probe context against evidence-driven signatures.
type Identifier struct {
	signatures []Signature
}

// NewIdentifier creates a new protocol and technology identifier.
func NewIdentifier() *Identifier {
	return &Identifier{
		signatures: BuiltinSignatures(),
	}
}

// Identify analyzes evidentiary signals to classify protocol and technology.
func (id *Identifier) Identify(ctx ProbeContext) IdentificationResult {
	res := IdentificationResult{
		Protocol:           defaultProtocolHint(ctx.Port),
		ProtocolConfidence: domain.ConfidenceInferred,
		Technology:         "",
		Version:            "",
		TechConfidence:     domain.ConfidenceLow,
		Evidence:           fmt.Sprintf("Port %d open hint", ctx.Port),
		IsOT:               false,
	}

	// 1. Direct Evidence Match against Signatures
	for _, sig := range id.signatures {
		match := false
		var matchedEvidence []string

		// Check Banner
		if sig.BannerRegex != nil && ctx.Banner != "" {
			if sig.BannerRegex.MatchString(ctx.Banner) {
				match = true
				matchedEvidence = append(matchedEvidence, fmt.Sprintf("Banner matched %q", ctx.Banner))
			}
		}

		// Check HTTP Headers
		if sig.HeaderKey != "" && len(ctx.Headers) > 0 {
			if headerVal, ok := ctx.Headers[sig.HeaderKey]; ok && headerVal != "" {
				if sig.HeaderRegex != nil && sig.HeaderRegex.MatchString(headerVal) {
					match = true
					matchedEvidence = append(matchedEvidence, fmt.Sprintf("Header %s: %s", sig.HeaderKey, headerVal))
				}
			}
		}

		// Check HTML Title
		if sig.TitleRegex != nil && ctx.HTMLTitle != "" {
			if sig.TitleRegex.MatchString(ctx.HTMLTitle) {
				match = true
				matchedEvidence = append(matchedEvidence, fmt.Sprintf("Title matched %q", ctx.HTMLTitle))
			}
		}

		// Check TLS Subject
		if sig.TLSSubjectRegex != nil && ctx.TLSSubject != "" {
			if sig.TLSSubjectRegex.MatchString(ctx.TLSSubject) {
				match = true
				matchedEvidence = append(matchedEvidence, fmt.Sprintf("TLS Subject matched %q", ctx.TLSSubject))
			}
		}

		// Check Raw Response
		if sig.ResponseRegex != nil && ctx.RawResponse != "" {
			if sig.ResponseRegex.MatchString(ctx.RawResponse) {
				match = true
				matchedEvidence = append(matchedEvidence, "Response pattern matched")
			}
		}

		if match {
			res.Protocol = sig.Protocol
			res.ProtocolConfidence = sig.Confidence
			res.Technology = sig.Name
			res.Category = sig.Category
			res.IsOT = sig.IsOT
			res.TechConfidence = sig.Confidence
			res.Evidence = strings.Join(matchedEvidence, "; ")

			// Extract version if pattern exists
			if sig.VersionRegex != nil {
				candidateText := ctx.Banner
				if hVal, ok := ctx.Headers[sig.HeaderKey]; ok && hVal != "" {
					candidateText = hVal
				}
				if m := sig.VersionRegex.FindStringSubmatch(candidateText); len(m) > 1 {
					res.Version = m[1]
				}
			}
			return res
		}
	}

	// 2. OT Port Guard: Ports are hints, never confirmed protocols without evidence!
	if isOTPort(ctx.Port) {
		res.IsOT = true
		res.Protocol = fmt.Sprintf("tcp-%d", ctx.Port)
		res.ProtocolConfidence = domain.ConfidenceLow
		res.Evidence = fmt.Sprintf("Port %d observed open; protocol unverified (no OT handshake response)", ctx.Port)
		return res
	}

	// 3. Fallback standard protocol hint based on verified probe signals
	if ctx.StatusCode > 0 {
		res.Protocol = "HTTP"
		res.ProtocolConfidence = domain.ConfidenceObserved
		res.Evidence = fmt.Sprintf("HTTP response %d received", ctx.StatusCode)
		return res
	}

	if ctx.TLSSubject != "" {
		res.Protocol = "HTTPS"
		res.ProtocolConfidence = domain.ConfidenceObserved
		res.Evidence = fmt.Sprintf("TLS handshake completed (Subject: %s)", ctx.TLSSubject)
		return res
	}

	if ctx.Banner != "" {
		res.ProtocolConfidence = domain.ConfidenceMedium
		res.Evidence = fmt.Sprintf("Banner: %s", ctx.Banner)
	}

	if res.Protocol == "" && ctx.Port > 0 {
		res.Protocol = strings.ToLower(defaultProtocolHint(ctx.Port))
		res.ProtocolConfidence = domain.ConfidenceLow
		res.Evidence = fmt.Sprintf("Port %d standard port mapping (unverified protocol)", ctx.Port)
	}

	return res
}

func isOTPort(port int) bool {
	switch port {
	case 502, 102, 4840, 20000, 44818:
		return true
	default:
		return false
	}
}

func defaultProtocolHint(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25, 465, 587:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8080:
		return "HTTP"
	case 443, 8443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 389, 636:
		return "LDAP"
	case 3389:
		return "RDP"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 1433:
		return "MSSQL"
	default:
		return fmt.Sprintf("tcp-%d", port)
	}
}
