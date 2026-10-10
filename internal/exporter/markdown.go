package exporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// ExportMarkdown generates a professional network segmentation audit report.
func ExportMarkdown(env *schema.SessionEnvironment, outputPath string) error {
	var sb strings.Builder

	sb.WriteString("# FALCON TOOLKIT — ENTERPRISE NETWORK POSTURE & SEGMENTATION AUDIT\n\n")
	sb.WriteString(fmt.Sprintf("**Session ID:** `%s`  \n", env.SessionID))
	sb.WriteString(fmt.Sprintf("**Audit Date:** `%s`  \n", env.StartTime.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("**Active Assessment Scope:** `%s`  \n", env.ActiveCIDR))
	sb.WriteString(fmt.Sprintf("**Target Scopes Count:** `%d`  \n\n", len(env.TargetScopes)))
	sb.WriteString("---\n\n")

	sb.WriteString("## 1. Executive Summary\n\n")
	sb.WriteString("This report documents observed network reachability, micro-segmentation efficacy, and lateral movement exposure. ")
	sb.WriteString("All metrics and findings are backed by empirical network socket connections, banner observations, and cryptographic handshake validations.\n\n")

	totalSubnets := len(env.Postures)
	openServicesCount := 0
	highRiskSubnets := 0

	for _, p := range env.Postures {
		if p.BlastScore >= 6.0 {
			highRiskSubnets++
		}
		for _, svc := range p.ProbedServices {
			if svc.State == schema.StateOpen {
				openServicesCount++
			}
		}
	}

	sb.WriteString("| Metric | Evaluated Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| Total Network Segments Audited | %d |\n", totalSubnets))
	sb.WriteString(fmt.Sprintf("| Open Cross-Boundary Services | %d |\n", openServicesCount))
	sb.WriteString(fmt.Sprintf("| Critical / High Blast Radius Segments (Score ≥ 6.0) | %d |\n", highRiskSubnets))
	sb.WriteString("\n---\n\n")

	sb.WriteString("## 2. Subnet Posture & Blast Radius Matrix\n\n")
	sb.WriteString("| Subnet CIDR | Compliance | Blast Radius (0-10) | Exposed Hosts | Open Services |\n")
	sb.WriteString("| :--- | :---: | :---: | :---: | :--- |\n")

	for cidr, p := range env.Postures {
		var openSvcs []string
		for _, svc := range p.ProbedServices {
			if svc.State == schema.StateOpen {
				openSvcs = append(openSvcs, fmt.Sprintf("%s (%d/tcp)", svc.ServiceName, svc.Port))
			}
		}
		openSummary := strings.Join(openSvcs, ", ")
		if openSummary == "" {
			openSummary = "*Isolated / Filtered*"
		}

		sb.WriteString(fmt.Sprintf("| `%s` | **%s** | `%.1f / 10.0` | %d | %s |\n",
			cidr, p.Compliance, p.BlastScore, len(p.ExposedHosts), openSummary))
	}
	sb.WriteString("\n---\n\n")

	sb.WriteString("## 3. Detailed Service Observations & Cryptographic Assets\n\n")
	for cidr, p := range env.Postures {
		sb.WriteString(fmt.Sprintf("### Segment: `%s` (Blast Score: `%.1f`)\n\n", cidr, p.BlastScore))
		if len(p.ProbedServices) == 0 {
			sb.WriteString("No accessible services identified within configured scope.\n\n")
			continue
		}

		sb.WriteString("| Port | Proto | Service | State | Latency | Observation / Banner |\n")
		sb.WriteString("| :---: | :---: | :--- | :---: | :---: | :--- |\n")
		for _, s := range p.ProbedServices {
			bannerText := s.Banner
			if bannerText == "" && len(s.TLSDetails) > 0 {
				bannerText = fmt.Sprintf("CN: %s | SANs: %s", s.TLSDetails["subject_cn"], s.TLSDetails["sans"])
			}
			if bannerText == "" {
				bannerText = "-"
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | `%s` | %dms | %s |\n",
				s.Port, s.Protocol, s.ServiceName, s.State, s.LatencyMs, bannerText))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\n")
	sb.WriteString("## 4. Remediation & Strategic Isolation Policy\n\n")
	sb.WriteString("To minimize lateral movement paths and remediate identified leakage:\n")
	sb.WriteString("1. Restrict internal access to critical management planes (SSH, RDP, WinRM) via dedicated bastion gateways.\n")
	sb.WriteString("2. Ensure legacy broadcast protocols (LLMNR, NetBIOS) are disabled via Group Policy (GPO).\n")
	sb.WriteString("3. Enforce strict outbound firewall egress rules on non-standard ports.\n\n")
	sb.WriteString(fmt.Sprintf("*Report generated autonomously by Falcon Toolkit v4.0 on %s*\n", time.Now().UTC().Format(time.RFC3339)))

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}
