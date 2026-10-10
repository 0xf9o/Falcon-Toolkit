package exporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// ExportFirewallRemediation translates open reachability vectors into ready-to-deploy firewall deny rules.
func ExportFirewallRemediation(env *schema.SessionEnvironment, outputPath string) error {
	var sb strings.Builder

	sb.WriteString("# ====================================================================\n")
	sb.WriteString("# FALCON TOOLKIT — AUTOMATED FIREWALL REMEDIATION SNIPPETS\n")
	sb.WriteString(fmt.Sprintf("# Session: %s\n", env.SessionID))
	sb.WriteString("# ====================================================================\n\n")

	// 1. Cisco ASA / IOS Extended Access-List
	sb.WriteString("# --------------------------------------------------------------------\n")
	sb.WriteString("# CISCO ASA / IOS EXTENDED ACL SYNTAX\n")
	sb.WriteString("# --------------------------------------------------------------------\n")
	for cidr, p := range env.Postures {
		for _, svc := range p.ProbedServices {
			if svc.State == schema.StateOpen {
				sb.WriteString(fmt.Sprintf("access-list FALCON_DENY_LEAK extended deny %s any %s eq %d\n",
					svc.Protocol, cidrToCiscoWildcard(cidr), svc.Port))
			}
		}
	}
	sb.WriteString("\n")

	// 2. Palo Alto Networks PAN-OS CLI Syntax
	sb.WriteString("# --------------------------------------------------------------------\n")
	sb.WriteString("# PALO ALTO NETWORKS (PAN-OS) SET COMMANDS\n")
	sb.WriteString("# --------------------------------------------------------------------\n")
	for cidr, p := range env.Postures {
		for _, svc := range p.ProbedServices {
			if svc.State == schema.StateOpen {
				ruleName := fmt.Sprintf("FALCON_BLOCK_%d_%s", svc.Port, strings.ReplaceAll(cidr, "/", "_"))
				sb.WriteString(fmt.Sprintf("set security rules %s from any to any destination %s application any port %d action drop log-end yes\n",
					ruleName, cidr, svc.Port))
			}
		}
	}
	sb.WriteString("\n")

	// 3. Linux iptables Syntax
	sb.WriteString("# --------------------------------------------------------------------\n")
	sb.WriteString("# LINUX IPTABLES SYNTAX\n")
	sb.WriteString("# --------------------------------------------------------------------\n")
	for cidr, p := range env.Postures {
		for _, svc := range p.ProbedServices {
			if svc.State == schema.StateOpen {
				sb.WriteString(fmt.Sprintf("iptables -A FORWARD -d %s -p %s --dport %d -j DROP -m comment --comment \"Falcon Remediation\"\n",
					cidr, svc.Protocol, svc.Port))
			}
		}
	}
	sb.WriteString("\n")

	// 4. Linux nftables Syntax
	sb.WriteString("# --------------------------------------------------------------------\n")
	sb.WriteString("# LINUX NFTABLES SYNTAX\n")
	sb.WriteString("# --------------------------------------------------------------------\n")
	for cidr, p := range env.Postures {
		for _, svc := range p.ProbedServices {
			if svc.State == schema.StateOpen {
				sb.WriteString(fmt.Sprintf("nft add rule inet filter forward ip daddr %s %s dport %d counter drop comment \"Falcon Remediation\"\n",
					cidr, svc.Protocol, svc.Port))
			}
		}
	}

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func cidrToCiscoWildcard(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return cidr
	}
	ip := parts[0]
	maskLen := parts[1]

	var mask string
	switch maskLen {
	case "24":
		mask = "255.255.255.0"
	case "16":
		mask = "255.255.0.0"
	case "8":
		mask = "255.0.0.0"
	case "32":
		mask = "host " + ip
		return mask
	default:
		mask = "255.255.255.0"
	}

	return fmt.Sprintf("%s %s", ip, mask)
}
