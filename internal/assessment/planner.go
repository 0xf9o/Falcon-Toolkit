package assessment

import (
	"fmt"
	"strconv"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/scope"
)

// GenerateAssessmentPlan builds a verified pre-execution plan for a given target and scope.
func GenerateAssessmentPlan(tgt *domain.Target, sg *scope.ScopeGuard, profile string) (*domain.AssessmentPlan, error) {
	if tgt == nil {
		return nil, fmt.Errorf("no target provided for assessment plan")
	}

	if profile == "" {
		profile = "network"
	}

	plan := &domain.AssessmentPlan{
		TargetID:    tgt.ID,
		TargetValue: tgt.NormalizedValue,
		TargetType:  tgt.Type,
		Profile:     profile,
		RateLimit:   "conservative",
		Timeout:     "2s",
		Workers:     32,
		ScopeGuard:  true,
		Metadata:    make(map[string]interface{}),
	}

	// Calculate Scope Summary and Discovery Steps
	switch tgt.Type {
	case domain.TargetCIDR, domain.TargetNetwork:
		totalIPs := 256
		if ipsStr, ok := tgt.Metadata["total_ips"]; ok {
			if n, err := strconv.Atoi(ipsStr); err == nil && n > 0 {
				totalIPs = n
			}
		}
		plan.EstimatedHosts = totalIPs
		plan.ScopeSummary = fmt.Sprintf("%d addresses (%s)", totalIPs, tgt.NormalizedValue)
		plan.DiscoverySteps = []string{
			"Target validation",
			"Host discovery",
			"TCP service discovery",
			"DNS intelligence",
			"HTTP metadata",
			"TLS metadata",
		}

	case domain.TargetDomain:
		plan.EstimatedHosts = 1
		plan.ScopeSummary = fmt.Sprintf("Domain zone (%s)", tgt.NormalizedValue)
		plan.DiscoverySteps = []string{
			"Target validation",
			"DNS intelligence (A, AAAA, MX, NS, TXT, CNAME)",
			"Reverse PTR lookup",
			"Host verification",
			"TCP service discovery",
			"HTTP metadata",
			"TLS certificate inspection",
		}

	case domain.TargetHostname:
		plan.EstimatedHosts = 1
		plan.ScopeSummary = fmt.Sprintf("Single host (%s)", tgt.NormalizedValue)
		plan.DiscoverySteps = []string{
			"Target validation",
			"DNS resolution",
			"Host verification",
			"TCP service discovery",
			"Protocol detection",
		}

	case domain.TargetURL:
		plan.EstimatedHosts = 1
		plan.ScopeSummary = fmt.Sprintf("Web application endpoint (%s)", tgt.NormalizedValue)
		plan.DiscoverySteps = []string{
			"Target validation",
			"DNS resolution",
			"TCP service discovery",
			"HTTP response fingerprinting",
			"TLS certificate & cipher metadata",
			"Header security inspection",
		}

	case domain.TargetIPv4, domain.TargetIPv6, domain.TargetIP:
		plan.EstimatedHosts = 1
		plan.ScopeSummary = fmt.Sprintf("Single IP address (%s)", tgt.NormalizedValue)
		plan.DiscoverySteps = []string{
			"Target validation",
			"Host reachability",
			"TCP service discovery",
			"Reverse DNS (PTR)",
			"HTTP metadata",
			"TLS metadata",
		}

	default:
		plan.EstimatedHosts = 1
		plan.ScopeSummary = tgt.NormalizedValue
		plan.DiscoverySteps = []string{
			"Target validation",
			"Host discovery",
			"Service discovery",
		}
	}

	plan.CorrelationSteps = []string{
		"Identity resolution",
		"Technology detection",
		"Service correlation",
		"Network mapping",
	}

	plan.IntelligenceSteps = []string{
		"Attack surface",
		"Exposure analysis",
		"Relationship graph",
		"Evidence correlation",
	}

	if sg != nil {
		summary := sg.Summary()
		plan.Metadata["scope_rules_count"] = summary.TotalRules
		plan.Metadata["excluded_ranges"] = summary.ExcludedRanges
	}

	return plan, nil
}
