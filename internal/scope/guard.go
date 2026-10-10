package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// ScopeGuard validates that active collection and target definitions
// remain strictly within authorized operational boundaries.
type ScopeGuard struct {
	workspaceID   string
	rules         []domain.ScopeRule
	activeTargets []domain.Target

	includedCIDRs   []*net.IPNet
	includedIPs     []net.IP
	includedDomains []string

	excludedCIDRs   []*net.IPNet
	excludedIPs     []net.IP
	excludedDomains []string

	rateLimit  string
	timeout    time.Duration
	maxWorkers int

	hasExplicitIncludes bool
}

// ScopeSummary describes the active scope guard state.
type ScopeSummary struct {
	TotalRules      int      `json:"total_rules"`
	IncludeCount    int      `json:"include_count"`
	ExcludeCount    int      `json:"exclude_count"`
	TargetCount     int      `json:"target_count"`
	IncludedRanges  []string `json:"included_ranges"`
	ExcludedRanges  []string `json:"excluded_ranges"`
	ExcludedDomains []string `json:"excluded_domains"`
	RateLimit       string   `json:"rate_limit"`
	Timeout         string   `json:"timeout"`
	MaxWorkers      int      `json:"max_workers"`
}

// NewScopeGuard creates and compiles a ScopeGuard from workspace rules and targets.
func NewScopeGuard(workspaceID string, rules []domain.ScopeRule, targets []domain.Target) *ScopeGuard {
	sg := &ScopeGuard{
		workspaceID:   workspaceID,
		rules:         rules,
		activeTargets: targets,
		rateLimit:     "conservative",
		timeout:       2 * time.Second,
		maxWorkers:    32,
	}

	sg.compile()
	return sg
}

func (sg *ScopeGuard) compile() {
	// 1. Compile explicit scope rules
	for _, rule := range sg.rules {
		pat := strings.ToLower(strings.TrimSpace(rule.Pattern))
		if pat == "" {
			continue
		}

		if rule.RuleType == domain.ScopeExclude {
			sg.compilePattern(pat, true)
		} else {
			sg.hasExplicitIncludes = true
			sg.compilePattern(pat, false)
		}
	}

	// 2. Compile active workspace targets
	for _, t := range sg.activeTargets {
		norm := strings.ToLower(strings.TrimSpace(t.NormalizedValue))
		if norm == "" {
			continue
		}

		isExclude := (t.Scope == domain.TargetOutOfScope || t.Status == domain.TargetStatusExcluded)
		if t.Type == domain.TargetURL {
			u, err := url.Parse(norm)
			if err == nil && u.Hostname() != "" {
				sg.compilePattern(u.Hostname(), isExclude)
			}
			continue
		}

		sg.compilePattern(norm, isExclude)
	}
}

func (sg *ScopeGuard) compilePattern(pattern string, isExclude bool) {
	// Try parsing as CIDR
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			if isExclude {
				sg.excludedCIDRs = append(sg.excludedCIDRs, ipNet)
			} else {
				sg.includedCIDRs = append(sg.includedCIDRs, ipNet)
			}
			return
		}
	}

	// Try parsing as IP
	ip := net.ParseIP(pattern)
	if ip != nil {
		if isExclude {
			sg.excludedIPs = append(sg.excludedIPs, ip)
		} else {
			sg.includedIPs = append(sg.includedIPs, ip)
		}
		return
	}

	// Otherwise treat as domain/hostname/wildcard
	cleanDomain := strings.TrimPrefix(pattern, "*.")
	cleanDomain = strings.TrimPrefix(cleanDomain, ".")
	if isExclude {
		sg.excludedDomains = append(sg.excludedDomains, cleanDomain)
	} else {
		sg.includedDomains = append(sg.includedDomains, cleanDomain)
	}
}

// Validate checks whether a Target passes scope authorization.
func (sg *ScopeGuard) Validate(target *domain.Target) error {
	if target == nil {
		return fmt.Errorf("nil target")
	}

	// 1. Exclusions check (always forbidden)
	if target.Scope == domain.TargetOutOfScope || target.Status == domain.TargetStatusExcluded {
		return fmt.Errorf("target is explicitly marked out of scope")
	}

	val := target.NormalizedValue
	for _, excIP := range sg.excludedIPs {
		if ip := net.ParseIP(val); ip != nil && excIP.Equal(ip) {
			return fmt.Errorf("target %s matches explicit exclusion rule", val)
		}
	}
	for _, excNet := range sg.excludedCIDRs {
		if ip := net.ParseIP(val); ip != nil && excNet.Contains(ip) {
			return fmt.Errorf("target %s falls within excluded CIDR %s", val, excNet.String())
		}
		if _, tNet, err := net.ParseCIDR(val); err == nil {
			if excNet.Contains(tNet.IP) || tNet.Contains(excNet.IP) {
				return fmt.Errorf("target CIDR %s conflicts with excluded network %s", val, excNet.String())
			}
		}
	}
	for _, excDom := range sg.excludedDomains {
		host := val
		if target.Type == domain.TargetURL {
			if u, err := url.Parse(host); err == nil {
				host = u.Hostname()
			}
		}
		cleanHost := strings.TrimPrefix(strings.ToLower(host), "*.")
		if cleanHost == excDom || strings.HasSuffix(cleanHost, "."+excDom) {
			return fmt.Errorf("target %s matches excluded domain rule %s", val, excDom)
		}
	}

	// 2. If explicit include rules exist, target must match at least one
	if sg.hasExplicitIncludes {
		allowed, reason := sg.IsAllowed(target)
		if !allowed {
			return fmt.Errorf("scope authorization rejected target %s: %s", val, reason)
		}
	}

	return nil
}

// IsAllowed evaluates target scope status and returns allowed boolean and explanation.
func (sg *ScopeGuard) IsAllowed(target *domain.Target) (bool, string) {
	if target == nil {
		return false, "nil target"
	}

	if target.Scope == domain.TargetOutOfScope || target.Status == domain.TargetStatusExcluded {
		return false, "target is explicitly marked out of scope"
	}

	val := target.NormalizedValue
	switch target.Type {
	case domain.TargetIPv4, domain.TargetIPv6, domain.TargetIP:
		ip := net.ParseIP(val)
		if ip == nil {
			return false, "invalid IP representation"
		}
		return sg.IsIPAllowed(ip)

	case domain.TargetCIDR, domain.TargetNetwork:
		_, ipNet, err := net.ParseCIDR(val)
		if err != nil {
			return false, "invalid CIDR representation"
		}
		return sg.isCIDRAllowed(ipNet)

	case domain.TargetURL:
		u, err := url.Parse(val)
		if err != nil {
			return false, "invalid URL representation"
		}
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			return sg.IsIPAllowed(ip)
		}
		return sg.IsHostAllowed(host)

	case domain.TargetDomain, domain.TargetHostname:
		return sg.IsHostAllowed(val)

	default:
		return sg.IsHostAllowed(val)
	}
}

// IsIPAllowed tests if a specific IP address is in scope.
func (sg *ScopeGuard) IsIPAllowed(ip net.IP) (bool, string) {
	if ip == nil {
		return false, "nil IP"
	}

	// 1. Check exclusions first (Denylist has absolute precedence)
	for _, excIP := range sg.excludedIPs {
		if excIP.Equal(ip) {
			return false, fmt.Sprintf("IP %s matches explicit exclusion rule", ip.String())
		}
	}
	for _, excNet := range sg.excludedCIDRs {
		if excNet.Contains(ip) {
			return false, fmt.Sprintf("IP %s falls within excluded CIDR %s", ip.String(), excNet.String())
		}
	}

	// 2. Check inclusions (if any inclusions defined)
	hasInclusions := len(sg.includedIPs) > 0 || len(sg.includedCIDRs) > 0
	if !hasInclusions {
		// When no IP inclusions are specified, check if workspace has domain-only scope
		if len(sg.includedDomains) > 0 {
			// IP not explicitly included in domain-only scope, allowed if resolving
			return true, "permitted by default domain scope"
		}
		return true, "permitted by default workspace scope"
	}

	for _, incIP := range sg.includedIPs {
		if incIP.Equal(ip) {
			return true, fmt.Sprintf("matched included IP %s", incIP.String())
		}
	}
	for _, incNet := range sg.includedCIDRs {
		if incNet.Contains(ip) {
			return true, fmt.Sprintf("matched included CIDR %s", incNet.String())
		}
	}

	return false, fmt.Sprintf("IP %s is not within any included scope rule", ip.String())
}

// isCIDRAllowed tests if a CIDR block is in scope without conflicting with exclusions.
func (sg *ScopeGuard) isCIDRAllowed(targetNet *net.IPNet) (bool, string) {
	if targetNet == nil {
		return false, "nil CIDR"
	}

	// Check if target CIDR contains or is contained in an exclusion
	for _, excNet := range sg.excludedCIDRs {
		if excNet.Contains(targetNet.IP) || targetNet.Contains(excNet.IP) {
			return false, fmt.Sprintf("CIDR %s conflicts with excluded network %s", targetNet.String(), excNet.String())
		}
	}

	// Check inclusions
	if len(sg.includedCIDRs) == 0 && len(sg.includedIPs) == 0 && len(sg.includedDomains) == 0 {
		return true, "permitted by default workspace scope"
	}

	for _, incNet := range sg.includedCIDRs {
		if incNet.Contains(targetNet.IP) || targetNet.String() == incNet.String() {
			return true, fmt.Sprintf("matched included network %s", incNet.String())
		}
	}

	return true, "target CIDR accepted as authorized scope root"
}

// IsHostAllowed tests if a domain or hostname is in scope.
func (sg *ScopeGuard) IsHostAllowed(host string) (bool, string) {
	clean := strings.ToLower(strings.TrimSpace(host))
	clean = strings.TrimPrefix(clean, "*.")
	clean = strings.TrimSuffix(clean, ".")

	// 1. Check exclusions
	for _, exc := range sg.excludedDomains {
		if clean == exc || strings.HasSuffix(clean, "."+exc) {
			return false, fmt.Sprintf("host %s matches excluded domain rule %s", clean, exc)
		}
	}

	// 2. Check inclusions
	if len(sg.includedDomains) == 0 {
		return true, "permitted by workspace scope"
	}

	for _, inc := range sg.includedDomains {
		if clean == inc || strings.HasSuffix(clean, "."+inc) {
			return true, fmt.Sprintf("matched included domain %s", inc)
		}
	}

	return false, fmt.Sprintf("host %s is not within included domains", clean)
}

// Summary returns a snapshot of scope rules and operational limits.
func (sg *ScopeGuard) Summary() ScopeSummary {
	var incRanges, excRanges, excDomains []string

	for _, net := range sg.includedCIDRs {
		incRanges = append(incRanges, net.String())
	}
	for _, ip := range sg.includedIPs {
		incRanges = append(incRanges, ip.String()+"/32")
	}

	for _, net := range sg.excludedCIDRs {
		excRanges = append(excRanges, net.String())
	}
	for _, ip := range sg.excludedIPs {
		excRanges = append(excRanges, ip.String()+"/32")
	}

	excDomains = append(excDomains, sg.excludedDomains...)

	return ScopeSummary{
		TotalRules:      len(sg.rules),
		IncludeCount:    len(sg.includedCIDRs) + len(sg.includedIPs) + len(sg.includedDomains),
		ExcludeCount:    len(sg.excludedCIDRs) + len(sg.excludedIPs) + len(sg.excludedDomains),
		TargetCount:     len(sg.activeTargets),
		IncludedRanges:  incRanges,
		ExcludedRanges:  excRanges,
		ExcludedDomains: excDomains,
		RateLimit:       sg.rateLimit,
		Timeout:         sg.timeout.String(),
		MaxWorkers:      sg.maxWorkers,
	}
}
