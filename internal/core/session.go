package core

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/graph"
	"github.com/falcon-toolkit/falcon/internal/identity"
	"github.com/falcon-toolkit/falcon/internal/schema"
	"github.com/falcon-toolkit/falcon/internal/scope"
)

// Session manages the real-time target definitions, execution configuration,
// scope boundaries, identity fusion, graph topology, and evaluated network postures.
type Session struct {
	mu            sync.RWMutex
	Env           *schema.SessionEnvironment
	WorkspaceID   string
	WorkspaceName string
	Profile       string
	RateLimit     int           // packets or probes per second
	Workers       int           // concurrent worker pool size
	ProbeTimeout  time.Duration // per-probe timeout
	Evasion       bool          // jitter / evasion flag
	Passive       bool          // passive listener flag

	ScopeRules []domain.ScopeRule
	ScopeGuard *scope.ScopeGuard
	Fusion     *identity.FusionEngine
	Graph      *graph.Graph
	Evidence   []domain.Evidence
}

// NewSession creates a newly initialized, thread-safe session.
func NewSession() *Session {
	sessID := fmt.Sprintf("SES-%d", time.Now().Unix())
	s := &Session{
		Env: &schema.SessionEnvironment{
			SessionID:    sessID,
			StartTime:    time.Now().UTC(),
			ActiveCIDR:   "",
			TargetScopes: []string{},
			Postures:     make(map[string]schema.SubnetPosture),
		},
		WorkspaceID:   "default",
		WorkspaceName: "default",
		Profile:       "default",
		RateLimit:     100,
		Workers:       30,
		ProbeTimeout:  3 * time.Second,
		Evasion:       false,
		Passive:       false,
		ScopeRules:    []domain.ScopeRule{},
		Fusion:        identity.NewFusionEngine(),
		Graph:         graph.New(),
		Evidence:      []domain.Evidence{},
	}
	s.recompileScope()
	return s
}

func (s *Session) recompileScope() {
	var activeTargets []domain.Target
	for _, t := range s.Env.TargetScopes {
		activeTargets = append(activeTargets, domain.Target{
			WorkspaceID:     s.WorkspaceID,
			Input:           t,
			NormalizedValue: t,
			Scope:           domain.TargetInScope,
			Status:          domain.TargetStatusPending,
		})
	}
	s.ScopeGuard = scope.NewScopeGuard(s.WorkspaceID, s.ScopeRules, activeTargets)
}

// AddScopeRule adds an include or exclude rule to the active scope guard.
func (s *Session) AddScopeRule(ruleType domain.ScopeRuleType, pattern string, desc string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ScopeRules = append(s.ScopeRules, domain.ScopeRule{
		ID:          fmt.Sprintf("SR-%d", time.Now().UnixNano()),
		WorkspaceID: s.WorkspaceID,
		RuleType:    ruleType,
		Pattern:     pattern,
		Description: desc,
		CreatedAt:   time.Now().UTC(),
	})
	s.recompileScope()
}

// GetScopeRules returns a copy of current scope rules.
func (s *Session) GetScopeRules() []domain.ScopeRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]domain.ScopeRule, len(s.ScopeRules))
	copy(res, s.ScopeRules)
	return res
}

// ValidateTarget checks if a target string satisfies the ScopeGuard bounds.
func (s *Session) ValidateTarget(targetStr string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t := &domain.Target{
		WorkspaceID:     s.WorkspaceID,
		Input:           targetStr,
		NormalizedValue: targetStr,
		Scope:           domain.TargetInScope,
	}
	return s.ScopeGuard.Validate(t)
}

// SetTargets parses and sets active target scopes.
// Supports: Single IPs, CIDRs (10.0.0.0/24), IP ranges (192.168.1.1-192.168.1.50), and Hostnames.
func (s *Session) SetTargets(inputs []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var validTargets []string
	for _, raw := range inputs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		expanded, err := ParseTargetSpecification(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", trimmed, err)
		}
		validTargets = append(validTargets, expanded...)
	}

	// De-duplicate targets
	seen := make(map[string]bool)
	var unique []string
	for _, t := range validTargets {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}

	s.Env.TargetScopes = unique
	if len(unique) > 0 {
		s.Env.ActiveCIDR = unique[0]
	}
	s.recompileScope()

	return unique, nil
}

// AddTarget adds an individual target scope.
func (s *Session) AddTarget(targetStr string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expanded, err := ParseTargetSpecification(targetStr)
	if err != nil {
		return nil, err
	}

	for _, exp := range expanded {
		found := false
		for _, existing := range s.Env.TargetScopes {
			if existing == exp {
				found = true
				break
			}
		}
		if !found {
			s.Env.TargetScopes = append(s.Env.TargetScopes, exp)
		}
	}

	if len(s.Env.TargetScopes) > 0 && s.Env.ActiveCIDR == "" {
		s.Env.ActiveCIDR = s.Env.TargetScopes[0]
	}
	s.recompileScope()

	return s.Env.TargetScopes, nil
}

// RemoveTarget removes a target from active targets.
func (s *Session) RemoveTarget(targetStr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var updated []string
	removed := false
	for _, t := range s.Env.TargetScopes {
		if strings.EqualFold(t, targetStr) {
			removed = true
		} else {
			updated = append(updated, t)
		}
	}
	s.Env.TargetScopes = updated
	if len(updated) > 0 {
		s.Env.ActiveCIDR = updated[0]
	} else {
		s.Env.ActiveCIDR = ""
	}
	s.recompileScope()
	return removed
}

// ClearTargets removes all active targets.
func (s *Session) ClearTargets() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Env.TargetScopes = []string{}
	s.Env.ActiveCIDR = ""
	s.recompileScope()
}

// AddEvidence records an empirical evidence entry in the session.
func (s *Session) AddEvidence(ev domain.Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("EVID-%d", time.Now().UnixNano())
	}
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = time.Now().UTC()
	}
	s.Evidence = append(s.Evidence, ev)
}

// GetEvidence returns a copy of all collected evidence items.
func (s *Session) GetEvidence() []domain.Evidence {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]domain.Evidence, len(s.Evidence))
	copy(res, s.Evidence)
	return res
}

// GetIdentities returns all current identities tracked by the fusion engine.
func (s *Session) GetIdentities() []schema.Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Fusion.GetAllIdentities()
}

// GetIdentityDrifts returns all detected identity drifts.
func (s *Session) GetIdentityDrifts() []schema.IdentityDrift {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Fusion.GetDrifts()
}

// IngestTelemetry fuses a telemetry observation into identities and evidence.
func (s *Session) IngestTelemetry(obs schema.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if obs.WorkspaceID == "" {
		obs.WorkspaceID = s.WorkspaceID
	}
	s.Fusion.IngestObservation(obs)
}

// GetTargets returns a copy of current target scopes.
func (s *Session) GetTargets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]string, len(s.Env.TargetScopes))
	copy(res, s.Env.TargetScopes)
	return res
}

// SetProfile updates the active probing profile.
func (s *Session) SetProfile(profile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Profile = profile
}

// GetProfile returns the active profile name.
func (s *Session) GetProfile() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Profile
}

// SetRateLimit sets the probes-per-second limit.
func (s *Session) SetRateLimit(rate int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rate < 1 {
		rate = 1
	}
	s.RateLimit = rate
}

// GetRateLimit returns the current rate limit.
func (s *Session) GetRateLimit() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RateLimit
}

// SetWorkers sets concurrent worker count.
func (s *Session) SetWorkers(workers int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if workers < 1 {
		workers = 1
	}
	s.Workers = workers
}

// GetWorkers returns worker count.
func (s *Session) GetWorkers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Workers
}

// SetPosture updates or inserts a SubnetPosture.
func (s *Session) SetPosture(posture schema.SubnetPosture) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Env.Postures == nil {
		s.Env.Postures = make(map[string]schema.SubnetPosture)
	}
	s.Env.Postures[posture.SubnetCIDR] = posture
}

// GetPosture retrieves a SubnetPosture by CIDR.
func (s *Session) GetPosture(cidr string) (schema.SubnetPosture, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.Env.Postures[cidr]
	return p, ok
}

// GetAllPostures returns a snapshot map of all posture evaluations.
func (s *Session) GetAllPostures() map[string]schema.SubnetPosture {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]schema.SubnetPosture, len(s.Env.Postures))
	for k, v := range s.Env.Postures {
		cp[k] = v
	}
	return cp
}

// AddDiscoveredHost records a host discovered dynamically (e.g. from passive sniffers).
func (s *Session) AddDiscoveredHost(subnetCIDR string, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	posture, exists := s.Env.Postures[subnetCIDR]
	if !exists {
		posture = schema.SubnetPosture{
			SubnetCIDR:   subnetCIDR,
			ExposedHosts: []string{},
			Compliance:   "UNKNOWN",
		}
	}

	for _, h := range posture.ExposedHosts {
		if h == ip {
			return
		}
	}
	posture.ExposedHosts = append(posture.ExposedHosts, ip)
	s.Env.Postures[subnetCIDR] = posture
}

// ParseTargetSpecification expands single IP, CIDR, hyphenated IP range, or validates domain.
func ParseTargetSpecification(spec string) ([]string, error) {
	// 1. IP Range: 192.168.1.1-192.168.1.50 or 192.168.1.1-50
	if strings.Contains(spec, "-") && !strings.Contains(spec, ":") {
		parts := strings.Split(spec, "-")
		if len(parts) == 2 {
			startStr := strings.TrimSpace(parts[0])
			endStr := strings.TrimSpace(parts[1])

			startIP := net.ParseIP(startStr)
			if startIP != nil && startIP.To4() != nil {
				var endIP net.IP
				if !strings.Contains(endStr, ".") {
					// Format: 192.168.1.1-50
					lastOctet, err := strconv.Atoi(endStr)
					if err == nil && lastOctet >= 0 && lastOctet <= 255 {
						ip4 := startIP.To4()
						endIP = net.IPv4(ip4[0], ip4[1], ip4[2], byte(lastOctet))
					}
				} else {
					endIP = net.ParseIP(endStr)
				}

				if endIP != nil && endIP.To4() != nil {
					return expandIPRange(startIP.To4(), endIP.To4())
				}
			}
		}
	}

	// 2. CIDR: 10.0.0.0/24
	if strings.Contains(spec, "/") {
		ip, ipNet, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		_ = ip
		return []string{ipNet.String()}, nil
	}

	// 3. Single IP: 192.168.1.1 or 2001:db8::1
	if ip := net.ParseIP(spec); ip != nil {
		return []string{ip.String()}, nil
	}

	// 4. Hostname / FQDN
	if isValidHostname(spec) {
		return []string{spec}, nil
	}

	return nil, fmt.Errorf("unrecognized format: %s", spec)
}

func expandIPRange(start, end net.IP) ([]string, error) {
	s := ipToUint32(start)
	e := ipToUint32(end)
	if s > e {
		s, e = e, s
	}

	// Safety cap: don't expand more than 4096 addresses in a single range specification
	if e-s > 4096 {
		return nil, fmt.Errorf("range size (%d) exceeds safety cap of 4096 hosts; use CIDR notation", e-s+1)
	}

	var ips []string
	for cur := s; cur <= e; cur++ {
		ips = append(ips, uint32ToIP(cur).String())
	}
	return ips, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func isValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, part := range strings.Split(h, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for _, ch := range part {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}
