package schema

import "time"

// ReachabilityState defines the deterministic classification of network reachability.
type ReachabilityState string

const (
	StateOpen       ReachabilityState = "REACHABLE"
	StateRefused    ReachabilityState = "REFUSED"
	StateTimeout    ReachabilityState = "TIMEOUT"
	StateNoResponse ReachabilityState = "NO_RESPONSE"
	StateFiltered   ReachabilityState = "FILTERED"
	StateAsymmetric ReachabilityState = "ASYMMETRIC_LEAK"
	StateIsolated   ReachabilityState = "STRICTLY_ISOLATED"
)

// ServiceProbeResult captures detailed inspection metrics for a probed service.
type ServiceProbeResult struct {
	Protocol    string            `json:"protocol"`
	Port        int               `json:"port"`
	ServiceName string            `json:"service_name"`
	Banner      string            `json:"banner,omitempty"`
	TLSDetails  map[string]string `json:"tls_details,omitempty"`
	State       ReachabilityState `json:"state"`
	LatencyMs   int64             `json:"latency_ms"`
}

// SubnetPosture captures security and reachability posture for a subnet.
type SubnetPosture struct {
	SubnetCIDR     string               `json:"subnet_cidr"`
	VLANID         int                  `json:"vlan_id,omitempty"`
	SwitchPort     string               `json:"switch_port,omitempty"`
	ExposedHosts   []string             `json:"exposed_hosts"`
	ProbedServices []ServiceProbeResult `json:"probed_services"`
	BlastScore     float64              `json:"blast_score"` // 0.0 to 10.0
	Compliance     string               `json:"compliance"`  // PASS / FAIL
}

// Identity represents a fused entity correlated from multiple telemetry sources.
type Identity struct {
	ID            string    `json:"id"`
	WorkspaceID   string    `json:"workspace_id"`
	PrimaryIP     string    `json:"primary_ip"`
	MACAddress    string    `json:"mac_address,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	OSFingerprint string    `json:"os_fingerprint,omitempty"`
	TLSNames      []string  `json:"tls_names,omitempty"`
	ADDomain      string    `json:"ad_domain,omitempty"`
	ADRoles       []string  `json:"ad_roles,omitempty"`
	Confidence    string    `json:"confidence"` // HIGH, MEDIUM, LOW
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// IdentityDrift tracks timeline changes and anomalies for an asset identity.
type IdentityDrift struct {
	IdentityID  string    `json:"identity_id"`
	PreviousIP  string    `json:"previous_ip"`
	NewIP       string    `json:"new_ip"`
	DetectedAt  time.Time `json:"detected_at"`
	Description string    `json:"description"`
}

// Observation represents an individual raw telemetry observation record.
type Observation struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	SourceID    string    `json:"source_id"`
	Kind        string    `json:"kind"` // flow, arp, dns, banner, tls
	TargetIP    string    `json:"target_ip"`
	Port        int       `json:"port,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	RawData     string    `json:"raw_data"`
	ObservedAt  time.Time `json:"observed_at"`
}

// SessionEnvironment encapsulates the real-time operational state.
type SessionEnvironment struct {
	SessionID    string                   `json:"session_id"`
	StartTime    time.Time                `json:"start_time"`
	ActiveCIDR   string                   `json:"active_cidr"`
	TargetScopes []string                 `json:"target_scopes"`
	Postures     map[string]SubnetPosture `json:"postures"`
	Identities   map[string]Identity      `json:"identities,omitempty"`
}
