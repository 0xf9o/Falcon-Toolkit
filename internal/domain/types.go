// Package domain defines the core entity types for Falcon ToolKit.
// All domain types are persistence-agnostic and represent the application's
// source of truth for Red Team intelligence and assessment data.
package domain

import (
	"fmt"
	"time"
)

// -------------------------------------------------------------------
// Workspace
// -------------------------------------------------------------------

// Workspace represents an isolated working environment containing its own
// set of assets, evidence, findings, and other domain objects.
type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// -------------------------------------------------------------------
// Engagement & Scope
// -------------------------------------------------------------------

// EngagementStatus represents the state of a Red Team engagement.
type EngagementStatus string

const (
	EngagementActive    EngagementStatus = "active"
	EngagementCompleted EngagementStatus = "completed"
	EngagementArchived  EngagementStatus = "archived"
)

// Engagement represents a Red Team assessment campaign.
type Engagement struct {
	ID          string           `json:"id"`
	WorkspaceID string           `json:"workspace_id"`
	Name        string           `json:"name"`
	Type        string           `json:"type"` // e.g. "Internal Assessment", "External Surface", "Assumed Breach"
	Status      EngagementStatus `json:"status"`
	Description string           `json:"description,omitempty"`
	Objectives  []Objective      `json:"objectives,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// Objective represents a goal or milestone in an engagement.
type Objective struct {
	ID           string    `json:"id"`
	EngagementID string    `json:"engagement_id"`
	Title        string    `json:"title"`
	Completed    bool      `json:"completed"`
	CreatedAt    time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// Asset
// -------------------------------------------------------------------

// Asset represents a discovered network entity such as a host, device,
// or controller. Assets are identified through the observation pipeline
// and resolved via identity resolution.
type Asset struct {
	ID            string    `json:"asset_id"`
	WorkspaceID   string    `json:"workspace_id"`
	Hostname      string    `json:"hostname,omitempty"`
	FirstObserved time.Time `json:"first_observed"`
	LastObserved  time.Time `json:"last_observed"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// -------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------

// Interface represents a network interface belonging to an asset,
// identified by an IP address and optional MAC address.
type Interface struct {
	ID         string    `json:"interface_id"`
	AssetID    string    `json:"asset_id"`
	Address    string    `json:"address"`
	MACAddress string    `json:"mac_address,omitempty"`
	NetworkID  string    `json:"network_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// -------------------------------------------------------------------
// Service
// -------------------------------------------------------------------

// ServiceState represents the observed state of a network service.
type ServiceState string

const (
	ServiceStateOpen     ServiceState = "open"
	ServiceStateClosed   ServiceState = "closed"
	ServiceStateFiltered ServiceState = "filtered"
	ServiceStateUnknown  ServiceState = "unknown"
)

// ReachabilityState describes the outcome of an authorized network communication probe.
type ReachabilityState string

const (
	ReachReachable       ReachabilityState = "REACHABLE"
	ReachRefused         ReachabilityState = "REFUSED"
	ReachTimeout         ReachabilityState = "TIMEOUT"
	ReachUnreachable     ReachabilityState = "UNREACHABLE"
	ReachNoResponse      ReachabilityState = "NO_RESPONSE"
	ReachICMPUnreachable ReachabilityState = "ICMP_UNREACHABLE"
	ReachError           ReachabilityState = "ERROR"
	ReachUnknown         ReachabilityState = "UNKNOWN"
	ReachNotTested       ReachabilityState = "NOT_TESTED"
)

// Service represents a network service observed on an asset.
type Service struct {
	ID            string       `json:"service_id"`
	AssetID       string       `json:"asset_id"`
	Protocol      string       `json:"protocol"`
	Port          int          `json:"port"`
	State         ServiceState `json:"state"`
	ServiceName   string       `json:"service_name,omitempty"`
	Technology    string       `json:"technology,omitempty"`
	Version       string       `json:"version,omitempty"`
	FirstObserved time.Time    `json:"first_observed"`
	LastObserved  time.Time    `json:"last_observed"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// -------------------------------------------------------------------
// Network
// -------------------------------------------------------------------

// Network represents an observed network segment, typically defined by
// a CIDR block.
type Network struct {
	ID          string    `json:"network_id"`
	WorkspaceID string    `json:"workspace_id"`
	CIDR        string    `json:"cidr"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// -------------------------------------------------------------------
// Relationship
// -------------------------------------------------------------------

// RelationshipType defines the kind of relationship between two graph nodes.
type RelationshipType string

const (
	RelOwns         RelationshipType = "owns"
	RelHasInterface RelationshipType = "has_interface"
	RelHosts        RelationshipType = "hosts"
	RelExposes      RelationshipType = "exposes"
	RelBelongsTo    RelationshipType = "belongs_to"
	RelObservedOn   RelationshipType = "observed_on"
	RelConnectedTo  RelationshipType = "connected_to"
	RelEvidencedBy  RelationshipType = "evidenced_by"
	RelResolvesTo   RelationshipType = "resolves_to"
	RelAliasOf      RelationshipType = "alias_of"
	RelMailServer   RelationshipType = "mail_server"
	RelNameserver   RelationshipType = "nameserver"
	RelPresents     RelationshipType = "presents"
	RelIdentifies   RelationshipType = "identifies"
	RelIssuedBy     RelationshipType = "issued_by"
	RelServes       RelationshipType = "serves"
	RelRoutesTo     RelationshipType = "routes_to"
	RelTargets      RelationshipType = "targets"
	RelSpeaks       RelationshipType = "speaks"
	RelUses         RelationshipType = "uses"
	RelRuns         RelationshipType = "runs"
	RelCrosses      RelationshipType = "crosses"
	RelSupportedBy  RelationshipType = "supported_by"
)

// Relationship represents a directed edge between two entities in the
// domain graph.
type Relationship struct {
	ID         string           `json:"relationship_id"`
	SourceType string           `json:"source_type"`
	SourceID   string           `json:"source_id"`
	TargetType string           `json:"target_type"`
	TargetID   string           `json:"target_id"`
	Type       RelationshipType `json:"type"`
	CreatedAt  time.Time        `json:"created_at"`
}

// -------------------------------------------------------------------
// Observation
// -------------------------------------------------------------------

// ObservationKind describes the type of raw observation.
type ObservationKind string

const (
	ObsAsset     ObservationKind = "asset"
	ObsInterface ObservationKind = "interface"
	ObsService   ObservationKind = "service"
	ObsNetwork   ObservationKind = "network"
	ObsRoute     ObservationKind = "route"
)

// Observation represents a raw data point from an external source before
// identity resolution and normalization.
type Observation struct {
	ID          string          `json:"observation_id"`
	SourceID    string          `json:"source_id"`
	Kind        ObservationKind `json:"kind"`
	RawData     string          `json:"raw_data"`
	ObservedAt  time.Time       `json:"observed_at"`
	WorkspaceID string          `json:"workspace_id"`
	CreatedAt   time.Time       `json:"created_at"`
}

// -------------------------------------------------------------------
// Evidence
// -------------------------------------------------------------------

// EvidenceCategory classifies the type of evidence.
type EvidenceCategory string

const (
	EvidenceDirect   EvidenceCategory = "direct"
	EvidenceInferred EvidenceCategory = "inferred"
	EvidenceReported EvidenceCategory = "reported"
	EvidenceManual   EvidenceCategory = "manual"
)

// ConfidenceLevel describes evidentiary certainty.
type ConfidenceLevel string

const (
	ConfObserved ConfidenceLevel = "OBSERVED"
	ConfHigh     ConfidenceLevel = "HIGH"
	ConfMedium   ConfidenceLevel = "MEDIUM"
	ConfLow      ConfidenceLevel = "LOW"
	ConfDerived  ConfidenceLevel = "DERIVED"
	ConfInferred ConfidenceLevel = "INFERRED"
	ConfUnknown  ConfidenceLevel = "UNKNOWN"

	// Convenient aliases
	ConfidenceObserved = ConfObserved
	ConfidenceHigh     = ConfHigh
	ConfidenceMedium   = ConfMedium
	ConfidenceLow      = ConfLow
	ConfidenceInferred = ConfInferred
)

// Evidence represents a verified observation that has been through the
// normalization and identity resolution pipeline.
type Evidence struct {
	ID            string           `json:"evidence_id"`
	WorkspaceID   string           `json:"workspace_id"`
	SourceID      string           `json:"source_id"`
	Category      EvidenceCategory `json:"category"`
	Confidence    ConfidenceLevel  `json:"confidence"`
	EntityType    string           `json:"entity_type"`
	EntityID      string           `json:"entity_id"`
	Protocol      string           `json:"protocol,omitempty"`
	Port          int              `json:"port,omitempty"`
	ServiceName   string           `json:"service_name,omitempty"`
	Technology    string           `json:"technology,omitempty"`
	Address       string           `json:"address,omitempty"`
	Description   string           `json:"description,omitempty"`
	ObservedAt    time.Time        `json:"observed_at"`
	FirstObserved time.Time        `json:"first_observed"`
	LastObserved  time.Time        `json:"last_observed"`
	CreatedAt     time.Time        `json:"created_at"`
}

// -------------------------------------------------------------------
// Finding
// -------------------------------------------------------------------

// FindingStatus represents the lifecycle state of a finding.
type FindingStatus string

const (
	FindingOpen         FindingStatus = "open"
	FindingAcknowledged FindingStatus = "acknowledged"
	FindingResolved     FindingStatus = "resolved"
)

// FindingCategory categorizes findings for filtering.
type FindingCategory string

const (
	CategoryOT         FindingCategory = "ot"
	CategoryExposure   FindingCategory = "exposure"
	CategoryNetwork    FindingCategory = "network"
	CategoryTechnology FindingCategory = "technology"
)

// Finding represents an assessment result traceable to evidence and rules.
type Finding struct {
	ID            string          `json:"finding_id"`
	WorkspaceID   string          `json:"workspace_id"`
	RuleID        string          `json:"rule_id"`
	Category      FindingCategory `json:"category"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	EntityType    string          `json:"entity_type"`
	EntityID      string          `json:"entity_id"`
	EvidenceIDs   []string        `json:"evidence_ids"`
	Confidence    ConfidenceLevel `json:"confidence"`
	Status        FindingStatus   `json:"status"`
	FirstObserved time.Time       `json:"first_observed"`
	LastObserved  time.Time       `json:"last_observed"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// -------------------------------------------------------------------
// Assessment
// -------------------------------------------------------------------

// Assessment represents a single run of the assessment engine.
type Assessment struct {
	ID             string    `json:"assessment_id"`
	WorkspaceID    string    `json:"workspace_id"`
	RulesetVersion string    `json:"ruleset_version"`
	SchemaVersion  string    `json:"schema_version"`
	TotalFindings  int       `json:"total_findings"`
	NewFindings    int       `json:"new_findings"`
	CreatedAt      time.Time `json:"created_at"`
}

// AssessmentSnapshot stores a point-in-time snapshot of an assessment.
type AssessmentSnapshot struct {
	ID           string    `json:"snapshot_id"`
	AssessmentID string    `json:"assessment_id"`
	WorkspaceID  string    `json:"workspace_id"`
	SnapshotData string    `json:"snapshot_data"` // JSON
	CreatedAt    time.Time `json:"created_at"`
}

// ReportSnapshot stores a generated report.
type ReportSnapshot struct {
	ID          string    `json:"report_id"`
	WorkspaceID string    `json:"workspace_id"`
	Format      string    `json:"format"`
	Content     string    `json:"content"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// Target
// -------------------------------------------------------------------

// TargetType classifies a target definition.
type TargetType string

const (
	TargetDomain   TargetType = "domain"
	TargetHostname TargetType = "hostname"
	TargetIPv4     TargetType = "ipv4"
	TargetIPv6     TargetType = "ipv6"
	TargetCIDR     TargetType = "cidr"
	TargetURL      TargetType = "url"

	// Backward compatibility aliases
	TargetIP      TargetType = "ip"
	TargetNetwork TargetType = "network"
	TargetAsset   TargetType = "asset"
)

// TargetStatus represents the lifecycle state of a target.
type TargetStatus string

const (
	TargetStatusPending   TargetStatus = "pending"
	TargetStatusActive    TargetStatus = "active"
	TargetStatusExcluded  TargetStatus = "excluded"
	TargetStatusCompleted TargetStatus = "completed"
)

// TargetScope indicates whether a target is in or out of scope.
type TargetScope string

const (
	TargetInScope    TargetScope = "in_scope"
	TargetOutOfScope TargetScope = "out_of_scope"
)

// Target represents a target definition for assessment purposes.
type Target struct {
	ID              string            `json:"target_id"`
	WorkspaceID     string            `json:"workspace_id"`
	Input           string            `json:"input"`
	NormalizedValue string            `json:"normalized_value"`
	Value           string            `json:"value"` // Maintained for backward compatibility
	Type            TargetType        `json:"type"`
	Scope           TargetScope       `json:"scope"`
	Status          TargetStatus      `json:"status"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// -------------------------------------------------------------------
// Scope
// -------------------------------------------------------------------

// ScopeRuleType indicates whether a rule includes or excludes targets.
type ScopeRuleType string

const (
	ScopeInclude ScopeRuleType = "include"
	ScopeExclude ScopeRuleType = "exclude"
)

// ScopeRule represents an authorization boundary rule.
type ScopeRule struct {
	ID          string        `json:"id"`
	WorkspaceID string        `json:"workspace_id"`
	RuleType    ScopeRuleType `json:"rule_type"`
	TargetType  TargetType    `json:"target_type"`
	Pattern     string        `json:"pattern"`
	Description string        `json:"description,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
}

// -------------------------------------------------------------------
// Assessment Plan
// -------------------------------------------------------------------

// AssessmentPlan represents a verified pre-execution plan for a target.
type AssessmentPlan struct {
	TargetID          string                 `json:"target_id"`
	TargetValue       string                 `json:"target_value"`
	TargetType        TargetType             `json:"target_type"`
	Profile           string                 `json:"profile"`
	ScopeSummary      string                 `json:"scope_summary"`
	RateLimit         string                 `json:"rate_limit"`
	Timeout           string                 `json:"timeout"`
	Workers           int                    `json:"workers"`
	ScopeGuard        bool                   `json:"scope_guard"`
	DiscoverySteps    []string               `json:"discovery_steps"`
	CorrelationSteps  []string               `json:"correlation_steps"`
	IntelligenceSteps []string               `json:"intelligence_steps"`
	EstimatedHosts    int                    `json:"estimated_hosts"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// -------------------------------------------------------------------
// Assessment Run & Lifecycle
// -------------------------------------------------------------------

// RunStatus defines the execution state of an assessment run.
type RunStatus string

const (
	RunPlanned   RunStatus = "PLANNED"
	RunRunning   RunStatus = "RUNNING"
	RunCompleted RunStatus = "COMPLETED"
	RunFailed    RunStatus = "FAILED"
	RunCancelled RunStatus = "CANCELLED"
)

// AssessmentRun records the execution lifecycle, parameters, and results of an assessment.
type AssessmentRun struct {
	ID             string          `json:"run_id"`
	WorkspaceID    string          `json:"workspace_id"`
	TargetID       string          `json:"target_id,omitempty"`
	TargetValue    string          `json:"target_value,omitempty"`
	Plan           *AssessmentPlan `json:"plan,omitempty"`
	Status         RunStatus       `json:"status"`
	StartedAt      time.Time       `json:"started_at"`
	CompletedAt    time.Time       `json:"completed_at,omitempty"`
	CollectorStats map[string]int  `json:"collector_stats,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// -------------------------------------------------------------------
// Source
// -------------------------------------------------------------------

// Source describes an import source/format that Falcon understands.
type Source struct {
	ID          string `json:"source_id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Format      string `json:"format"`
}

// BuiltinSources returns the list of built-in import sources.
func BuiltinSources() []Source {
	return []Source{
		{ID: "json", Name: "JSON", Version: "1.0", Description: "Falcon JSON observation format", Format: "json"},
		{ID: "nmapxml", Name: "Nmap XML", Version: "1.0", Description: "Nmap XML scan output", Format: "xml"},
		{ID: "dnsdata", Name: "DNS Data", Version: "1.0", Description: "Static DNS records", Format: "text"},
		{ID: "arp", Name: "ARP", Version: "1.0", Description: "ARP table data", Format: "text"},
		{ID: "routing", Name: "Routing", Version: "1.0", Description: "Routing table data", Format: "text"},
		{ID: "pcapmeta", Name: "PCAP Metadata", Version: "1.0", Description: "PCAP flow metadata (JSON)", Format: "json"},
		{ID: "manual", Name: "Manual", Version: "1.0", Description: "Manual structured observations", Format: "json"},
	}
}

// -------------------------------------------------------------------
// Tag
// -------------------------------------------------------------------

// Tag represents user-applied metadata on an entity.
type Tag struct {
	ID         string    `json:"tag_id"`
	EntityType string    `json:"entity_type"`
	EntityID   string    `json:"entity_id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// Note
// -------------------------------------------------------------------

// Note represents a user annotation on an entity.
type Note struct {
	ID         string    `json:"note_id"`
	EntityType string    `json:"entity_type"`
	EntityID   string    `json:"entity_id"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// AuditEvent
// -------------------------------------------------------------------

// AuditAction classifies the type of audited operation.
type AuditAction string

const (
	AuditImport           AuditAction = "import"
	AuditAssessment       AuditAction = "assessment"
	AuditReportGenerated  AuditAction = "report_generated"
	AuditWorkspaceCreated AuditAction = "workspace_created"
	AuditWorkspaceUsed    AuditAction = "workspace_used"
	AuditWorkspaceDeleted AuditAction = "workspace_deleted"
	AuditWorkspaceExport  AuditAction = "workspace_export"
	AuditWorkspaceImport  AuditAction = "workspace_import"
	AuditFindingChanged   AuditAction = "finding_changed"
	AuditTagChanged       AuditAction = "tag_changed"
	AuditNoteCreated      AuditAction = "note_created"
)

// AuditEvent records a workspace mutation for traceability.
type AuditEvent struct {
	ID          string      `json:"audit_id"`
	WorkspaceID string      `json:"workspace_id"`
	Action      AuditAction `json:"action"`
	EntityType  string      `json:"entity_type,omitempty"`
	EntityID    string      `json:"entity_id,omitempty"`
	Detail      string      `json:"detail,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
}

// -------------------------------------------------------------------
// Module
// -------------------------------------------------------------------

// ModuleStatus indicates the health state of an in-process module.
type ModuleStatus string

const (
	ModuleReady    ModuleStatus = "READY"
	ModuleError    ModuleStatus = "ERROR"
	ModuleDisabled ModuleStatus = "DISABLED"
)

// ModuleType classifies the function of a module.
type ModuleType string

const (
	ModuleTypeCore      ModuleType = "core"
	ModuleTypeAnalysis  ModuleType = "analysis"
	ModuleTypeImporter  ModuleType = "importer"
	ModuleTypeReporting ModuleType = "reporting"
)

// Module represents an in-process capability module.
type Module struct {
	ID           string       `json:"module_id"`
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Description  string       `json:"description"`
	Type         ModuleType   `json:"type"`
	Capabilities []string     `json:"capabilities"`
	Status       ModuleStatus `json:"status"`
}

// -------------------------------------------------------------------
// SavedQuery
// -------------------------------------------------------------------

// SavedQuery stores a named Falcon command for reuse.
type SavedQuery struct {
	ID          string    `json:"query_id"`
	WorkspaceID string    `json:"workspace_id"`
	Name        string    `json:"name"`
	Command     string    `json:"command"`
	CreatedAt   time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// SchemaMetadata
// -------------------------------------------------------------------

// SchemaMetadata tracks the database schema version.
type SchemaMetadata struct {
	Version   int       `json:"version"`
	AppliedAt time.Time `json:"applied_at"`
}

// -------------------------------------------------------------------
// Red Team Intelligence Models
// -------------------------------------------------------------------

// AttackSurfaceSummary represents the analytical attack-surface metrics.
type AttackSurfaceSummary struct {
	AssetCount           int            `json:"asset_count"`
	NetworkCount         int            `json:"network_count"`
	ServiceCount         int            `json:"service_count"`
	TechnologyCount      int            `json:"technology_count"`
	OTCount              int            `json:"ot_count"`
	TrustBoundaryCount   int            `json:"trust_boundary_count"`
	FindingCount         int            `json:"finding_count"`
	InternetAddressed    int            `json:"internet_addressed"`
	MultiInterface       int            `json:"multi_interface"`
	CrossNetworkLinks    int            `json:"cross_network_links"`
	UnclassifiedServices int            `json:"unclassified_services"`
	UnknownTechnologies  int            `json:"unknown_technologies"`
	MissingProvenance    int            `json:"missing_provenance"`
	CategoryCounts       map[string]int `json:"category_counts,omitempty"`
}

// AttackPath represents an observed multi-hop analytical path between networks/assets.
type AttackPath struct {
	ID            string          `json:"id"`
	Title         string          `json:"title"`
	Steps         []string        `json:"steps"`
	EvidenceCount int             `json:"evidence_count"`
	Confidence    ConfidenceLevel `json:"confidence"`
}

// PivotCandidate represents a host with multi-homing or cross-network visibility.
type PivotCandidate struct {
	AssetID        string   `json:"asset_id"`
	Hostname       string   `json:"hostname"`
	Addresses      []string `json:"addresses"`
	InterfaceCount int      `json:"interface_count"`
	ServiceCount   int      `json:"service_count"`
	Reason         string   `json:"reason"`
}

// TrustBoundary represents observed separation between network zones.
type TrustBoundary struct {
	FromZone         string   `json:"from_zone"`
	ToZone           string   `json:"to_zone"`
	ConnectingAssets []string `json:"connecting_assets"`
	IsInferred       bool     `json:"is_inferred"`
}

// TimelineItem represents a chronological intelligence event.
type TimelineItem struct {
	Timestamp   time.Time `json:"timestamp"`
	Kind        string    `json:"kind"`
	EntityID    string    `json:"entity_id"`
	Description string    `json:"description"`
}

// -------------------------------------------------------------------
// OT Indicators
// -------------------------------------------------------------------

// OTIndicator maps a port/protocol combination to an OT/ICS technology indicator.
type OTIndicator struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
}

// KnownOTIndicators returns the documented OT/ICS port indicators.
func KnownOTIndicators() []OTIndicator {
	return []OTIndicator{
		{Protocol: "tcp", Port: 502, Name: "Modbus/TCP"},
		{Protocol: "tcp", Port: 4840, Name: "OPC UA"},
		{Protocol: "tcp", Port: 102, Name: "S7"},
		{Protocol: "tcp", Port: 44818, Name: "EtherNet/IP"},
		{Protocol: "tcp", Port: 20000, Name: "DNP3"},
	}
}

// -------------------------------------------------------------------
// ID Formatting
// -------------------------------------------------------------------

func FormatAssetID(seq int) string {
	return fmt.Sprintf("ASSET-%03d", seq)
}

func FormatServiceID(seq int) string {
	return fmt.Sprintf("SVC-%03d", seq)
}

func FormatNetworkID(seq int) string {
	return fmt.Sprintf("NET-%03d", seq)
}

func FormatInterfaceID(seq int) string {
	return fmt.Sprintf("IF-%03d", seq)
}

func FormatEvidenceID(seq int) string {
	return fmt.Sprintf("EV-%04d", seq)
}

func FormatFindingID(seq int) string {
	return fmt.Sprintf("FND-%04d", seq)
}

func FormatObservationID(seq int) string {
	return fmt.Sprintf("OBS-%04d", seq)
}

func FormatRelationshipID(seq int) string {
	return fmt.Sprintf("REL-%04d", seq)
}

func FormatTargetID(seq int) string {
	return fmt.Sprintf("TGT-%03d", seq)
}

func FormatAssessmentID(seq int) string {
	return fmt.Sprintf("ASSESS-%03d", seq)
}

func FormatAuditID(seq int) string {
	return fmt.Sprintf("AUD-%04d", seq)
}

func FormatEngagementID(seq int) string {
	return fmt.Sprintf("ENG-%03d", seq)
}

func FormatScopeRuleID(seq int) string {
	return fmt.Sprintf("SCP-%03d", seq)
}

func FormatRunID(seq int) string {
	return fmt.Sprintf("RUN-%03d", seq)
}
