package assessment

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// Explanation contains detailed explainability data for any intelligence conclusion.
type Explanation struct {
	TargetType   string                 `json:"target_type"` // ASSET, SERVICE, FINDING, PATH, RELATIONSHIP
	TargetID     string                 `json:"target_id"`
	Belief       string                 `json:"belief"`
	Rationale    string                 `json:"rationale"`
	EvidenceList []domain.Evidence      `json:"evidence_list"`
	Collectors   []string               `json:"collectors"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	Confidence   domain.ConfidenceLevel `json:"confidence"`
	IsSufficient bool                   `json:"is_sufficient"`

	// Legacy / finding compatibility fields
	FindingID   string `json:"finding_id,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Category    string `json:"category,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	EntityType  string `json:"entity_type,omitempty"`
	EntityID    string `json:"entity_id,omitempty"`
}

// Explainer generates detailed, evidence-backed explainability reports.
type Explainer struct {
	repo *storage.Repository
}

// NewExplainer creates a new Explainer.
func NewExplainer(repo *storage.Repository) *Explainer {
	return &Explainer{repo: repo}
}

// ExplainFinding generates an Explanation structure for a given finding ID.
func (e *Explainer) ExplainFinding(findingID string) (*Explanation, error) {
	fnd, err := e.repo.GetFinding(findingID)
	if err != nil {
		return nil, fmt.Errorf("finding query failed: %w", err)
	}
	if fnd == nil {
		return nil, fmt.Errorf("finding %s not found", findingID)
	}

	var evList []domain.Evidence
	collectorMap := make(map[string]bool)
	for _, evID := range fnd.EvidenceIDs {
		ev, err := e.repo.GetEvidence(evID)
		if err == nil && ev != nil {
			evList = append(evList, *ev)
			if ev.SourceID != "" {
				collectorMap[ev.SourceID] = true
			}
		}
	}

	var collectors []string
	for c := range collectorMap {
		collectors = append(collectors, c)
	}
	sort.Strings(collectors)

	belief := fmt.Sprintf("Security finding identified: %s on %s %s", fnd.Title, fnd.EntityType, fnd.EntityID)
	rationale := e.buildFindingRationale(fnd, evList)
	isSufficient := len(evList) > 0 && (fnd.Confidence == domain.ConfidenceHigh || fnd.Confidence == domain.ConfidenceObserved)

	return &Explanation{
		TargetType:   "FINDING",
		TargetID:     fnd.ID,
		Belief:       belief,
		Rationale:    rationale,
		EvidenceList: evList,
		Collectors:   collectors,
		FirstSeen:    fnd.FirstObserved,
		LastSeen:     fnd.LastObserved,
		Confidence:   fnd.Confidence,
		IsSufficient: isSufficient,

		// Backward compatibility
		FindingID:   fnd.ID,
		RuleID:      fnd.RuleID,
		Category:    string(fnd.Category),
		Title:       fnd.Title,
		Description: fnd.Description,
		Status:      string(fnd.Status),
		EntityType:  fnd.EntityType,
		EntityID:    fnd.EntityID,
	}, nil
}

// ExplainAsset generates an Explanation for an asset by ID, IP, or hostname.
func (e *Explainer) ExplainAsset(workspace, query string) (*Explanation, error) {
	var targetAsset *domain.Asset

	// 1. Direct ID
	a, err := e.repo.GetAsset(query)
	if err == nil && a != nil {
		targetAsset = a
	}

	// 2. Hostname
	if targetAsset == nil {
		a, err = e.repo.GetAssetByHostname(workspace, query)
		if err == nil && a != nil {
			targetAsset = a
		}
	}

	// 3. Search by IP address among interfaces
	if targetAsset == nil {
		assets, err := e.repo.ListAssets(workspace)
		if err == nil {
			for _, item := range assets {
				ifaces, _ := e.repo.ListInterfacesByAsset(item.ID)
				for _, ifc := range ifaces {
					if ifc.Address == query {
						targetAsset = &item
						break
					}
				}
				if targetAsset != nil {
					break
				}
			}
		}
	}

	if targetAsset == nil {
		return nil, fmt.Errorf("asset %q not found", query)
	}

	ifaces, _ := e.repo.ListInterfacesByAsset(targetAsset.ID)
	services, _ := e.repo.ListServicesByAsset(targetAsset.ID)
	allEv, _ := e.repo.ListEvidence(workspace)

	var evList []domain.Evidence
	collectorMap := make(map[string]bool)

	svcIDs := make(map[string]bool)
	for _, s := range services {
		svcIDs[s.ID] = true
	}

	for _, ev := range allEv {
		if ev.EntityID == targetAsset.ID || svcIDs[ev.EntityID] {
			evList = append(evList, ev)
			if ev.SourceID != "" {
				collectorMap[ev.SourceID] = true
			}
		}
	}

	var collectors []string
	for c := range collectorMap {
		collectors = append(collectors, c)
	}
	sort.Strings(collectors)

	var addrs []string
	for _, ifc := range ifaces {
		addrs = append(addrs, ifc.Address)
	}

	belief := fmt.Sprintf("Asset %s (hostname: %q, addresses: %s) with %d confirmed services",
		targetAsset.ID, targetAsset.Hostname, strings.Join(addrs, ", "), len(services))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Host identity correlated from %d network interfaces and %d active services.\n", len(ifaces), len(services)))
	if len(ifaces) > 1 {
		sb.WriteString("Multi-homed asset confirmed with presence in multiple subnets.\n")
	}
	if len(evList) > 0 {
		sb.WriteString("\nSupporting Evidence:\n")
		for i, ev := range evList {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s | Source: %s (observed %s)\n",
				i+1, ev.ID, ev.Description, ev.SourceID, ev.ObservedAt.Format(time.RFC3339)))
		}
	} else {
		sb.WriteString("No direct low-level evidence attached; host identity formed from structural observation.\n")
	}

	conf := domain.ConfidenceHigh
	if len(evList) == 0 {
		conf = domain.ConfidenceLow
	} else if len(evList) < 2 {
		conf = domain.ConfidenceMedium
	}

	isSufficient := len(evList) > 0 && conf != domain.ConfidenceLow

	firstSeen := targetAsset.CreatedAt
	lastSeen := targetAsset.UpdatedAt
	if len(evList) > 0 {
		firstSeen = evList[0].ObservedAt
		lastSeen = evList[len(evList)-1].ObservedAt
	}

	return &Explanation{
		TargetType:   "ASSET",
		TargetID:     targetAsset.ID,
		Belief:       belief,
		Rationale:    sb.String(),
		EvidenceList: evList,
		Collectors:   collectors,
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
		Confidence:   conf,
		IsSufficient: isSufficient,
		EntityType:   "asset",
		EntityID:     targetAsset.ID,
		Title:        belief,
		Description:  sb.String(),
	}, nil
}

// ExplainService generates an Explanation for a service by ID or port.
func (e *Explainer) ExplainService(workspace, query string) (*Explanation, error) {
	var targetSvc *domain.Service

	// 1. Direct ID
	s, err := e.repo.GetService(query)
	if err == nil && s != nil {
		targetSvc = s
	}

	// 2. Query as port or service name
	if targetSvc == nil {
		services, err := e.repo.ListServices(workspace)
		if err == nil {
			portNum, _ := strconv.Atoi(query)
			for _, item := range services {
				if item.ID == query || (portNum > 0 && item.Port == portNum) || strings.EqualFold(item.ServiceName, query) {
					targetSvc = &item
					break
				}
			}
		}
	}

	if targetSvc == nil {
		return nil, fmt.Errorf("service %q not found", query)
	}

	allEv, _ := e.repo.ListEvidence(workspace)
	var evList []domain.Evidence
	collectorMap := make(map[string]bool)

	for _, ev := range allEv {
		if ev.EntityID == targetSvc.ID {
			evList = append(evList, ev)
			if ev.SourceID != "" {
				collectorMap[ev.SourceID] = true
			}
		}
	}

	var collectors []string
	for c := range collectorMap {
		collectors = append(collectors, c)
	}
	sort.Strings(collectors)

	belief := fmt.Sprintf("Service %s on port %d/%s (Asset: %s)", targetSvc.ServiceName, targetSvc.Port, targetSvc.Protocol, targetSvc.AssetID)
	if targetSvc.Technology != "" {
		belief += fmt.Sprintf(" running %s %s", targetSvc.Technology, targetSvc.Version)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Service observation verified on port %d/%s.\n", targetSvc.Port, targetSvc.Protocol))
	if targetSvc.Technology != "" {
		sb.WriteString(fmt.Sprintf("Observed Technology: %s %s\n", targetSvc.Technology, targetSvc.Version))
	}
	if len(evList) > 0 {
		sb.WriteString("\nSupporting Evidence:\n")
		for i, ev := range evList {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s | Source: %s (observed %s)\n",
				i+1, ev.ID, ev.Description, ev.SourceID, ev.ObservedAt.Format(time.RFC3339)))
		}
	}

	conf := domain.ConfidenceHigh
	if len(evList) == 0 && targetSvc.Technology == "" {
		conf = domain.ConfidenceLow
	}

	firstSeen := targetSvc.FirstObserved
	lastSeen := targetSvc.LastObserved
	if len(evList) > 0 {
		firstSeen = evList[0].ObservedAt
		lastSeen = evList[len(evList)-1].ObservedAt
	}

	return &Explanation{
		TargetType:   "SERVICE",
		TargetID:     targetSvc.ID,
		Belief:       belief,
		Rationale:    sb.String(),
		EvidenceList: evList,
		Collectors:   collectors,
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
		Confidence:   conf,
		IsSufficient: len(evList) > 0 || targetSvc.Technology != "",
		EntityType:   "service",
		EntityID:     targetSvc.ID,
		Title:        belief,
		Description:  sb.String(),
	}, nil
}

// ExplainRelationship generates an Explanation for an edge/relationship.
func (e *Explainer) ExplainRelationship(sourceID, targetID, relType string, conf domain.ConfidenceLevel, evList []domain.Evidence) *Explanation {
	belief := fmt.Sprintf("Relationship %s between %s and %s", relType, sourceID, targetID)

	var collectors []string
	collectorMap := make(map[string]bool)
	for _, ev := range evList {
		if ev.SourceID != "" {
			collectorMap[ev.SourceID] = true
		}
	}
	for c := range collectorMap {
		collectors = append(collectors, c)
	}
	sort.Strings(collectors)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Graph edge connects node %s to node %s with relationship type %s.\n", sourceID, targetID, relType))
	if len(evList) > 0 {
		sb.WriteString("\nSupporting Evidence:\n")
		for i, ev := range evList {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s | Source: %s\n", i+1, ev.ID, ev.Description, ev.SourceID))
		}
	}

	isSufficient := len(evList) > 0 && conf != domain.ConfidenceLow

	return &Explanation{
		TargetType:   "RELATIONSHIP",
		TargetID:     fmt.Sprintf("%s->%s", sourceID, targetID),
		Belief:       belief,
		Rationale:    sb.String(),
		EvidenceList: evList,
		Collectors:   collectors,
		FirstSeen:    time.Now().UTC(),
		LastSeen:     time.Now().UTC(),
		Confidence:   conf,
		IsSufficient: isSufficient,
		EntityType:   "relationship",
		EntityID:     fmt.Sprintf("%s->%s", sourceID, targetID),
		Title:        belief,
		Description:  sb.String(),
	}
}

// ExplainGeneral resolves any target identifier (finding, asset, service, or path) into an Explanation.
func (e *Explainer) ExplainGeneral(workspace, query string) (*Explanation, error) {
	// 1. Try Finding
	if strings.HasPrefix(strings.ToUpper(query), "FIND-") {
		return e.ExplainFinding(query)
	}

	// 2. Try Asset
	if strings.HasPrefix(strings.ToUpper(query), "ASSET-") {
		return e.ExplainAsset(workspace, query)
	}

	// 3. Try Service
	if strings.HasPrefix(strings.ToUpper(query), "SVC-") {
		return e.ExplainService(workspace, query)
	}

	// 4. Try finding if exists
	fnd, err := e.repo.GetFinding(query)
	if err == nil && fnd != nil {
		return e.ExplainFinding(query)
	}

	// 5. Try asset
	ast, err := e.repo.GetAsset(query)
	if err == nil && ast != nil {
		return e.ExplainAsset(workspace, query)
	}

	// 6. Try service
	svc, err := e.repo.GetService(query)
	if err == nil && svc != nil {
		return e.ExplainService(workspace, query)
	}

	// 7. Try finding asset by IP or hostname
	expAsset, err := e.ExplainAsset(workspace, query)
	if err == nil && expAsset != nil {
		return expAsset, nil
	}

	// 8. Try service by port or name
	expSvc, err := e.ExplainService(workspace, query)
	if err == nil && expSvc != nil {
		return expSvc, nil
	}

	return nil, fmt.Errorf("entity %q not found across findings, assets, or services", query)
}

func (e *Explainer) buildFindingRationale(fnd *domain.Finding, evList []domain.Evidence) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Rule %q flagged entity %s (%s).\n", fnd.RuleID, fnd.EntityID, fnd.EntityType))
	sb.WriteString(fmt.Sprintf("Evaluation concluded: %s\n\n", fnd.Description))

	if len(evList) > 0 {
		sb.WriteString("Verified Evidence Chain:\n")
		for i, ev := range evList {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s | Source: %s (observed %s)\n",
				i+1, ev.ID, ev.Description, ev.SourceID, ev.ObservedAt.Format(time.RFC3339)))
		}
	} else {
		sb.WriteString("No direct evidence records linked (inferred or topological rule).\n")
	}

	return sb.String()
}

// Suppress unused import errors if sql isn't directly queried
var _ = sql.ErrNoRows
