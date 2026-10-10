// Package assessment implements deterministic rule-based evaluation of domain entities and evidence.
package assessment

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/graph"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// AssessmentContext holds input data and state for assessment evaluation.
type AssessmentContext struct {
	Workspace string
	Repo      *storage.Repository
	Graph     *graph.Graph
	Timestamp time.Time
}

// Rule defines an assessment rule interface.
type Rule interface {
	ID() string
	Name() string
	Category() domain.FindingCategory
	Evaluate(ctx *AssessmentContext) ([]domain.Finding, error)
}

// -------------------------------------------------------------------
// Rule: ServiceExposureRule
// -------------------------------------------------------------------

type ServiceExposureRule struct{}

func (r *ServiceExposureRule) ID() string                       { return "service-exposure" }
func (r *ServiceExposureRule) Name() string                     { return "Sensitive / Cleartext Service Exposure" }
func (r *ServiceExposureRule) Category() domain.FindingCategory { return domain.CategoryExposure }

func (r *ServiceExposureRule) Evaluate(ctx *AssessmentContext) ([]domain.Finding, error) {
	services, err := ctx.Repo.ListServices(ctx.Workspace)
	if err != nil {
		return nil, err
	}

	var findings []domain.Finding
	sensitivePorts := map[int]string{
		21:   "FTP (cleartext authentication)",
		23:   "Telnet (unencrypted terminal)",
		69:   "TFTP (unauthenticated file transfer)",
		80:   "HTTP (unencrypted web traffic)",
		5900: "VNC (remote desktop interface)",
		3389: "RDP (remote desktop interface)",
		513:  "rlogin (legacy cleartext service)",
		514:  "rsh (legacy cleartext service)",
	}

	for _, svc := range services {
		if svc.State != domain.ServiceStateOpen {
			continue
		}

		desc, isSensitive := sensitivePorts[svc.Port]
		if isSensitive {
			evList, _ := ctx.Repo.ListEvidenceByEntity("service", svc.ID)
			var evIDs []string
			for _, e := range evList {
				evIDs = append(evIDs, e.ID)
			}

			findings = append(findings, domain.Finding{
				WorkspaceID:   ctx.Workspace,
				RuleID:        r.ID(),
				Category:      r.Category(),
				Title:         fmt.Sprintf("Exposed %s on port %d/%s", desc, svc.Port, svc.Protocol),
				Description:   fmt.Sprintf("Service %s on asset %s is open with cleartext or remote management exposure: %s", svc.ID, svc.AssetID, desc),
				EntityType:    "service",
				EntityID:      svc.ID,
				EvidenceIDs:   evIDs,
				Status:        domain.FindingOpen,
				FirstObserved: svc.FirstObserved,
				LastObserved:  svc.LastObserved,
				CreatedAt:     ctx.Timestamp,
				UpdatedAt:     ctx.Timestamp,
			})
		}
	}

	return findings, nil
}

// -------------------------------------------------------------------
// Rule: GlobalAddressRule
// -------------------------------------------------------------------

type GlobalAddressRule struct{}

func (r *GlobalAddressRule) ID() string                       { return "global-address" }
func (r *GlobalAddressRule) Name() string                     { return "Public Routable Address on Internal Asset" }
func (r *GlobalAddressRule) Category() domain.FindingCategory { return domain.CategoryNetwork }

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func (r *GlobalAddressRule) Evaluate(ctx *AssessmentContext) ([]domain.Finding, error) {
	interfaces, err := ctx.Repo.ListInterfaces(ctx.Workspace)
	if err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, iface := range interfaces {
		if !isPrivateIP(iface.Address) {
			evList, _ := ctx.Repo.ListEvidenceByEntity("asset", iface.AssetID)
			var evIDs []string
			for _, e := range evList {
				evIDs = append(evIDs, e.ID)
			}

			findings = append(findings, domain.Finding{
				WorkspaceID:   ctx.Workspace,
				RuleID:        r.ID(),
				Category:      r.Category(),
				Title:         fmt.Sprintf("Public / Globally Routable IP %s Assigned", iface.Address),
				Description:   fmt.Sprintf("Interface %s on asset %s is configured with a globally routable public IP (%s)", iface.ID, iface.AssetID, iface.Address),
				EntityType:    "interface",
				EntityID:      iface.ID,
				EvidenceIDs:   evIDs,
				Status:        domain.FindingOpen,
				FirstObserved: iface.CreatedAt,
				LastObserved:  iface.UpdatedAt,
				CreatedAt:     ctx.Timestamp,
				UpdatedAt:     ctx.Timestamp,
			})
		}
	}

	return findings, nil
}

// -------------------------------------------------------------------
// Rule: OTIndicatorRule
// -------------------------------------------------------------------

type OTIndicatorRule struct{}

func (r *OTIndicatorRule) ID() string                       { return "ot-indicator" }
func (r *OTIndicatorRule) Name() string                     { return "OT / ICS Protocol Indicator" }
func (r *OTIndicatorRule) Category() domain.FindingCategory { return domain.CategoryOT }

func (r *OTIndicatorRule) Evaluate(ctx *AssessmentContext) ([]domain.Finding, error) {
	services, err := ctx.Repo.ListServices(ctx.Workspace)
	if err != nil {
		return nil, err
	}

	indicators := domain.KnownOTIndicators()
	indicatorMap := make(map[string]string) // "proto:port" -> name
	for _, ind := range indicators {
		indicatorMap[fmt.Sprintf("%s:%d", ind.Protocol, ind.Port)] = ind.Name
	}

	var findings []domain.Finding
	for _, svc := range services {
		key := fmt.Sprintf("%s:%d", svc.Protocol, svc.Port)
		name, isOT := indicatorMap[key]
		if !isOT && svc.ServiceName != "" {
			for _, ind := range indicators {
				if strings.EqualFold(svc.ServiceName, ind.Name) {
					isOT = true
					name = ind.Name
					break
				}
			}
		}

		if isOT {
			evList, _ := ctx.Repo.ListEvidenceByEntity("service", svc.ID)
			var evIDs []string
			for _, e := range evList {
				evIDs = append(evIDs, e.ID)
			}

			findings = append(findings, domain.Finding{
				WorkspaceID:   ctx.Workspace,
				RuleID:        r.ID(),
				Category:      r.Category(),
				Title:         fmt.Sprintf("OT / Industrial Control Protocol Indicator: %s (%d/%s)", name, svc.Port, svc.Protocol),
				Description:   fmt.Sprintf("Service %s on asset %s matches known OT/ICS indicator %s on port %d/%s. (Note: Port match indicates potential industrial protocol, not verified controller identity)", svc.ID, svc.AssetID, name, svc.Port, svc.Protocol),
				EntityType:    "service",
				EntityID:      svc.ID,
				EvidenceIDs:   evIDs,
				Status:        domain.FindingOpen,
				FirstObserved: svc.FirstObserved,
				LastObserved:  svc.LastObserved,
				CreatedAt:     ctx.Timestamp,
				UpdatedAt:     ctx.Timestamp,
			})
		}
	}

	return findings, nil
}

// -------------------------------------------------------------------
// Rule: MultiInterfaceRule
// -------------------------------------------------------------------

type MultiInterfaceRule struct{}

func (r *MultiInterfaceRule) ID() string                       { return "multi-interface" }
func (r *MultiInterfaceRule) Name() string                     { return "Multi-Homed / Bridging Asset" }
func (r *MultiInterfaceRule) Category() domain.FindingCategory { return domain.CategoryNetwork }

func (r *MultiInterfaceRule) Evaluate(ctx *AssessmentContext) ([]domain.Finding, error) {
	assets, err := ctx.Repo.ListAssets(ctx.Workspace)
	if err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, asset := range assets {
		ifaces, err := ctx.Repo.ListInterfacesByAsset(asset.ID)
		if err != nil {
			continue
		}

		if len(ifaces) > 1 {
			var addrs []string
			for _, iface := range ifaces {
				addrs = append(addrs, iface.Address)
			}

			evList, _ := ctx.Repo.ListEvidenceByEntity("asset", asset.ID)
			var evIDs []string
			for _, e := range evList {
				evIDs = append(evIDs, e.ID)
			}

			findings = append(findings, domain.Finding{
				WorkspaceID:   ctx.Workspace,
				RuleID:        r.ID(),
				Category:      r.Category(),
				Title:         fmt.Sprintf("Multi-Homed Asset Spanning %d Interfaces", len(ifaces)),
				Description:   fmt.Sprintf("Asset %s has %d configured network interfaces (%s), indicating multi-homing or potential network bridging.", asset.ID, len(ifaces), strings.Join(addrs, ", ")),
				EntityType:    "asset",
				EntityID:      asset.ID,
				EvidenceIDs:   evIDs,
				Status:        domain.FindingOpen,
				FirstObserved: asset.FirstObserved,
				LastObserved:  asset.LastObserved,
				CreatedAt:     ctx.Timestamp,
				UpdatedAt:     ctx.Timestamp,
			})
		}
	}

	return findings, nil
}

// -------------------------------------------------------------------
// Rule: TechnologyObservedRule
// -------------------------------------------------------------------

type TechnologyObservedRule struct{}

func (r *TechnologyObservedRule) ID() string                       { return "technology-observed" }
func (r *TechnologyObservedRule) Name() string                     { return "Identified Technology Stack" }
func (r *TechnologyObservedRule) Category() domain.FindingCategory { return domain.CategoryTechnology }

func (r *TechnologyObservedRule) Evaluate(ctx *AssessmentContext) ([]domain.Finding, error) {
	services, err := ctx.Repo.ListServices(ctx.Workspace)
	if err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, svc := range services {
		if svc.Technology != "" {
			evList, _ := ctx.Repo.ListEvidenceByEntity("service", svc.ID)
			var evIDs []string
			for _, e := range evList {
				evIDs = append(evIDs, e.ID)
			}

			ver := ""
			if svc.Version != "" {
				ver = fmt.Sprintf(" v%s", svc.Version)
			}

			findings = append(findings, domain.Finding{
				WorkspaceID:   ctx.Workspace,
				RuleID:        r.ID(),
				Category:      r.Category(),
				Title:         fmt.Sprintf("Identified %s%s on port %d/%s", svc.Technology, ver, svc.Port, svc.Protocol),
				Description:   fmt.Sprintf("Service %s on asset %s runs identified technology %s%s", svc.ID, svc.AssetID, svc.Technology, ver),
				EntityType:    "service",
				EntityID:      svc.ID,
				EvidenceIDs:   evIDs,
				Status:        domain.FindingOpen,
				FirstObserved: svc.FirstObserved,
				LastObserved:  svc.LastObserved,
				CreatedAt:     ctx.Timestamp,
				UpdatedAt:     ctx.Timestamp,
			})
		}
	}

	return findings, nil
}

// BuiltinRules returns all default assessment rules.
func BuiltinRules() []Rule {
	return []Rule{
		&ServiceExposureRule{},
		&GlobalAddressRule{},
		&OTIndicatorRule{},
		&MultiInterfaceRule{},
		&TechnologyObservedRule{},
	}
}
