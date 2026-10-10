package observation

import (
	"fmt"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/protocol"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// Pipeline orchestrates the ingestion of observations into verified domain entities and evidence.
type Pipeline struct {
	repo       *storage.Repository
	normalizer *Normalizer
	resolver   *Resolver
	identifier *protocol.Identifier
}

// NewPipeline creates a new Observation Pipeline.
func NewPipeline(repo *storage.Repository) *Pipeline {
	return &Pipeline{
		repo:       repo,
		normalizer: NewNormalizer(),
		resolver:   NewResolver(repo),
		identifier: protocol.NewIdentifier(),
	}
}

// HostObservation represents an observation of a host/node with its interfaces and services.
type HostObservation struct {
	IPAddress  string
	MACAddress string
	Hostname   string
	ObservedAt time.Time
	SourceID   string
	Services   []ServiceObservation
	Tags       []string
}

// ServiceObservation represents an observed network service.
type ServiceObservation struct {
	Protocol    string
	Port        int
	State       domain.ServiceState
	ServiceName string
	Technology  string
	Version     string
	Description string
}

// NetworkObservation represents an observed network segment / CIDR.
type NetworkObservation struct {
	CIDR        string
	Name        string
	Description string
	ObservedAt  time.Time
	SourceID    string
}

// IngestResult reports statistics from an ingestion run.
type IngestResult struct {
	AssetsCreated      int
	InterfacesCreated  int
	ServicesCreated    int
	NetworksCreated    int
	EvidenceRecorded   int
	ObservationsStored int
}

// IngestHost processes a single host observation through the entire pipeline.
func (p *Pipeline) IngestHost(workspace string, obs *HostObservation) (*IngestResult, error) {
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	if obs.SourceID == "" {
		obs.SourceID = "unknown"
	}

	result := &IngestResult{}

	// Normalize IP
	var normIP string
	if obs.IPAddress != "" {
		ip, ok := p.normalizer.NormalizeIP(obs.IPAddress)
		if !ok {
			return nil, fmt.Errorf("invalid IP address: %s", obs.IPAddress)
		}
		normIP = ip
	}

	// Normalize MAC
	var normMAC string
	if obs.MACAddress != "" {
		mac, ok := p.normalizer.NormalizeMAC(obs.MACAddress)
		if ok {
			normMAC = mac
		}
	}

	// Normalize Hostname
	normHostname := p.normalizer.NormalizeHostname(obs.Hostname)

	// Resolve Identity
	res, err := p.resolver.ResolveHost(workspace, normIP, normHostname, normMAC, obs.ObservedAt)
	if err != nil {
		return nil, fmt.Errorf("resolving host identity: %w", err)
	}

	if res.IsNewAsset {
		result.AssetsCreated++
	}
	if res.IsNewIface {
		result.InterfacesCreated++
	}

	asset := res.Asset

	// Record Asset Evidence
	evSeq, _ := p.repo.NextSequence(workspace, "evidence")
	assetEvidence := &domain.Evidence{
		ID:            domain.FormatEvidenceID(evSeq),
		WorkspaceID:   workspace,
		SourceID:      obs.SourceID,
		Category:      domain.EvidenceDirect,
		EntityType:    "asset",
		EntityID:      asset.ID,
		Address:       normIP,
		Description:   fmt.Sprintf("Host observed with IP %s, hostname %s", normIP, normHostname),
		ObservedAt:    obs.ObservedAt,
		FirstObserved: obs.ObservedAt,
		LastObserved:  obs.ObservedAt,
		CreatedAt:     time.Now().UTC(),
	}
	_ = p.repo.SaveEvidence(assetEvidence)
	result.EvidenceRecorded++

	// Record evidence relationship
	relSeq, _ := p.repo.NextSequence(workspace, "relationship")
	_ = p.repo.SaveRelationship(&domain.Relationship{
		ID:         domain.FormatRelationshipID(relSeq),
		SourceType: "evidence",
		SourceID:   assetEvidence.ID,
		TargetType: "asset",
		TargetID:   asset.ID,
		Type:       domain.RelEvidencedBy,
		CreatedAt:  obs.ObservedAt,
	})

	// Process Services
	for _, svcObs := range obs.Services {
		proto := p.normalizer.NormalizeProtocol(svcObs.Protocol)
		port, ok := p.normalizer.NormalizePort(svcObs.Port)
		if !ok {
			continue
		}

		state := svcObs.State
		if state == "" {
			state = domain.ServiceStateOpen
		}

		confidence := domain.ConfidenceObserved
		if svcObs.Technology == "" && (svcObs.Description != "" || svcObs.ServiceName != "") {
			idRes := p.identifier.Identify(protocol.ProbeContext{
				Port:   port,
				Banner: svcObs.Description,
			})
			if idRes.Technology != "" {
				svcObs.Technology = idRes.Technology
				svcObs.Version = idRes.Version
				if idRes.TechConfidence != "" {
					confidence = idRes.TechConfidence
				}
			}
		} else if svcObs.Technology != "" {
			confidence = domain.ConfidenceHigh
		}

		// Check if service already exists on this asset
		existingSvc, err := p.repo.GetServiceByAssetProtoPort(asset.ID, proto, port)
		if err != nil {
			return nil, fmt.Errorf("checking service: %w", err)
		}

		var svcID string
		if existingSvc != nil {
			svcID = existingSvc.ID
			existingSvc.State = state
			existingSvc.LastObserved = obs.ObservedAt
			if svcObs.ServiceName != "" {
				existingSvc.ServiceName = svcObs.ServiceName
			}
			if svcObs.Technology != "" {
				existingSvc.Technology = svcObs.Technology
			}
			if svcObs.Version != "" {
				existingSvc.Version = svcObs.Version
			}
			_ = p.repo.SaveService(existingSvc)
		} else {
			svcSeq, _ := p.repo.NextSequence(workspace, "service")
			svcID = domain.FormatServiceID(svcSeq)
			newSvc := &domain.Service{
				ID:            svcID,
				AssetID:       asset.ID,
				Protocol:      proto,
				Port:          port,
				State:         state,
				ServiceName:   svcObs.ServiceName,
				Technology:    svcObs.Technology,
				Version:       svcObs.Version,
				FirstObserved: obs.ObservedAt,
				LastObserved:  obs.ObservedAt,
				CreatedAt:     obs.ObservedAt,
				UpdatedAt:     obs.ObservedAt,
			}
			_ = p.repo.SaveService(newSvc)
			result.ServicesCreated++

			// Add relationship: asset hosts service
			rSeq, _ := p.repo.NextSequence(workspace, "relationship")
			_ = p.repo.SaveRelationship(&domain.Relationship{
				ID:         domain.FormatRelationshipID(rSeq),
				SourceType: "asset",
				SourceID:   asset.ID,
				TargetType: "service",
				TargetID:   svcID,
				Type:       domain.RelHosts,
				CreatedAt:  obs.ObservedAt,
			})
		}

		// Record Service Evidence
		evSeqSvc, _ := p.repo.NextSequence(workspace, "evidence")
		desc := fmt.Sprintf("Service %s/%d (%s) observed as %s", proto, port, svcObs.ServiceName, state)
		if svcObs.Technology != "" && svcObs.Version != "" {
			desc = fmt.Sprintf("Service %s/%d (%s) running %s %s observed as %s", proto, port, svcObs.ServiceName, svcObs.Technology, svcObs.Version, state)
		} else if svcObs.Technology != "" {
			desc = fmt.Sprintf("Service %s/%d (%s) running %s observed as %s", proto, port, svcObs.ServiceName, svcObs.Technology, state)
		}

		svcEvidence := &domain.Evidence{
			ID:            domain.FormatEvidenceID(evSeqSvc),
			WorkspaceID:   workspace,
			SourceID:      obs.SourceID,
			Category:      domain.EvidenceDirect,
			Confidence:    confidence,
			EntityType:    "service",
			EntityID:      svcID,
			Protocol:      proto,
			Port:          port,
			ServiceName:   svcObs.ServiceName,
			Technology:    svcObs.Technology,
			Address:       normIP,
			Description:   desc,
			ObservedAt:    obs.ObservedAt,
			FirstObserved: obs.ObservedAt,
			LastObserved:  obs.ObservedAt,
			CreatedAt:     time.Now().UTC(),
		}
		_ = p.repo.SaveEvidence(svcEvidence)
		result.EvidenceRecorded++
	}

	return result, nil
}

// IngestNetwork processes a network segment observation.
func (p *Pipeline) IngestNetwork(workspace string, obs *NetworkObservation) (*IngestResult, error) {
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	if obs.SourceID == "" {
		obs.SourceID = "unknown"
	}

	normCIDR, ok := p.normalizer.NormalizeCIDR(obs.CIDR)
	if !ok {
		return nil, fmt.Errorf("invalid CIDR: %s", obs.CIDR)
	}

	result := &IngestResult{}

	// Check if network exists
	existingNet, err := p.repo.GetNetworkByCIDR(workspace, normCIDR)
	if err != nil {
		return nil, fmt.Errorf("checking network: %w", err)
	}

	var netID string
	if existingNet != nil {
		netID = existingNet.ID
		if obs.Name != "" {
			existingNet.Name = obs.Name
		}
		if obs.Description != "" {
			existingNet.Description = obs.Description
		}
		_ = p.repo.SaveNetwork(existingNet)
	} else {
		netSeq, _ := p.repo.NextSequence(workspace, "network")
		netID = domain.FormatNetworkID(netSeq)
		newNet := &domain.Network{
			ID:          netID,
			WorkspaceID: workspace,
			CIDR:        normCIDR,
			Name:        obs.Name,
			Description: obs.Description,
			CreatedAt:   obs.ObservedAt,
			UpdatedAt:   obs.ObservedAt,
		}
		_ = p.repo.SaveNetwork(newNet)
		result.NetworksCreated++
	}

	// Record Network Evidence
	evSeq, _ := p.repo.NextSequence(workspace, "evidence")
	netEvidence := &domain.Evidence{
		ID:            domain.FormatEvidenceID(evSeq),
		WorkspaceID:   workspace,
		SourceID:      obs.SourceID,
		Category:      domain.EvidenceDirect,
		EntityType:    "network",
		EntityID:      netID,
		Address:       normCIDR,
		Description:   fmt.Sprintf("Network %s (%s) observed", normCIDR, obs.Name),
		ObservedAt:    obs.ObservedAt,
		FirstObserved: obs.ObservedAt,
		LastObserved:  obs.ObservedAt,
		CreatedAt:     time.Now().UTC(),
	}
	_ = p.repo.SaveEvidence(netEvidence)
	result.EvidenceRecorded++

	return result, nil
}
