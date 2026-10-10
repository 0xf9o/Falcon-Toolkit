package observation

import (
	"fmt"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// Resolver resolves incoming observations into domain Assets and Interfaces.
type Resolver struct {
	repo *storage.Repository
}

// NewResolver creates a new identity Resolver.
func NewResolver(repo *storage.Repository) *Resolver {
	return &Resolver{repo: repo}
}

// ResolveAssetResult contains the resolved Asset, Interface, and whether they were newly created.
type ResolveAssetResult struct {
	Asset      *domain.Asset
	Interface  *domain.Interface
	IsNewAsset bool
	IsNewIface bool
}

// ResolveHost finds or creates an Asset and Interface for a given IP address, hostname, and MAC.
func (r *Resolver) ResolveHost(workspace string, ipAddress, hostname, macAddress string, observedAt time.Time) (*ResolveAssetResult, error) {
	result := &ResolveAssetResult{}

	// 1. Check if interface already exists by IP
	if ipAddress != "" {
		existingIface, err := r.repo.GetInterfaceByAddress(workspace, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("looking up interface by IP %s: %w", ipAddress, err)
		}

		if existingIface != nil {
			result.Interface = existingIface
			// Fetch associated asset
			asset, err := r.repo.GetAsset(existingIface.AssetID)
			if err != nil {
				return nil, fmt.Errorf("looking up asset %s: %w", existingIface.AssetID, err)
			}
			if asset != nil {
				result.Asset = asset
				// Update hostname if new and asset currently has none
				if hostname != "" && asset.Hostname == "" {
					asset.Hostname = hostname
					_ = r.repo.SaveAsset(asset)
				}
				// Update MAC if new
				if macAddress != "" && existingIface.MACAddress == "" {
					existingIface.MACAddress = macAddress
					_ = r.repo.SaveInterface(existingIface)
				}
				return result, nil
			}
		}
	}

	// 2. Check if asset exists by hostname if no IP match
	if hostname != "" {
		existingAsset, err := r.repo.GetAssetByHostname(workspace, hostname)
		if err != nil {
			return nil, fmt.Errorf("looking up asset by hostname %s: %w", hostname, err)
		}
		if existingAsset != nil {
			result.Asset = existingAsset
			if ipAddress != "" {
				// Create new interface for existing asset
				ifaceSeq, _ := r.repo.NextSequence(workspace, "interface")
				iface := &domain.Interface{
					ID:         domain.FormatInterfaceID(ifaceSeq),
					AssetID:    existingAsset.ID,
					Address:    ipAddress,
					MACAddress: macAddress,
					CreatedAt:  observedAt,
					UpdatedAt:  observedAt,
				}
				if err := r.repo.SaveInterface(iface); err != nil {
					return nil, fmt.Errorf("saving new interface: %w", err)
				}
				result.Interface = iface
				result.IsNewIface = true
			}
			return result, nil
		}
	}

	// 3. Create new Asset and Interface
	assetSeq, err := r.repo.NextSequence(workspace, "asset")
	if err != nil {
		return nil, fmt.Errorf("generating asset sequence: %w", err)
	}

	asset := &domain.Asset{
		ID:            domain.FormatAssetID(assetSeq),
		WorkspaceID:   workspace,
		Hostname:      hostname,
		FirstObserved: observedAt,
		LastObserved:  observedAt,
		CreatedAt:     observedAt,
		UpdatedAt:     observedAt,
	}
	if err := r.repo.SaveAsset(asset); err != nil {
		return nil, fmt.Errorf("saving new asset: %w", err)
	}
	result.Asset = asset
	result.IsNewAsset = true

	// Create interface if IP provided
	if ipAddress != "" {
		ifaceSeq, err := r.repo.NextSequence(workspace, "interface")
		if err != nil {
			return nil, fmt.Errorf("generating interface sequence: %w", err)
		}
		iface := &domain.Interface{
			ID:         domain.FormatInterfaceID(ifaceSeq),
			AssetID:    asset.ID,
			Address:    ipAddress,
			MACAddress: macAddress,
			CreatedAt:  observedAt,
			UpdatedAt:  observedAt,
		}
		if err := r.repo.SaveInterface(iface); err != nil {
			return nil, fmt.Errorf("saving new interface: %w", err)
		}
		result.Interface = iface
		result.IsNewIface = true

		// Add relationship: asset has_interface interface
		relSeq, _ := r.repo.NextSequence(workspace, "relationship")
		rel := &domain.Relationship{
			ID:         domain.FormatRelationshipID(relSeq),
			SourceType: "asset",
			SourceID:   asset.ID,
			TargetType: "interface",
			TargetID:   iface.ID,
			Type:       domain.RelHasInterface,
			CreatedAt:  observedAt,
		}
		_ = r.repo.SaveRelationship(rel)
	}

	return result, nil
}
