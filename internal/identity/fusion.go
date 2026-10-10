package identity

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// FusionEngine correlates disjointed network telemetry observations into unified Identity records.
type FusionEngine struct {
	mu         sync.RWMutex
	identities map[string]*schema.Identity // keyed by PrimaryIP or ID
	drifts     []schema.IdentityDrift
}

// NewFusionEngine initializes a thread-safe identity fusion engine.
func NewFusionEngine() *FusionEngine {
	return &FusionEngine{
		identities: make(map[string]*schema.Identity),
		drifts:     []schema.IdentityDrift{},
	}
}

// IngestObservation incorporates an observation to update or create an Identity.
func (fe *FusionEngine) IngestObservation(obs schema.Observation) *schema.Identity {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	ip := strings.TrimSpace(obs.TargetIP)
	if ip == "" {
		return nil
	}

	now := obs.ObservedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	ident, exists := fe.identities[ip]
	if !exists {
		ident = &schema.Identity{
			ID:          fmt.Sprintf("IDENT-%s", strings.ReplaceAll(ip, ".", "-")),
			WorkspaceID: obs.WorkspaceID,
			PrimaryIP:   ip,
			Confidence:  "MEDIUM",
			FirstSeen:   now,
			LastSeen:    now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		fe.identities[ip] = ident
	}

	ident.LastSeen = now
	ident.UpdatedAt = now

	// Parse telemetry signals based on Kind
	switch strings.ToLower(obs.Kind) {
	case "arp":
		if obs.RawData != "" && strings.Contains(obs.RawData, ":") {
			if ident.MACAddress != "" && ident.MACAddress != obs.RawData {
				// Record MAC drift
				fe.drifts = append(fe.drifts, schema.IdentityDrift{
					IdentityID:  ident.ID,
					PreviousIP:  ident.PrimaryIP,
					NewIP:       ip,
					DetectedAt:  now,
					Description: fmt.Sprintf("MAC Address changed from %s to %s", ident.MACAddress, obs.RawData),
				})
			}
			ident.MACAddress = obs.RawData
			ident.Confidence = "HIGH"
		}

	case "dns", "mdns", "llmnr", "netbios":
		if obs.RawData != "" {
			if ident.Hostname != "" && !strings.EqualFold(ident.Hostname, obs.RawData) {
				fe.drifts = append(fe.drifts, schema.IdentityDrift{
					IdentityID:  ident.ID,
					PreviousIP:  ident.PrimaryIP,
					NewIP:       ip,
					DetectedAt:  now,
					Description: fmt.Sprintf("Hostname changed from %s to %s", ident.Hostname, obs.RawData),
				})
			}
			ident.Hostname = obs.RawData
		}

	case "tls":
		if obs.RawData != "" {
			// Append TLS Name if not already present
			found := false
			for _, name := range ident.TLSNames {
				if strings.EqualFold(name, obs.RawData) {
					found = true
					break
				}
			}
			if !found {
				ident.TLSNames = append(ident.TLSNames, obs.RawData)
			}
		}

	case "ad", "kerberos", "ldap":
		if obs.RawData != "" {
			parts := strings.Split(obs.RawData, ":")
			if len(parts) >= 2 {
				ident.ADDomain = parts[0]
				ident.ADRoles = append(ident.ADRoles, parts[1])
			} else {
				ident.ADDomain = obs.RawData
			}
			ident.Confidence = "HIGH"
		}
	}

	return ident
}

// GetIdentity retrieves an identity by IP address.
func (fe *FusionEngine) GetIdentity(ip string) (*schema.Identity, bool) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	ident, exists := fe.identities[ip]
	if !exists {
		return nil, false
	}
	cp := *ident
	return &cp, true
}

// GetAllIdentities returns a snapshot of all correlated identities.
func (fe *FusionEngine) GetAllIdentities() []schema.Identity {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	var list []schema.Identity
	for _, ident := range fe.identities {
		list = append(list, *ident)
	}
	return list
}

// GetDrifts returns all detected identity drift events.
func (fe *FusionEngine) GetDrifts() []schema.IdentityDrift {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	res := make([]schema.IdentityDrift, len(fe.drifts))
	copy(res, fe.drifts)
	return res
}
