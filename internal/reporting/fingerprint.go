// Package reporting generates deterministic multi-format reports and diffs.
package reporting

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/storage"
)

// CalculateDatasetFingerprint computes a deterministic SHA-256 hash representing the workspace state.
func CalculateDatasetFingerprint(repo *storage.Repository, workspace string) (string, error) {
	var lines []string

	// Assets
	assets, err := repo.ListAssets(workspace)
	if err != nil {
		return "", err
	}
	for _, a := range assets {
		lines = append(lines, fmt.Sprintf("ASSET:%s:%s", a.ID, a.Hostname))
	}

	// Interfaces
	ifaces, err := repo.ListInterfaces(workspace)
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		lines = append(lines, fmt.Sprintf("IFACE:%s:%s:%s:%s", i.ID, i.AssetID, i.Address, i.MACAddress))
	}

	// Services
	services, err := repo.ListServices(workspace)
	if err != nil {
		return "", err
	}
	for _, s := range services {
		lines = append(lines, fmt.Sprintf("SVC:%s:%s:%s:%d:%s:%s", s.ID, s.AssetID, s.Protocol, s.Port, s.State, s.ServiceName))
	}

	// Networks
	networks, err := repo.ListNetworks(workspace)
	if err != nil {
		return "", err
	}
	for _, n := range networks {
		lines = append(lines, fmt.Sprintf("NET:%s:%s", n.ID, n.CIDR))
	}

	// Evidence
	evidence, err := repo.ListEvidence(workspace)
	if err != nil {
		return "", err
	}
	for _, e := range evidence {
		lines = append(lines, fmt.Sprintf("EV:%s:%s:%s:%s:%d", e.ID, e.SourceID, e.EntityType, e.EntityID, e.Port))
	}

	// Findings
	findings, err := repo.ListFindings(workspace)
	if err != nil {
		return "", err
	}
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("FND:%s:%s:%s:%s:%s", f.ID, f.RuleID, f.Category, f.EntityType, f.EntityID))
	}

	// Sort lines for determinism
	sort.Strings(lines)

	hasher := sha256.New()
	hasher.Write([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
