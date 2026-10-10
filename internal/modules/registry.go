// Package modules manages in-process capability modules, metadata, and health checks.
package modules

import (
	"sort"
	"sync"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// ModuleInfo describes a registered capability module.
type ModuleInfo struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Version      string              `json:"version"`
	Description  string              `json:"description"`
	Type         domain.ModuleType   `json:"type"`
	Capabilities []string            `json:"capabilities"`
	Status       domain.ModuleStatus `json:"status"`
	HealthMsg    string              `json:"health_message,omitempty"`
}

// Registry maintains all registered in-process modules.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]*ModuleInfo
}

// DefaultRegistry returns a registry initialized with all built-in Falcon modules.
func DefaultRegistry() *Registry {
	r := &Registry{
		modules: make(map[string]*ModuleInfo),
	}

	builtins := []*ModuleInfo{
		{
			ID:           "core-storage",
			Name:         "SQLite Storage Engine",
			Version:      "3.1.0",
			Description:  "Authoritative SQLite persistence with WAL mode and foreign key integrity",
			Type:         domain.ModuleTypeCore,
			Capabilities: []string{"sqlite", "wal", "foreign-keys", "migrations", "audit"},
			Status:       domain.ModuleReady,
		},
		{
			ID:           "importers",
			Name:         "Multi-Format Ingestion",
			Version:      "3.1.0",
			Description:  "Parsers for JSON, Nmap XML, DNS records, ARP tables, routing, and PCAP metadata",
			Type:         domain.ModuleTypeImporter,
			Capabilities: []string{"json", "nmapxml", "dnsdata", "arp", "routing", "pcapmeta"},
			Status:       domain.ModuleReady,
		},
		{
			ID:           "graph-engine",
			Name:         "Topology & Graph Engine",
			Version:      "3.1.0",
			Description:  "In-memory directed relationship graph with BFS paths and DOT export",
			Type:         domain.ModuleTypeAnalysis,
			Capabilities: []string{"bfs", "shortest-path", "subgraphs", "components", "dot-export"},
			Status:       domain.ModuleReady,
		},
		{
			ID:           "assessment-engine",
			Name:         "Rule-Based Assessment",
			Version:      "3.1.0",
			Description:  "Deterministic rule evaluation producing verified findings with snapshot diffing",
			Type:         domain.ModuleTypeAnalysis,
			Capabilities: []string{"service-exposure", "global-address", "ot-indicators", "multi-interface", "technology"},
			Status:       domain.ModuleReady,
		},
		{
			ID:           "evidence-manager",
			Name:         "Evidence & Lineage Verification",
			Version:      "3.1.0",
			Description:  "Finding to Source deterministic provenance and lineage reconstruction",
			Type:         domain.ModuleTypeAnalysis,
			Capabilities: []string{"lineage", "provenance", "evidence-trace"},
			Status:       domain.ModuleReady,
		},
		{
			ID:           "reporting-engine",
			Name:         "Deterministic Reporter",
			Version:      "3.1.0",
			Description:  "Multi-format output rendering in Table, JSON, NDJSON, and Markdown",
			Type:         domain.ModuleTypeReporting,
			Capabilities: []string{"table", "json", "ndjson", "markdown", "fingerprint", "diff"},
			Status:       domain.ModuleReady,
		},
		{
			ID:           "ot-indicators",
			Name:         "OT / ICS Protocol Indicators",
			Version:      "3.1.0",
			Description:  "Indicator matching for Modbus, OPC UA, S7, EtherNet/IP, and DNP3",
			Type:         domain.ModuleTypeAnalysis,
			Capabilities: []string{"modbus", "opc-ua", "s7", "ethernet-ip", "dnp3"},
			Status:       domain.ModuleReady,
		},
	}

	for _, m := range builtins {
		r.Register(m)
	}

	return r
}

// Register registers a module.
func (r *Registry) Register(m *ModuleInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modules[m.ID] = m
}

// Get retrieves a module by ID.
func (r *Registry) Get(id string) (*ModuleInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[id]
	return m, ok
}

// List returns all registered modules sorted deterministically by ID.
func (r *Registry) List() []*ModuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]*ModuleInfo, 0, len(r.modules))
	for _, m := range r.modules {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
	return list
}
