// Package graph provides the in-memory directed intelligence graph engine for Falcon ToolKit.
// Nodes represent domain entities and Evidence; edges represent verified relationships.
package graph

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// NodeType represents the kind of entity represented by a graph vertex.
type NodeType string

const (
	NodeTarget      NodeType = "target"
	NodeAsset       NodeType = "asset"
	NodeInterface   NodeType = "interface"
	NodeNetwork     NodeType = "network"
	NodeService     NodeType = "service"
	NodeProtocol    NodeType = "protocol"
	NodeTechnology  NodeType = "technology"
	NodeApplication NodeType = "application"
	NodeZone        NodeType = "zone"
	NodeEvidence    NodeType = "evidence"
	NodeFinding     NodeType = "finding"
	NodeCertificate NodeType = "certificate"
	NodeRoute       NodeType = "route"
)

// Node represents a vertex in the domain intelligence graph.
type Node struct {
	ID         string            `json:"id"`
	Type       NodeType          `json:"type"`
	Label      string            `json:"label"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Edge represents a directed relationship between two nodes in the intelligence graph.
type Edge struct {
	ID         string                  `json:"id"`
	SourceID   string                  `json:"source_id"`
	TargetID   string                  `json:"target_id"`
	Type       domain.RelationshipType `json:"type"`
	Confidence domain.ConfidenceLevel  `json:"confidence,omitempty"`
	EvidenceID string                  `json:"evidence_id,omitempty"`
	FirstSeen  time.Time               `json:"first_seen,omitempty"`
	LastSeen   time.Time               `json:"last_seen,omitempty"`
	ObservedAt time.Time               `json:"observed_at,omitempty"`
	Properties map[string]string       `json:"properties,omitempty"`
}

// Graph holds the in-memory intelligence graph representation for a workspace.
type Graph struct {
	mu          sync.RWMutex
	nodes       map[string]*Node
	edges       map[string]*Edge
	adjacency   map[string][]string // sourceID -> []targetID
	inAdjacency map[string][]string // targetID -> []sourceID
}

// New creates an empty Graph.
func New() *Graph {
	return &Graph{
		nodes:       make(map[string]*Node),
		edges:       make(map[string]*Edge),
		adjacency:   make(map[string][]string),
		inAdjacency: make(map[string][]string),
	}
}

// BuildFromStorage constructs an in-memory intelligence graph from SQLite workspace data.
func BuildFromStorage(repo *storage.Repository, workspace string) (*Graph, error) {
	g := New()

	// 1. Load Targets
	targets, err := repo.ListTargets(workspace)
	if err == nil {
		for _, tgt := range targets {
			g.AddNode(&Node{
				ID:    tgt.ID,
				Type:  NodeTarget,
				Label: fmt.Sprintf("Target: %s", tgt.NormalizedValue),
				Properties: map[string]string{
					"value":  tgt.NormalizedValue,
					"type":   string(tgt.Type),
					"scope":  string(tgt.Scope),
					"status": string(tgt.Status),
				},
			})
		}
	}

	// 2. Load Assets
	assets, err := repo.ListAssets(workspace)
	if err != nil {
		return nil, fmt.Errorf("loading assets for graph: %w", err)
	}
	for _, a := range assets {
		lbl := a.Hostname
		if lbl == "" {
			lbl = a.ID
		}
		g.AddNode(&Node{
			ID:    a.ID,
			Type:  NodeAsset,
			Label: lbl,
			Properties: map[string]string{
				"hostname": a.Hostname,
			},
		})
	}

	// 3. Load Interfaces
	interfaces, err := repo.ListInterfaces(workspace)
	if err != nil {
		return nil, fmt.Errorf("loading interfaces for graph: %w", err)
	}
	for _, iface := range interfaces {
		g.AddNode(&Node{
			ID:    iface.ID,
			Type:  NodeInterface,
			Label: iface.Address,
			Properties: map[string]string{
				"address":     iface.Address,
				"mac_address": iface.MACAddress,
				"asset_id":    iface.AssetID,
			},
		})
		// Edge: Asset -> Interface
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("e_%s_%s", iface.AssetID, iface.ID),
			SourceID:   iface.AssetID,
			TargetID:   iface.ID,
			Type:       domain.RelHasInterface,
			Confidence: domain.ConfidenceObserved,
		})

		if iface.NetworkID != "" {
			g.AddEdge(&Edge{
				ID:         fmt.Sprintf("e_%s_%s", iface.ID, iface.NetworkID),
				SourceID:   iface.ID,
				TargetID:   iface.NetworkID,
				Type:       domain.RelBelongsTo,
				Confidence: domain.ConfidenceObserved,
			})
		}
	}

	// 4. Load Networks & Zones
	networks, err := repo.ListNetworks(workspace)
	if err != nil {
		return nil, fmt.Errorf("loading networks for graph: %w", err)
	}
	for _, net := range networks {
		lbl := net.CIDR
		if net.Name != "" {
			lbl += fmt.Sprintf(" (%s)", net.Name)
		}
		g.AddNode(&Node{
			ID:    net.ID,
			Type:  NodeNetwork,
			Label: lbl,
			Properties: map[string]string{
				"cidr": net.CIDR,
				"name": net.Name,
			},
		})

		// If network indicates a security zone, create Zone node
		if net.Name != "" {
			zoneID := fmt.Sprintf("ZONE-%s", net.ID)
			g.AddNode(&Node{
				ID:    zoneID,
				Type:  NodeZone,
				Label: fmt.Sprintf("Zone: %s", net.Name),
				Properties: map[string]string{
					"name": net.Name,
					"cidr": net.CIDR,
				},
			})
			g.AddEdge(&Edge{
				ID:         fmt.Sprintf("e_%s_%s", net.ID, zoneID),
				SourceID:   net.ID,
				TargetID:   zoneID,
				Type:       domain.RelBelongsTo,
				Confidence: domain.ConfidenceObserved,
			})
		}
	}

	// 5. Load Services, Protocols, and Technologies
	services, err := repo.ListServices(workspace)
	if err != nil {
		return nil, fmt.Errorf("loading services for graph: %w", err)
	}
	for _, svc := range services {
		lbl := fmt.Sprintf("%s/%d", svc.Protocol, svc.Port)
		if svc.ServiceName != "" {
			lbl += fmt.Sprintf(" (%s)", svc.ServiceName)
		}
		g.AddNode(&Node{
			ID:    svc.ID,
			Type:  NodeService,
			Label: lbl,
			Properties: map[string]string{
				"protocol":     svc.Protocol,
				"port":         fmt.Sprintf("%d", svc.Port),
				"state":        string(svc.State),
				"service_name": svc.ServiceName,
				"technology":   svc.Technology,
				"version":      svc.Version,
				"asset_id":     svc.AssetID,
			},
		})
		// Edge: Asset -> Service
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("e_%s_%s", svc.AssetID, svc.ID),
			SourceID:   svc.AssetID,
			TargetID:   svc.ID,
			Type:       domain.RelHosts,
			Confidence: domain.ConfidenceObserved,
		})

		// Create Protocol Node & Edge
		if svc.ServiceName != "" || svc.Protocol != "" {
			protoName := strings.ToUpper(svc.ServiceName)
			if protoName == "" {
				protoName = strings.ToUpper(svc.Protocol)
			}
			protoID := fmt.Sprintf("PROTO-%s", protoName)
			g.AddNode(&Node{
				ID:    protoID,
				Type:  NodeProtocol,
				Label: fmt.Sprintf("Protocol: %s", protoName),
				Properties: map[string]string{
					"name": protoName,
				},
			})
			g.AddEdge(&Edge{
				ID:         fmt.Sprintf("e_%s_%s", svc.ID, protoID),
				SourceID:   svc.ID,
				TargetID:   protoID,
				Type:       domain.RelSpeaks,
				Confidence: domain.ConfidenceHigh,
			})
		}

		// Create Technology Node & Edge
		if svc.Technology != "" {
			techID := fmt.Sprintf("TECH-%s", strings.ReplaceAll(svc.Technology, " ", "-"))
			techLabel := svc.Technology
			if svc.Version != "" {
				techLabel += " " + svc.Version
			}
			g.AddNode(&Node{
				ID:    techID,
				Type:  NodeTechnology,
				Label: techLabel,
				Properties: map[string]string{
					"technology": svc.Technology,
					"version":    svc.Version,
				},
			})
			g.AddEdge(&Edge{
				ID:         fmt.Sprintf("e_%s_%s", svc.ID, techID),
				SourceID:   svc.ID,
				TargetID:   techID,
				Type:       domain.RelRuns,
				Confidence: domain.ConfidenceHigh,
			})
		}
	}

	// 6. Load Evidence
	evidenceList, err := repo.ListEvidence(workspace)
	if err == nil {
		for _, ev := range evidenceList {
			g.AddNode(&Node{
				ID:    ev.ID,
				Type:  NodeEvidence,
				Label: fmt.Sprintf("[%s] %s", ev.Confidence, ev.Description),
				Properties: map[string]string{
					"category":    string(ev.Category),
					"confidence":  string(ev.Confidence),
					"entity_type": ev.EntityType,
					"entity_id":   ev.EntityID,
				},
			})
			if ev.EntityID != "" {
				g.AddEdge(&Edge{
					ID:         fmt.Sprintf("e_%s_%s", ev.ID, ev.EntityID),
					SourceID:   ev.ID,
					TargetID:   ev.EntityID,
					Type:       domain.RelEvidencedBy,
					Confidence: ev.Confidence,
				})
			}
		}
	}

	// 7. Load Findings
	findings, err := repo.ListFindings(workspace)
	if err == nil {
		for _, f := range findings {
			g.AddNode(&Node{
				ID:    f.ID,
				Type:  NodeFinding,
				Label: f.Title,
				Properties: map[string]string{
					"category":    string(f.Category),
					"rule_id":     f.RuleID,
					"entity_id":   f.EntityID,
					"entity_type": f.EntityType,
					"status":      string(f.Status),
				},
			})
			if f.EntityID != "" {
				g.AddEdge(&Edge{
					ID:         fmt.Sprintf("e_%s_%s", f.EntityID, f.ID),
					SourceID:   f.EntityID,
					TargetID:   f.ID,
					Type:       domain.RelEvidencedBy,
					Confidence: domain.ConfidenceHigh,
				})
			}
		}
	}

	// 8. Load Explicit Relationships from DB
	relationships, err := repo.ListRelationships(workspace)
	if err == nil {
		for _, rel := range relationships {
			// If relationship involves certificates, add NodeCertificate
			if rel.SourceType == "certificate" {
				g.AddNode(&Node{
					ID:    rel.SourceID,
					Type:  NodeCertificate,
					Label: fmt.Sprintf("Cert #%s", rel.SourceID),
				})
			}
			g.AddEdge(&Edge{
				ID:         rel.ID,
				SourceID:   rel.SourceID,
				TargetID:   rel.TargetID,
				Type:       rel.Type,
				Confidence: domain.ConfidenceObserved,
			})
		}
	}

	return g, nil
}

// AddNode adds a node to the graph.
func (g *Graph) AddNode(n *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = n
}

// AddEdge adds a directed edge to the graph.
func (g *Graph) AddEdge(e *Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[e.ID] = e
	g.adjacency[e.SourceID] = append(g.adjacency[e.SourceID], e.TargetID)
	g.inAdjacency[e.TargetID] = append(g.inAdjacency[e.TargetID], e.SourceID)
}

// GetNode returns a node by ID.
func (g *Graph) GetNode(id string) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

// Nodes returns all nodes sorted deterministically by ID.
func (g *Graph) Nodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	list := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		list = append(list, n)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
	return list
}

// Edges returns all edges sorted deterministically by ID.
func (g *Graph) Edges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	list := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
	return list
}

// NodesByType returns all nodes of a specific NodeType.
func (g *Graph) NodesByType(t NodeType) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var list []*Node
	for _, n := range g.nodes {
		if n.Type == t {
			list = append(list, n)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
	return list
}

// Neighbors returns outgoing and incoming neighbor nodes and connecting edges.
func (g *Graph) Neighbors(nodeID string) ([]*Node, []*Edge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodeMap := make(map[string]*Node)
	var edgeList []*Edge

	for _, e := range g.edges {
		if e.SourceID == nodeID {
			if target, ok := g.nodes[e.TargetID]; ok {
				nodeMap[target.ID] = target
				edgeList = append(edgeList, e)
			}
		} else if e.TargetID == nodeID {
			if src, ok := g.nodes[e.SourceID]; ok {
				nodeMap[src.ID] = src
				edgeList = append(edgeList, e)
			}
		}
	}

	var nodeList []*Node
	for _, n := range nodeMap {
		nodeList = append(nodeList, n)
	}
	sort.Slice(nodeList, func(i, j int) bool {
		return nodeList[i].ID < nodeList[j].ID
	})
	sort.Slice(edgeList, func(i, j int) bool {
		return edgeList[i].ID < edgeList[j].ID
	})

	return nodeList, edgeList
}

// ServicesFor returns service nodes connected to an asset or interface.
func (g *Graph) ServicesFor(nodeID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var services []*Node
	for _, targetID := range g.adjacency[nodeID] {
		if n, ok := g.nodes[targetID]; ok && n.Type == NodeService {
			services = append(services, n)
		}
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].ID < services[j].ID
	})
	return services
}

// HostsFor returns asset/host nodes connected to a network, service, or interface.
func (g *Graph) HostsFor(nodeID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	hostMap := make(map[string]*Node)

	// Outgoing and incoming traversals
	for _, srcID := range g.inAdjacency[nodeID] {
		if n, ok := g.nodes[srcID]; ok && n.Type == NodeAsset {
			hostMap[n.ID] = n
		}
	}
	for _, dstID := range g.adjacency[nodeID] {
		if n, ok := g.nodes[dstID]; ok && n.Type == NodeAsset {
			hostMap[n.ID] = n
		}
	}

	var hosts []*Node
	for _, h := range hostMap {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].ID < hosts[j].ID
	})
	return hosts
}

// IsolatedNodes returns nodes with degree 0 (no incoming or outgoing edges).
func (g *Graph) IsolatedNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var isolated []*Node
	for id, n := range g.nodes {
		inCount := len(g.inAdjacency[id])
		outCount := len(g.adjacency[id])
		if inCount == 0 && outCount == 0 {
			isolated = append(isolated, n)
		}
	}
	sort.Slice(isolated, func(i, j int) bool {
		return isolated[i].ID < isolated[j].ID
	})
	return isolated
}

// Stats returns high-level summary statistics of the graph.
type GraphStats struct {
	TotalNodes     int            `json:"total_nodes"`
	TotalEdges     int            `json:"total_edges"`
	NodesByType    map[string]int `json:"nodes_by_type"`
	EdgesByType    map[string]int `json:"edges_by_type"`
	ComponentCount int            `json:"component_count"`
}

// Stats calculates graph statistics.
func (g *Graph) Stats() GraphStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := GraphStats{
		TotalNodes:  len(g.nodes),
		TotalEdges:  len(g.edges),
		NodesByType: make(map[string]int),
		EdgesByType: make(map[string]int),
	}

	for _, n := range g.nodes {
		stats.NodesByType[string(n.Type)]++
	}
	for _, e := range g.edges {
		stats.EdgesByType[string(e.Type)]++
	}

	stats.ComponentCount = len(g.ConnectedComponents())
	return stats
}

// ExportDOT renders the graph in Graphviz DOT format.
func (g *Graph) ExportDOT() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph FalconNetwork {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=filled, fontname=\"Helvetica\"];\n\n")

	for _, n := range g.Nodes() {
		color := "#e2e8f0"
		switch n.Type {
		case NodeTarget:
			color = "#fbcfe8"
		case NodeAsset:
			color = "#bfdbfe"
		case NodeInterface:
			color = "#bbf7d0"
		case NodeService:
			color = "#fef08a"
		case NodeNetwork:
			color = "#fed7aa"
		case NodeZone:
			color = "#fef9c3"
		case NodeProtocol:
			color = "#e0e7ff"
		case NodeTechnology:
			color = "#ddd6fe"
		case NodeEvidence:
			color = "#e9d5ff"
		case NodeFinding:
			color = "#fecaca"
		case NodeCertificate:
			color = "#c7d2fe"
		}
		cleanLabel := strings.ReplaceAll(n.Label, "\"", "'")
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n(%s)\", fillcolor=\"%s\"];\n", n.ID, cleanLabel, n.Type, color))
	}

	sb.WriteString("\n")
	for _, e := range g.Edges() {
		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\"];\n", e.SourceID, e.TargetID, e.Type))
	}

	sb.WriteString("}\n")
	return sb.String()
}
