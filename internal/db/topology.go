package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AssetType distinguishes domains from IP addresses.
type AssetType string

const (
	AssetDomain AssetType = "domain"
	AssetIP     AssetType = "ip"
)

// AssetNode represents a root or intermediate target entity (Domain or IP).
type AssetNode struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      AssetType         `json:"type"`
	ParentID  string            `json:"parent_id,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt string            `json:"created_at"`
}

// ServiceNode represents an active network service identified on an asset.
type ServiceNode struct {
	ID        string `json:"id"`
	AssetID   string `json:"asset_id"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Service   string `json:"service"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	Banner    string `json:"banner,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Timestamp string `json:"timestamp"`
}

// TopologyGraph models the interconnected asset & service hierarchy.
type TopologyGraph struct {
	Workspace string                 `json:"workspace"`
	Assets    map[string]AssetNode   `json:"assets"`
	Services  map[string]ServiceNode `json:"services"`
	Edges     []TopologyEdge         `json:"edges"`
}

// TopologyEdge establishes relational links between nodes.
type TopologyEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"` // "resolves_to", "runs_service"
}

// SaveAssetNode persists an asset node in the workspace topology.
func (s *Store) SaveAssetNode(workspace string, node AssetNode) error {
	if node.CreatedAt == "" {
		node.CreatedAt = time.Now().Format(time.RFC3339)
	}

	data, err := json.Marshal(node)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName(workspace, "topology_assets"))
		if err != nil {
			return err
		}
		return b.Put([]byte(node.ID), data)
	})
}

// SaveServiceNode persists an identified service node in the workspace topology.
func (s *Store) SaveServiceNode(workspace string, node ServiceNode) error {
	if node.Timestamp == "" {
		node.Timestamp = time.Now().Format(time.RFC3339)
	}

	data, err := json.Marshal(node)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName(workspace, "topology_services"))
		if err != nil {
			return err
		}
		return b.Put([]byte(node.ID), data)
	})
}

// GetTopologyGraph builds the complete topology graph for a given workspace.
func (s *Store) GetTopologyGraph(workspace string) (*TopologyGraph, error) {
	graph := &TopologyGraph{
		Workspace: workspace,
		Assets:    make(map[string]AssetNode),
		Services:  make(map[string]ServiceNode),
		Edges:     []TopologyEdge{},
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		// Read assets
		ab := tx.Bucket(bucketName(workspace, "topology_assets"))
		if ab != nil {
			_ = ab.ForEach(func(k, v []byte) error {
				var a AssetNode
				if err := json.Unmarshal(v, &a); err == nil {
					graph.Assets[a.ID] = a
					if a.ParentID != "" {
						graph.Edges = append(graph.Edges, TopologyEdge{
							From:     a.ParentID,
							To:       a.ID,
							Relation: "resolves_to",
						})
					}
				}
				return nil
			})
		}

		// Read services
		sb := tx.Bucket(bucketName(workspace, "topology_services"))
		if sb != nil {
			_ = sb.ForEach(func(k, v []byte) error {
				var s ServiceNode
				if err := json.Unmarshal(v, &s); err == nil {
					graph.Services[s.ID] = s
					if s.AssetID != "" {
						graph.Edges = append(graph.Edges, TopologyEdge{
							From:     s.AssetID,
							To:       s.ID,
							Relation: "runs_service",
						})
					}
				}
				return nil
			})
		}
		return nil
	})

	return graph, err
}

// RenderTopologyTree formats the topology graph into an ASCII tree representation.
func RenderTopologyTree(graph *TopologyGraph) string {
	if len(graph.Assets) == 0 && len(graph.Services) == 0 {
		return "  (No topology assets mapped in current workspace)"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Target Asset Graph [%s]\n", graph.Workspace))

	// Group assets by parent
	rootAssets := make([]AssetNode, 0)
	childAssets := make(map[string][]AssetNode)

	for _, a := range graph.Assets {
		if a.ParentID == "" {
			rootAssets = append(rootAssets, a)
		} else {
			childAssets[a.ParentID] = append(childAssets[a.ParentID], a)
		}
	}

	// Services indexed by asset ID
	assetServices := make(map[string][]ServiceNode)
	for _, s := range graph.Services {
		assetServices[s.AssetID] = append(assetServices[s.AssetID], s)
	}

	for _, root := range rootAssets {
		sb.WriteString(fmt.Sprintf("├── [%s] %s\n", strings.ToUpper(string(root.Type)), root.Name))

		// Render child assets (e.g. IPs under Domain)
		children := childAssets[root.ID]
		for _, child := range children {
			sb.WriteString(fmt.Sprintf("│   ├── ↳ [%s] %s\n", strings.ToUpper(string(child.Type)), child.Name))
			for _, svc := range assetServices[child.ID] {
				prodInfo := svc.Service
				if svc.Product != "" {
					prodInfo = fmt.Sprintf("%s (%s %s)", svc.Service, svc.Product, svc.Version)
				}
				sb.WriteString(fmt.Sprintf("│   │   └── :%d/%s -> %s [%dms]\n",
					svc.Port, svc.Protocol, prodInfo, svc.LatencyMs))
			}
		}

		// Services directly on root asset
		for _, svc := range assetServices[root.ID] {
			prodInfo := svc.Service
			if svc.Product != "" {
				prodInfo = fmt.Sprintf("%s (%s %s)", svc.Service, svc.Product, svc.Version)
			}
			sb.WriteString(fmt.Sprintf("│   └── :%d/%s -> %s [%dms]\n",
				svc.Port, svc.Protocol, prodInfo, svc.LatencyMs))
		}
	}

	return sb.String()
}
