package graph

import (
	"sort"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// ShortestPath finds the shortest unweighted path between source and target using BFS.
func (g *Graph) ShortestPath(sourceID, targetID string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.nodes[sourceID]; !ok {
		return nil
	}
	if _, ok := g.nodes[targetID]; !ok {
		return nil
	}
	if sourceID == targetID {
		return []string{sourceID}
	}

	visited := make(map[string]bool)
	parent := make(map[string]string)
	queue := []string{sourceID}
	visited[sourceID] = true

	found := false
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr == targetID {
			found = true
			break
		}

		// Look at both outgoing and incoming edges for undirected reachability
		neighbors := append(g.adjacency[curr], g.inAdjacency[curr]...)
		for _, next := range neighbors {
			if !visited[next] {
				visited[next] = true
				parent[next] = curr
				queue = append(queue, next)
			}
		}
	}

	if !found {
		return nil
	}

	// Reconstruct path
	var path []string
	curr := targetID
	for curr != "" {
		path = append([]string{curr}, path...)
		curr = parent[curr]
	}

	return path
}

// DetailedPathStep represents an individual hop along an analytical graph path.
type DetailedPathStep struct {
	FromNode *Node                   `json:"from_node"`
	ToNode   *Node                   `json:"to_node"`
	EdgeType domain.RelationshipType `json:"edge_type"`
	EdgeID   string                  `json:"edge_id"`
}

// DetailedPathResult contains the ordered path and evidentiary hops.
type DetailedPathResult struct {
	SourceID string             `json:"source_id"`
	TargetID string             `json:"target_id"`
	Hops     int                `json:"hops"`
	NodeIDs  []string           `json:"node_ids"`
	Nodes    []*Node            `json:"nodes"`
	Steps    []DetailedPathStep `json:"steps"`
}

// DetailedPath finds the shortest path and returns detailed node and edge hop records.
func (g *Graph) DetailedPath(sourceID, targetID string) *DetailedPathResult {
	nodeIDs := g.ShortestPath(sourceID, targetID)
	if len(nodeIDs) == 0 {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	res := &DetailedPathResult{
		SourceID: sourceID,
		TargetID: targetID,
		Hops:     len(nodeIDs) - 1,
		NodeIDs:  nodeIDs,
	}

	for _, id := range nodeIDs {
		if n, ok := g.nodes[id]; ok {
			res.Nodes = append(res.Nodes, n)
		}
	}

	// Resolve connecting edges for each consecutive pair
	for i := 0; i < len(nodeIDs)-1; i++ {
		u := nodeIDs[i]
		v := nodeIDs[i+1]
		var connectingEdge *Edge
		for _, e := range g.edges {
			if (e.SourceID == u && e.TargetID == v) || (e.SourceID == v && e.TargetID == u) {
				connectingEdge = e
				break
			}
		}

		edgeType := domain.RelConnectedTo
		edgeID := ""
		if connectingEdge != nil {
			edgeType = connectingEdge.Type
			edgeID = connectingEdge.ID
		}

		res.Steps = append(res.Steps, DetailedPathStep{
			FromNode: g.nodes[u],
			ToNode:   g.nodes[v],
			EdgeType: edgeType,
			EdgeID:   edgeID,
		})
	}

	return res
}

// Subgraph returns all nodes and edges within `depth` hops of the given root node.
func (g *Graph) Subgraph(rootID string, depth int) (*Graph, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	sub := New()
	if _, ok := g.nodes[rootID]; !ok {
		return sub, nil
	}

	visited := make(map[string]int) // nodeID -> distance
	queue := []string{rootID}
	visited[rootID] = 0

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		d := visited[curr]

		sub.AddNode(g.nodes[curr])

		if d < depth {
			neighbors := append(g.adjacency[curr], g.inAdjacency[curr]...)
			for _, next := range neighbors {
				if _, ok := visited[next]; !ok {
					visited[next] = d + 1
					queue = append(queue, next)
				}
			}
		}
	}

	// Add connecting edges
	for _, e := range g.edges {
		if _, srcOk := visited[e.SourceID]; srcOk {
			if _, dstOk := visited[e.TargetID]; dstOk {
				sub.AddEdge(e)
			}
		}
	}

	return sub, nil
}

// ConnectedComponents returns all connected components in the graph.
func (g *Graph) ConnectedComponents() [][]string {
	visited := make(map[string]bool)
	var components [][]string

	allNodes := g.Nodes()
	for _, node := range allNodes {
		if visited[node.ID] {
			continue
		}

		var comp []string
		queue := []string{node.ID}
		visited[node.ID] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			comp = append(comp, curr)

			neighbors := append(g.adjacency[curr], g.inAdjacency[curr]...)
			for _, next := range neighbors {
				if !visited[next] {
					visited[next] = true
					queue = append(queue, next)
				}
			}
		}

		sort.Strings(comp)
		components = append(components, comp)
	}

	sort.Slice(components, func(i, j int) bool {
		if len(components[i]) != len(components[j]) {
			return len(components[i]) > len(components[j])
		}
		if len(components[i]) > 0 && len(components[j]) > 0 {
			return components[i][0] < components[j][0]
		}
		return false
	})

	return components
}
