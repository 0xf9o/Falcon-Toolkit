package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// LiveServer provides an embedded HTTP API and visual web topology dashboard.
type LiveServer struct {
	mu             sync.RWMutex
	env            *schema.SessionEnvironment
	server         *http.Server
	port           int
	isRunning      bool
	identitiesFunc func() []schema.Identity
}

// NewLiveServer creates a new embedded live topology server.
func NewLiveServer(env *schema.SessionEnvironment, identitiesFunc func() []schema.Identity) *LiveServer {
	return &LiveServer{
		env:            env,
		identitiesFunc: identitiesFunc,
		port:           8080,
	}
}

// Start launches the live HTTP listener.
func (ls *LiveServer) Start(port int) (string, error) {
	ls.mu.Lock()
	if ls.isRunning {
		ls.mu.Unlock()
		return fmt.Sprintf("http://127.0.0.1:%d", ls.port), nil
	}
	ls.port = port
	ls.isRunning = true
	ls.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/postures", ls.handleAPIPostures)
	mux.HandleFunc("/api/identities", ls.handleAPIIdentities)
	mux.HandleFunc("/api/graph", ls.handleAPIGraph)
	mux.HandleFunc("/", ls.handleDashboard)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ls.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		_ = ls.server.ListenAndServe()
	}()

	return fmt.Sprintf("http://%s", addr), nil
}

// Stop terminates the running server.
func (ls *LiveServer) Stop(ctx context.Context) error {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if !ls.isRunning || ls.server == nil {
		return nil
	}
	ls.isRunning = false
	return ls.server.Shutdown(ctx)
}

func (ls *LiveServer) handleAPIPostures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ls.env.Postures)
}

func (ls *LiveServer) handleAPIIdentities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ls.identitiesFunc != nil {
		_ = json.NewEncoder(w).Encode(ls.identitiesFunc())
		return
	}
	_ = json.NewEncoder(w).Encode([]schema.Identity{})
}

func (ls *LiveServer) handleAPIGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type WebNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Color string `json:"color"`
		Shape string `json:"shape"`
		Size  int    `json:"size"`
	}
	type WebEdge struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Label string `json:"label"`
		Color string `json:"color"`
	}

	var nodes []WebNode
	var edges []WebEdge

	for cidr, p := range ls.env.Postures {
		color := "#10b981"
		if p.BlastScore >= 5.0 {
			color = "#ef4444"
		} else if p.BlastScore > 0 {
			color = "#f59e0b"
		}

		nodes = append(nodes, WebNode{
			ID:    cidr,
			Label: fmt.Sprintf("%s\n(Blast: %.1f)", cidr, p.BlastScore),
			Color: color,
			Shape: "box",
			Size:  25,
		})

		for _, h := range p.ExposedHosts {
			nodes = append(nodes, WebNode{
				ID:    h,
				Label: h,
				Color: "#3b82f6",
				Shape: "dot",
				Size:  15,
			})
			edges = append(edges, WebEdge{
				From:  cidr,
				To:    h,
				Label: "Contains",
				Color: "#64748b",
			})
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": nodes,
		"edges": edges,
	})
}

func (ls *LiveServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Falcon Intelligence — Live Network Topology</title>
<script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
  body { margin: 0; padding: 0; background: #0b0f19; color: #f3f4f6; font-family: 'Segoe UI', Tahoma, sans-serif; display: flex; flex-direction: column; height: 100vh; }
  header { background: #111827; padding: 12px 24px; border-bottom: 1px solid #1f2937; display: flex; justify-content: space-between; align-items: center; }
  header h1 { margin: 0; font-size: 1.25rem; color: #10b981; font-weight: 700; letter-spacing: 0.05em; }
  header .status { font-size: 0.85rem; color: #9ca3af; }
  #network { flex: 1; width: 100%; height: 100%; background: #0b0f19; }
</style>
</head>
<body>
<header>
  <h1>FALCON NETWORK INTELLIGENCE PLATFORM</h1>
  <div class="status">Live Operational Topology & Blast Radius HUD &bull; Auto-Sync: 3s</div>
</header>
<div id="network"></div>
<script>
  let network = null;
  async function reloadGraph() {
    try {
      const res = await fetch('/api/graph');
      const data = await res.json();
      const container = document.getElementById('network');
      const networkData = {
        nodes: new vis.DataSet(data.nodes || []),
        edges: new vis.DataSet(data.edges || [])
      };
      const options = {
        nodes: { font: { color: '#f3f4f6', face: 'monospace' } },
        edges: { font: { color: '#9ca3af', size: 10 }, arrows: { to: { enabled: true } } },
        physics: { stabilization: true, barnesHut: { springLength: 100 } }
      };
      if (!network) {
        network = new vis.Network(container, networkData, options);
      } else {
        network.setData(networkData);
      }
    } catch(e) { console.error(e); }
  }
  reloadGraph();
  setInterval(reloadGraph, 3000);
</script>
</body>
</html>`
	_, _ = w.Write([]byte(html))
}
