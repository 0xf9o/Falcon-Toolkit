package exporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// ExportHTML generates a zero-dependency, self-contained offline interactive HTML graph.
func ExportHTML(env *schema.SessionEnvironment, outputPath string) error {
	var nodesJS []string
	var edgesJS []string

	nodeIdx := 1
	nodeIDMap := make(map[string]int)

	for cidr, p := range env.Postures {
		nodeIDMap[cidr] = nodeIdx

		color := "#10b981" // green
		if p.BlastScore >= 6.0 {
			color = "#ef4444" // red
		} else if p.BlastScore >= 3.0 {
			color = "#f59e0b" // amber
		}

		label := fmt.Sprintf("%s\\n(Blast: %.1f)", cidr, p.BlastScore)
		nodesJS = append(nodesJS, fmt.Sprintf("{id: %d, label: '%s', group: 'network', color: '%s', shape: 'box', font: {color: '#ffffff'}}",
			nodeIdx, label, color))
		nodeIdx++

		for _, host := range p.ExposedHosts {
			hIdx := nodeIdx
			nodeIDMap[host] = hIdx
			nodesJS = append(nodesJS, fmt.Sprintf("{id: %d, label: '%s', group: 'host', color: '#3b82f6', shape: 'ellipse', font: {color: '#ffffff'}}",
				hIdx, host))
			edgesJS = append(edgesJS, fmt.Sprintf("{from: %s, to: %d, label: 'contains', color: '#64748b'}",
				fmt.Sprintf("%d", nodeIDMap[cidr]), hIdx))
			nodeIdx++

			for _, s := range p.ProbedServices {
				if s.State == schema.StateOpen {
					sIdx := nodeIdx
					svcLabel := fmt.Sprintf("%s\\n%d/%s", s.ServiceName, s.Port, s.Protocol)
					nodesJS = append(nodesJS, fmt.Sprintf("{id: %d, label: '%s', group: 'service', color: '#8b5cf6', shape: 'dot', size: 15, font: {color: '#e2e8f0'}}",
						sIdx, svcLabel))
					edgesJS = append(edgesJS, fmt.Sprintf("{from: %d, to: %d, label: 'exposes', color: '#a855f7'}",
						hIdx, sIdx))
					nodeIdx++
				}
			}
		}
	}

	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Falcon Toolkit — Live Topology & Blast Radius Graph</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; overflow: hidden; }
    #header { height: 60px; padding: 12px 24px; background: #111827; border-bottom: 1px solid #1f2937; display: flex; align-items: center; justify-content: space-between; }
    #header h1 { font-size: 18px; color: #10b981; letter-spacing: 0.5px; }
    #stats { font-size: 13px; color: #94a3b8; }
    #network { width: 100vw; height: calc(100vh - 60px); }
    .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; background: #1e293b; color: #38bdf8; margin-left: 8px; }
  </style>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
</head>
<body>
  <div id="header">
    <h1>🦅 FALCON TOOLKIT — NETWORK REACHABILITY TOPOLOGY</h1>
    <div id="stats">
      Session: <span class="badge">` + env.SessionID + `</span>
      Subnets: <span class="badge">` + fmt.Sprintf("%d", len(env.Postures)) + `</span>
      Scope: <span class="badge">` + env.ActiveCIDR + `</span>
    </div>
  </div>
  <div id="network"></div>
  <script>
    var nodes = new vis.DataSet([
      ` + strings.Join(nodesJS, ",\n      ") + `
    ]);
    var edges = new vis.DataSet([
      ` + strings.Join(edgesJS, ",\n      ") + `
    ]);
    var container = document.getElementById('network');
    var data = { nodes: nodes, edges: edges };
    var options = {
      physics: {
        stabilization: true,
        barnesHut: { gravitationalConstant: -3000, springLength: 95 }
      },
      interaction: { hover: true, tooltipDelay: 200, navigationButtons: true },
      nodes: { font: { size: 12, face: 'monospace' } }
    };
    var network = new vis.Network(container, data, options);
  </script>
</body>
</html>`

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(outputPath, []byte(htmlTemplate), 0644)
}
