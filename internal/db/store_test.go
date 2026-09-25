package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempDB(t *testing.T) (*Store, func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q) error: %v", path, err)
	}
	cleanup := func() {
		_ = store.Close()
		_ = os.Remove(path)
	}
	return store, cleanup
}

func TestStore_WorkspaceLifecycle(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	// Default workspace must exist after Open
	ws, err := store.GetActiveWorkspace()
	if err != nil {
		t.Fatalf("GetActiveWorkspace error: %v", err)
	}
	if ws != "default" {
		t.Errorf("expected default workspace, got %q", ws)
	}

	// Create and switch workspace
	if err := store.SetActiveWorkspace("project-alpha"); err != nil {
		t.Fatalf("SetActiveWorkspace error: %v", err)
	}
	ws, _ = store.GetActiveWorkspace()
	if ws != "project-alpha" {
		t.Errorf("expected 'project-alpha', got %q", ws)
	}

	// List should include both
	list, err := store.ListWorkspaces()
	if err != nil {
		t.Fatalf("ListWorkspaces error: %v", err)
	}
	found := false
	for _, w := range list {
		if w == "project-alpha" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'project-alpha' in workspace list")
	}
}

func TestStore_PortPersistence(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	const workspace = "test-ws"
	rec := PortRecord{
		Target:    "192.168.1.1",
		Port:      443,
		Protocol:  "tcp",
		State:     "open",
		Service:   "HTTPS",
		Banner:    "HTTP/1.1 200 OK [nginx]",
		LatencyMs: 12,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if err := store.SavePort(workspace, rec); err != nil {
		t.Fatalf("SavePort error: %v", err)
	}

	ports, err := store.GetPorts(workspace)
	if err != nil {
		t.Fatalf("GetPorts error: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(ports))
	}

	got := ports[0]
	if got.Port != 443 || got.Target != "192.168.1.1" || got.Service != "HTTPS" {
		t.Errorf("port record mismatch: %+v", got)
	}
}

func TestStore_PortUpsert(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	const ws = "upsert-ws"
	rec := PortRecord{Target: "10.0.0.1", Port: 80, Protocol: "tcp", State: "open", Service: "HTTP"}

	_ = store.SavePort(ws, rec)
	rec.Service = "HTTP-Proxy"
	_ = store.SavePort(ws, rec) // Same key — should overwrite

	ports, _ := store.GetPorts(ws)
	if len(ports) != 1 {
		t.Fatalf("expected 1 port after upsert, got %d", len(ports))
	}
	if ports[0].Service != "HTTP-Proxy" {
		t.Errorf("expected upserted service 'HTTP-Proxy', got %q", ports[0].Service)
	}
}

func TestStore_SubdomainPersistence(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	const ws = "sub-ws"
	rec := SubdomainRecord{
		Domain:    "example.com",
		Subdomain: "www.example.com",
		IPs:       []string{"93.184.216.34"},
		Source:    "crt.sh+dns",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if err := store.SaveSubdomain(ws, rec); err != nil {
		t.Fatalf("SaveSubdomain error: %v", err)
	}

	subs, err := store.GetSubdomains(ws)
	if err != nil {
		t.Fatalf("GetSubdomains error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subdomain, got %d", len(subs))
	}
	if subs[0].Subdomain != "www.example.com" {
		t.Errorf("subdomain mismatch: %+v", subs[0])
	}
	if len(subs[0].IPs) != 1 || subs[0].IPs[0] != "93.184.216.34" {
		t.Errorf("IP mismatch: %+v", subs[0].IPs)
	}
}

func TestStore_TopologyGraph(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	const ws = "topo-ws"

	// Save asset nodes
	err := store.SaveAssetNode(ws, AssetNode{
		ID:   "example.com",
		Name: "example.com",
		Type: AssetDomain,
	})
	if err != nil {
		t.Fatalf("SaveAssetNode error: %v", err)
	}
	err = store.SaveAssetNode(ws, AssetNode{
		ID:       "93.184.216.34",
		Name:     "93.184.216.34",
		Type:     AssetIP,
		ParentID: "example.com",
	})
	if err != nil {
		t.Fatalf("SaveAssetNode (child) error: %v", err)
	}

	// Save a service node
	err = store.SaveServiceNode(ws, ServiceNode{
		ID:      "93.184.216.34:443",
		AssetID: "93.184.216.34",
		Port:    443,
		Service: "HTTPS",
	})
	if err != nil {
		t.Fatalf("SaveServiceNode error: %v", err)
	}

	graph, err := store.GetTopologyGraph(ws)
	if err != nil {
		t.Fatalf("GetTopologyGraph error: %v", err)
	}

	if len(graph.Assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(graph.Assets))
	}
	if len(graph.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(graph.Services))
	}
	if len(graph.Edges) < 2 {
		t.Errorf("expected at least 2 edges (parent+service), got %d", len(graph.Edges))
	}
}

func TestStore_ExportJSON(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	const ws = "export-ws"
	_ = store.SavePort(ws, PortRecord{Target: "1.2.3.4", Port: 22, Protocol: "tcp", State: "open"})
	_ = store.SaveSubdomain(ws, SubdomainRecord{Domain: "test.com", Subdomain: "api.test.com", Source: "crt.sh"})

	outPath := filepath.Join(t.TempDir(), "report.json")
	if err := store.ExportJSON(ws, outPath); err != nil {
		t.Fatalf("ExportJSON error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON export file")
	}
}

func TestStore_ExportCSV_Ports(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	const ws = "csv-ws"
	_ = store.SavePort(ws, PortRecord{Target: "10.0.0.1", Port: 80, Protocol: "tcp", State: "open", Service: "HTTP"})

	outPath := filepath.Join(t.TempDir(), "ports.csv")
	if err := store.ExportCSV(ws, "ports", outPath); err != nil {
		t.Fatalf("ExportCSV error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	if len(data) == 0 {
		t.Error("expected non-empty CSV export")
	}
}

func TestStore_ExportCSV_InvalidCategory(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	err := store.ExportCSV("ws", "invalid_category", t.TempDir()+"/out.csv")
	if err == nil {
		t.Error("expected error for invalid export category")
	}
}

func TestRenderTopologyTree_Empty(t *testing.T) {
	graph := &TopologyGraph{
		Workspace: "empty",
		Assets:    make(map[string]AssetNode),
		Services:  make(map[string]ServiceNode),
		Edges:     []TopologyEdge{},
	}
	out := RenderTopologyTree(graph)
	if out == "" {
		t.Error("expected non-empty render for empty graph")
	}
}

func TestRenderTopologyTree_Populated(t *testing.T) {
	graph := &TopologyGraph{
		Workspace: "demo",
		Assets: map[string]AssetNode{
			"target.com": {ID: "target.com", Name: "target.com", Type: AssetDomain},
			"1.2.3.4":    {ID: "1.2.3.4", Name: "1.2.3.4", Type: AssetIP, ParentID: "target.com"},
		},
		Services: map[string]ServiceNode{
			"1.2.3.4:80": {ID: "1.2.3.4:80", AssetID: "1.2.3.4", Port: 80, Service: "HTTP"},
		},
		Edges: []TopologyEdge{},
	}

	out := RenderTopologyTree(graph)
	if out == "" {
		t.Error("expected non-empty topology tree render")
	}
}
