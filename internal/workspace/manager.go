// Package workspace manages Falcon workspaces.
// Each workspace is an isolated SQLite database stored at ~/.falcon/workspaces/<name>/falcon.db
package workspace

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/config"
	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// WorkspaceInfo contains metadata and statistics for a workspace.
type WorkspaceInfo struct {
	Name          string    `json:"name"`
	Path          string    `json:"path"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	AssetCount    int       `json:"asset_count"`
	ServiceCount  int       `json:"service_count"`
	NetworkCount  int       `json:"network_count"`
	FindingCount  int       `json:"finding_count"`
	EvidenceCount int       `json:"evidence_count"`
	SizeBytes     int64     `json:"size_bytes"`
	IsActive      bool      `json:"is_active"`
}

// Manager manages workspace operations.
type Manager struct {
	cfg        *config.Config
	activeName string
	activeDB   *storage.DB
	activeRepo *storage.Repository
}

// NewManager creates a new workspace manager.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:        cfg,
		activeName: cfg.Workspace,
	}
}

// ActiveName returns the name of the currently active workspace.
func (m *Manager) ActiveName() string {
	return m.activeName
}

// ActiveDB returns the active database connection, opening it if necessary.
func (m *Manager) ActiveDB() (*storage.DB, error) {
	if m.activeDB != nil {
		return m.activeDB, nil
	}
	dbPath := m.cfg.WorkspaceDBPath(m.activeName)
	db, err := storage.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening workspace database %q: %w", m.activeName, err)
	}
	m.activeDB = db
	m.activeRepo = storage.NewRepository(db)

	// Ensure workspace entry exists in DB
	ws, err := m.activeRepo.GetWorkspaceByName(m.activeName)
	if err != nil || ws == nil {
		newWS := &domain.Workspace{
			ID:        "WS-" + m.activeName,
			Name:      m.activeName,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		_ = m.activeRepo.CreateWorkspace(newWS)
	}

	return m.activeDB, nil
}

// ActiveRepo returns the active repository, opening the DB if necessary.
func (m *Manager) ActiveRepo() (*storage.Repository, error) {
	if m.activeRepo != nil {
		return m.activeRepo, nil
	}
	_, err := m.ActiveDB()
	if err != nil {
		return nil, err
	}
	return m.activeRepo, nil
}

// Close closes the active database connection if open.
func (m *Manager) Close() error {
	if m.activeDB != nil {
		err := m.activeDB.Close()
		m.activeDB = nil
		m.activeRepo = nil
		return err
	}
	return nil
}

// List returns a list of all existing workspaces.
func (m *Manager) List() ([]WorkspaceInfo, error) {
	wsDir := m.cfg.WorkspacesDir()
	if err := os.MkdirAll(wsDir, 0755); err != nil {
		return nil, fmt.Errorf("creating workspaces directory: %w", err)
	}

	entries, err := os.ReadDir(wsDir)
	if err != nil {
		return nil, fmt.Errorf("reading workspaces directory: %w", err)
	}

	var workspaces []WorkspaceInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		info, err := m.GetInfo(name)
		if err != nil {
			// Include basic entry if DB cannot be read
			workspaces = append(workspaces, WorkspaceInfo{
				Name:     name,
				Path:     m.cfg.WorkspaceDir(name),
				IsActive: name == m.activeName,
			})
			continue
		}
		workspaces = append(workspaces, *info)
	}

	// If no workspaces exist, default is always listed
	if len(workspaces) == 0 {
		workspaces = append(workspaces, WorkspaceInfo{
			Name:      "default",
			Path:      m.cfg.WorkspaceDir("default"),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			IsActive:  true,
		})
	}

	return workspaces, nil
}

// Create creates a new workspace.
func (m *Manager) Create(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("workspace name cannot be empty")
	}
	if strings.ContainsAny(name, "/\\?%*:|\"<>. ") {
		return fmt.Errorf("invalid workspace name %q: must contain only alphanumeric characters, underscores, and hyphens", name)
	}

	wsPath := m.cfg.WorkspaceDBPath(name)
	if _, err := os.Stat(wsPath); err == nil {
		return fmt.Errorf("workspace %q already exists", name)
	}

	db, err := storage.Open(wsPath)
	if err != nil {
		return fmt.Errorf("initializing workspace %q: %w", name, err)
	}
	defer db.Close()

	repo := storage.NewRepository(db)
	ws := &domain.Workspace{
		ID:        "WS-" + name,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.CreateWorkspace(ws); err != nil {
		return fmt.Errorf("persisting workspace metadata: %w", err)
	}

	_ = repo.RecordAuditEvent(&domain.AuditEvent{
		ID:          domain.FormatAuditID(1),
		WorkspaceID: ws.ID,
		Action:      domain.AuditWorkspaceCreated,
		Detail:      fmt.Sprintf("Created workspace %s", name),
		CreatedAt:   time.Now().UTC(),
	})

	return nil
}

// Use switches the active workspace.
func (m *Manager) Use(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("workspace name cannot be empty")
	}

	// Close current DB if switching
	if m.activeDB != nil && m.activeName != name {
		_ = m.activeDB.Close()
		m.activeDB = nil
		m.activeRepo = nil
	}

	m.activeName = name
	m.cfg.Workspace = name

	// Ensure the workspace DB exists by opening it
	_, err := m.ActiveDB()
	if err != nil {
		return fmt.Errorf("activating workspace %q: %w", name, err)
	}

	return nil
}

// Delete deletes a workspace and its database file.
func (m *Manager) Delete(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("workspace name cannot be empty")
	}

	if name == m.activeName {
		// Close active connection before deletion
		_ = m.Close()
	}

	wsDir := m.cfg.WorkspaceDir(name)
	if _, err := os.Stat(wsDir); os.IsNotExist(err) {
		return fmt.Errorf("workspace %q does not exist", name)
	}

	if err := os.RemoveAll(wsDir); err != nil {
		return fmt.Errorf("deleting workspace %q: %w", name, err)
	}

	// If we deleted the active workspace, switch back to default
	if name == m.activeName {
		m.activeName = "default"
		m.cfg.Workspace = "default"
	}

	return nil
}

// GetInfo returns details and counts for a specific workspace.
func (m *Manager) GetInfo(name string) (*WorkspaceInfo, error) {
	wsDir := m.cfg.WorkspaceDir(name)
	dbPath := m.cfg.WorkspaceDBPath(name)

	info := &WorkspaceInfo{
		Name:     name,
		Path:     wsDir,
		IsActive: name == m.activeName,
	}

	fi, err := os.Stat(dbPath)
	if err == nil {
		info.SizeBytes = fi.Size()
		info.UpdatedAt = fi.ModTime()
	}

	var db *storage.DB
	var shouldClose bool

	if name == m.activeName && m.activeDB != nil {
		db = m.activeDB
	} else {
		db, err = storage.Open(dbPath)
		if err != nil {
			return info, nil
		}
		shouldClose = true
	}

	if shouldClose {
		defer db.Close()
	}

	repo := storage.NewRepository(db)
	ws, _ := repo.GetWorkspaceByName(name)
	if ws != nil {
		info.CreatedAt = ws.CreatedAt
		info.UpdatedAt = ws.UpdatedAt
	}

	assets, _ := repo.ListAssets(name)
	info.AssetCount = len(assets)

	services, _ := repo.ListServices(name)
	info.ServiceCount = len(services)

	networks, _ := repo.ListNetworks(name)
	info.NetworkCount = len(networks)

	findings, _ := repo.ListFindings(name)
	info.FindingCount = len(findings)

	evidence, _ := repo.ListEvidence(name)
	info.EvidenceCount = len(evidence)

	return info, nil
}

// Export exports a workspace's data and structure to a .tar.gz archive.
func (m *Manager) Export(name, destFile string) error {
	repo, err := m.ActiveRepo()
	if err != nil {
		return err
	}

	assets, err := repo.ListAssets(name)
	if err != nil {
		return err
	}
	interfaces, err := repo.ListInterfaces(name)
	if err != nil {
		return err
	}
	services, err := repo.ListServices(name)
	if err != nil {
		return err
	}
	networks, err := repo.ListNetworks(name)
	if err != nil {
		return err
	}
	evidence, err := repo.ListEvidence(name)
	if err != nil {
		return err
	}
	findings, err := repo.ListFindings(name)
	if err != nil {
		return err
	}
	relationships, err := repo.ListRelationships(name)
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"falcon_version": "3.1.0",
		"workspace_name": name,
		"exported_at":    time.Now().UTC(),
		"assets":         assets,
		"interfaces":     interfaces,
		"services":       services,
		"networks":       networks,
		"evidence":       evidence,
		"findings":       findings,
		"relationships":  relationships,
	}

	rawJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling workspace export: %w", err)
	}

	outFile, err := os.Create(destFile)
	if err != nil {
		return fmt.Errorf("creating export archive %q: %w", destFile, err)
	}
	defer outFile.Close()

	gw := gzip.NewWriter(outFile)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	hdr := &tar.Header{
		Name:    "workspace_export.json",
		Mode:    0644,
		Size:    int64(len(rawJSON)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing archive header: %w", err)
	}
	if _, err := tw.Write(rawJSON); err != nil {
		return fmt.Errorf("writing archive content: %w", err)
	}

	return nil
}

// ImportArchive imports a workspace from a .tar.gz archive into a new or existing workspace.
func (m *Manager) ImportArchive(archivePath, targetWorkspace string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening export archive %q: %w", archivePath, err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading gzip archive: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var rawJSON []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar archive: %w", err)
		}
		if hdr.Name == "workspace_export.json" {
			rawJSON, err = io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("reading exported JSON: %w", err)
			}
			break
		}
	}

	if len(rawJSON) == 0 {
		return fmt.Errorf("archive did not contain workspace_export.json")
	}

	var payload struct {
		FalconVersion string                `json:"falcon_version"`
		Assets        []domain.Asset        `json:"assets"`
		Interfaces    []domain.Interface    `json:"interfaces"`
		Services      []domain.Service      `json:"services"`
		Networks      []domain.Network      `json:"networks"`
		Evidence      []domain.Evidence     `json:"evidence"`
		Findings      []domain.Finding      `json:"findings"`
		Relationships []domain.Relationship `json:"relationships"`
	}
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		return fmt.Errorf("parsing workspace JSON: %w", err)
	}

	if err := m.Use(targetWorkspace); err != nil {
		return err
	}

	repo, err := m.ActiveRepo()
	if err != nil {
		return err
	}

	for _, a := range payload.Assets {
		a.WorkspaceID = targetWorkspace
		_ = repo.SaveAsset(&a)
	}
	for _, iface := range payload.Interfaces {
		_ = repo.SaveInterface(&iface)
	}
	for _, svc := range payload.Services {
		_ = repo.SaveService(&svc)
	}
	for _, net := range payload.Networks {
		net.WorkspaceID = targetWorkspace
		_ = repo.SaveNetwork(&net)
	}
	for _, ev := range payload.Evidence {
		ev.WorkspaceID = targetWorkspace
		_ = repo.SaveEvidence(&ev)
	}
	for _, fnd := range payload.Findings {
		fnd.WorkspaceID = targetWorkspace
		_ = repo.SaveFinding(&fnd)
	}
	for _, rel := range payload.Relationships {
		_ = repo.SaveRelationship(&rel)
	}

	return nil
}
