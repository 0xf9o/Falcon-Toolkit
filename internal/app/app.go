// Package app provides the high-level application orchestration layer.
// CLI commands call App services; CLI handlers do not perform direct SQL queries or graph operations.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/assessment"
	"github.com/falcon-toolkit/falcon/internal/audit"
	"github.com/falcon-toolkit/falcon/internal/collector"
	"github.com/falcon-toolkit/falcon/internal/config"
	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/evidence"
	"github.com/falcon-toolkit/falcon/internal/graph"
	"github.com/falcon-toolkit/falcon/internal/importer"
	"github.com/falcon-toolkit/falcon/internal/modules"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/reporting"
	"github.com/falcon-toolkit/falcon/internal/scope"
	"github.com/falcon-toolkit/falcon/internal/storage"
	"github.com/falcon-toolkit/falcon/internal/target"
	"github.com/falcon-toolkit/falcon/internal/workspace"
)

// App is the central container for Falcon services.
type App struct {
	Config           *config.Config
	WorkspaceManager *workspace.Manager
	Modules          *modules.Registry
}

// New creates and initializes an App instance.
func New(cfg *config.Config) *App {
	return &App{
		Config:           cfg,
		WorkspaceManager: workspace.NewManager(cfg),
		Modules:          modules.DefaultRegistry(),
	}
}

// Close gracefully closes any open database handles.
func (a *App) Close() error {
	return a.WorkspaceManager.Close()
}

// Repo returns the active repository for current workspace.
func (a *App) Repo() (*storage.Repository, error) {
	return a.WorkspaceManager.ActiveRepo()
}

// DB returns the active database connection.
func (a *App) DB() (*storage.DB, error) {
	return a.WorkspaceManager.ActiveDB()
}

// ActiveWorkspace returns the name of the currently selected workspace.
func (a *App) ActiveWorkspace() string {
	return a.WorkspaceManager.ActiveName()
}

// -------------------------------------------------------------------
// Workspaces
// -------------------------------------------------------------------

func (a *App) ListWorkspaces() ([]workspace.WorkspaceInfo, error) {
	return a.WorkspaceManager.List()
}

func (a *App) CreateWorkspace(name string) error {
	return a.WorkspaceManager.Create(name)
}

func (a *App) UseWorkspace(name string) error {
	return a.WorkspaceManager.Use(name)
}

func (a *App) DeleteWorkspace(name string) error {
	return a.WorkspaceManager.Delete(name)
}

func (a *App) WorkspaceInfo(name string) (*workspace.WorkspaceInfo, error) {
	return a.WorkspaceManager.GetInfo(name)
}

func (a *App) ExportWorkspace(name, destFile string) error {
	return a.WorkspaceManager.Export(name, destFile)
}

func (a *App) ImportWorkspaceArchive(archivePath, targetName string) error {
	return a.WorkspaceManager.ImportArchive(archivePath, targetName)
}

// -------------------------------------------------------------------
// Entities
// -------------------------------------------------------------------

func (a *App) ListAssets() ([]domain.Asset, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListAssets(a.ActiveWorkspace())
}

func (a *App) GetAsset(id string) (*domain.Asset, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetAsset(id)
}

func (a *App) ListServices() ([]domain.Service, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListServices(a.ActiveWorkspace())
}

func (a *App) ListInterfaces() ([]domain.Interface, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListInterfaces(a.ActiveWorkspace())
}

func (a *App) ListNetworks() ([]domain.Network, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListNetworks(a.ActiveWorkspace())
}

func (a *App) ListEvidence() ([]domain.Evidence, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	mgr := evidence.NewManager(repo)
	return mgr.List(a.ActiveWorkspace())
}

func (a *App) GetEvidenceLineage(findingID string) (*evidence.Lineage, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	mgr := evidence.NewManager(repo)
	return mgr.GetLineage(a.ActiveWorkspace(), findingID)
}

// -------------------------------------------------------------------
// Import
// -------------------------------------------------------------------

func (a *App) ImportFile(filePath string, opts importer.ImportOptions) (*importer.ImportSummary, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	imp := importer.New(repo)
	return imp.ImportFile(a.ActiveWorkspace(), filePath, opts)
}

// -------------------------------------------------------------------
// Assessment
// -------------------------------------------------------------------

func (a *App) RunAssessment() (*assessment.AssessmentResult, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	engine := assessment.NewEngine(repo, nil)
	return engine.Run(a.ActiveWorkspace())
}

func (a *App) ListFindings() ([]domain.Finding, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListFindings(a.ActiveWorkspace())
}

func (a *App) GetFinding(id string) (*domain.Finding, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetFinding(id)
}

func (a *App) ExplainFinding(findingID string) (*assessment.Explanation, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	explainer := assessment.NewExplainer(repo)
	return explainer.ExplainFinding(findingID)
}

func (a *App) Why(query string, secondaryQuery ...string) (*assessment.Explanation, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	explainer := assessment.NewExplainer(repo)

	// If secondary query provided or query is an edge format (A->B), explain relationship via graph
	if len(secondaryQuery) > 0 || strings.Contains(query, "->") {
		src := query
		dst := ""
		if len(secondaryQuery) > 0 {
			dst = secondaryQuery[0]
		} else {
			parts := strings.Split(query, "->")
			src = strings.TrimSpace(parts[0])
			dst = strings.TrimSpace(parts[1])
		}

		g, err := a.BuildGraph()
		if err == nil {
			edgeType := domain.RelConnectedTo
			conf := domain.ConfidenceMedium
			for _, e := range g.Edges() {
				if (e.SourceID == src && e.TargetID == dst) || (e.SourceID == dst && e.TargetID == src) {
					edgeType = e.Type
					conf = e.Confidence
					break
				}
			}
			var evList []domain.Evidence
			allEv, _ := repo.ListEvidence(a.ActiveWorkspace())
			for _, ev := range allEv {
				if ev.EntityID == src || ev.EntityID == dst {
					evList = append(evList, ev)
				}
			}
			return explainer.ExplainRelationship(src, dst, string(edgeType), conf, evList), nil
		}
	}

	// If query matches a path (e.g. PATH-001)
	if strings.HasPrefix(strings.ToUpper(query), "PATH-") {
		paths, err := a.GetAttackPaths()
		if err == nil {
			for _, p := range paths {
				if strings.EqualFold(p.ID, query) {
					var sb strings.Builder
					sb.WriteString(fmt.Sprintf("Analytical attack path with %d steps across network topology:\n\n", len(p.Steps)))
					for i, st := range p.Steps {
						sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, st))
					}
					return &assessment.Explanation{
						TargetType:   "PATH",
						TargetID:     p.ID,
						Belief:       p.Title,
						Rationale:    sb.String(),
						Confidence:   p.Confidence,
						IsSufficient: p.EvidenceCount > 0,
						Title:        p.Title,
						Description:  sb.String(),
						FirstSeen:    time.Now().UTC(),
						LastSeen:     time.Now().UTC(),
					}, nil
				}
			}
		}
	}

	return explainer.ExplainGeneral(a.ActiveWorkspace(), query)
}

// -------------------------------------------------------------------
// Graph
// -------------------------------------------------------------------

func (a *App) BuildGraph() (*graph.Graph, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return graph.BuildFromStorage(repo, a.ActiveWorkspace())
}

func (a *App) GraphStats() (*graph.GraphStats, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	stats := g.Stats()
	return &stats, nil
}

func (a *App) GraphPath(src, dst string) ([]string, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	path := g.ShortestPath(src, dst)
	return path, nil
}

func (a *App) GraphDetailedPath(src, dst string) (*graph.DetailedPathResult, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	return g.DetailedPath(src, dst), nil
}

func (a *App) GraphNeighbors(id string) ([]*graph.Node, []*graph.Edge, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, nil, err
	}
	nodes, edges := g.Neighbors(id)
	return nodes, edges, nil
}

func (a *App) GraphServices(id string) ([]*graph.Node, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	return g.ServicesFor(id), nil
}

func (a *App) GraphHosts(id string) ([]*graph.Node, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	return g.HostsFor(id), nil
}

func (a *App) GraphNodesByType(t graph.NodeType) ([]*graph.Node, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	return g.NodesByType(t), nil
}

func (a *App) GraphComponents() ([][]string, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	return g.ConnectedComponents(), nil
}

func (a *App) GraphIsolated() ([]*graph.Node, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}
	return g.IsolatedNodes(), nil
}

func (a *App) GraphExportDOT() (string, error) {
	g, err := a.BuildGraph()
	if err != nil {
		return "", err
	}
	return g.ExportDOT(), nil
}

// -------------------------------------------------------------------
// Reporting
// -------------------------------------------------------------------

func (a *App) GenerateReport(format reporting.ReportFormat, includeEntities bool) (string, error) {
	repo, err := a.Repo()
	if err != nil {
		return "", err
	}
	rep := reporting.NewReporter(repo)
	summary, err := rep.GenerateSummary(a.ActiveWorkspace(), includeEntities)
	if err != nil {
		return "", err
	}
	return rep.Render(summary, format)
}

func (a *App) CompareSnapshots(baseID, targetID string) (*reporting.AssessmentDiff, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return reporting.CompareSnapshots(repo, baseID, targetID)
}

// -------------------------------------------------------------------
// Audit & Tags & Notes & Saved Queries
// -------------------------------------------------------------------

func (a *App) ListAuditEvents() ([]domain.AuditEvent, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	logger := audit.NewLogger(repo)
	return logger.List(a.ActiveWorkspace())
}

func (a *App) AddTag(entityType, entityID, name string) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}
	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "tag")
	tag := &domain.Tag{
		ID:         fmt.Sprintf("TAG-%04d", seq),
		EntityType: entityType,
		EntityID:   entityID,
		Name:       name,
	}
	return repo.SaveTag(tag)
}

func (a *App) ListTags(entityType, entityID string) ([]domain.Tag, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListTagsByEntity(entityType, entityID)
}

func (a *App) AddNote(entityType, entityID, content string) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}
	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "note")
	note := &domain.Note{
		ID:         fmt.Sprintf("NOTE-%04d", seq),
		EntityType: entityType,
		EntityID:   entityID,
		Content:    content,
	}
	return repo.SaveNote(note)
}

func (a *App) ListNotes(entityType, entityID string) ([]domain.Note, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListNotesByEntity(entityType, entityID)
}

func (a *App) SaveQuery(name, command string) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}
	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "query")
	q := &domain.SavedQuery{
		ID:          fmt.Sprintf("QRY-%03d", seq),
		WorkspaceID: a.ActiveWorkspace(),
		Name:        name,
		Command:     command,
	}
	return repo.SaveQuery(q)
}

func (a *App) ListSavedQueries() ([]domain.SavedQuery, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListSavedQueries(a.ActiveWorkspace())
}

func (a *App) GetSavedQuery(name string) (*domain.SavedQuery, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetSavedQuery(a.ActiveWorkspace(), name)
}

// -------------------------------------------------------------------
// Targets & Scope
// -------------------------------------------------------------------

// SetTarget parses, normalizes, validates, and sets the active target for the workspace.
func (a *App) SetTarget(rawInput string) (*domain.Target, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	parsed, err := target.ParseTarget(rawInput)
	if err != nil {
		return nil, err
	}
	parsed.WorkspaceID = a.ActiveWorkspace()

	// Check if target matches existing normalized value in workspace
	existing, err := repo.GetTargetByNormalizedValue(a.ActiveWorkspace(), parsed.NormalizedValue)
	if err == nil && existing != nil {
		existing.Status = domain.TargetStatusActive
		existing.Scope = domain.TargetInScope
		existing.UpdatedAt = time.Now().UTC()
		if len(parsed.Metadata) > 0 {
			existing.Metadata = parsed.Metadata
		}
		if err := repo.SaveTarget(existing); err != nil {
			return nil, err
		}
		_ = repo.RecordAuditEvent(&domain.AuditEvent{
			ID:          domain.FormatAuditID(1),
			WorkspaceID: a.ActiveWorkspace(),
			Action:      domain.AuditFindingChanged,
			EntityType:  "target",
			EntityID:    existing.ID,
			Detail:      fmt.Sprintf("Activated target %s (%s)", existing.NormalizedValue, existing.Type),
			CreatedAt:   time.Now().UTC(),
		})
		return existing, nil
	}

	// Validate against ScopeGuard
	sg, _ := a.BuildScopeGuard()
	if sg != nil {
		if err := sg.Validate(parsed); err != nil {
			return nil, err
		}
	}

	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "target")
	parsed.ID = domain.FormatTargetID(seq)
	parsed.Status = domain.TargetStatusActive

	if err := repo.SaveTarget(parsed); err != nil {
		return nil, err
	}

	_ = repo.RecordAuditEvent(&domain.AuditEvent{
		ID:          domain.FormatAuditID(1),
		WorkspaceID: a.ActiveWorkspace(),
		Action:      domain.AuditFindingChanged,
		EntityType:  "target",
		EntityID:    parsed.ID,
		Detail:      fmt.Sprintf("Created target %s (%s)", parsed.NormalizedValue, parsed.Type),
		CreatedAt:   time.Now().UTC(),
	})

	return parsed, nil
}

// GetActiveTarget returns the primary active or most recently updated target in the workspace.
func (a *App) GetActiveTarget() (*domain.Target, error) {
	targets, err := a.ListTargets()
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	// Look for active target first
	for _, t := range targets {
		if t.Status == domain.TargetStatusActive {
			return &t, nil
		}
	}

	// Fallback to the latest target
	return &targets[len(targets)-1], nil
}

func (a *App) AddTarget(value string, targetType domain.TargetType) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}

	parsed, err := target.ParseTarget(value)
	if err == nil {
		if targetType != "" {
			parsed.Type = targetType
		}
		parsed.WorkspaceID = a.ActiveWorkspace()
		seq, _ := repo.NextSequence(a.ActiveWorkspace(), "target")
		parsed.ID = domain.FormatTargetID(seq)
		return repo.SaveTarget(parsed)
	}

	// Fallback if parsing didn't match standard formats
	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "target")
	t := &domain.Target{
		ID:              domain.FormatTargetID(seq),
		WorkspaceID:     a.ActiveWorkspace(),
		Input:           value,
		NormalizedValue: value,
		Value:           value,
		Type:            targetType,
		Scope:           domain.TargetInScope,
		Status:          domain.TargetStatusPending,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	return repo.SaveTarget(t)
}

func (a *App) GetTarget(id string) (*domain.Target, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetTarget(id)
}

func (a *App) ListTargets() ([]domain.Target, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListTargets(a.ActiveWorkspace())
}

func (a *App) DeleteTarget(id string) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}
	return repo.DeleteTarget(id)
}

// -------------------------------------------------------------------
// Scope Rules & ScopeGuard
// -------------------------------------------------------------------

func (a *App) BuildScopeGuard() (*scope.ScopeGuard, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	rules, err := repo.ListScopeRules(a.ActiveWorkspace())
	if err != nil {
		return nil, err
	}
	targets, err := repo.ListTargets(a.ActiveWorkspace())
	if err != nil {
		return nil, err
	}
	return scope.NewScopeGuard(a.ActiveWorkspace(), rules, targets), nil
}

func (a *App) AddScopeRule(ruleType domain.ScopeRuleType, pattern, description string) (*domain.ScopeRule, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("scope pattern cannot be empty")
	}

	// Classify target type from pattern
	tType, norm, _, err := target.ClassifyAndNormalize(pattern)
	if err != nil {
		// Default to domain or IP pattern
		if strings.Contains(pattern, "/") {
			tType = domain.TargetCIDR
		} else if net.ParseIP(pattern) != nil {
			tType = domain.TargetIPv4
		} else {
			tType = domain.TargetDomain
		}
		norm = pattern
	}

	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "scoperule")
	rule := &domain.ScopeRule{
		ID:          domain.FormatScopeRuleID(seq),
		WorkspaceID: a.ActiveWorkspace(),
		RuleType:    ruleType,
		TargetType:  tType,
		Pattern:     norm,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}

	if err := repo.SaveScopeRule(rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (a *App) ListScopeRules() ([]domain.ScopeRule, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListScopeRules(a.ActiveWorkspace())
}

func (a *App) DeleteScopeRule(id string) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}
	return repo.DeleteScopeRule(id)
}

func (a *App) GenerateAssessmentPlan(targetID, profile string) (*domain.AssessmentPlan, error) {
	var tgt *domain.Target
	var err error

	if targetID != "" {
		tgt, err = a.GetTarget(targetID)
		if err != nil {
			return nil, err
		}
		if tgt == nil {
			return nil, fmt.Errorf("target %s not found", targetID)
		}
	} else {
		tgt, err = a.GetActiveTarget()
		if err != nil {
			return nil, err
		}
		if tgt == nil {
			return nil, fmt.Errorf("no target defined in active workspace. Define one using 'target <val>'")
		}
	}

	sg, _ := a.BuildScopeGuard()
	return assessment.GenerateAssessmentPlan(tgt, sg, profile)
}

// ExecuteAssessment executes an active assessment using registered collectors, scope boundaries, and rules.
func (a *App) ExecuteAssessment(
	ctx context.Context,
	targetID string,
	opts collector.CollectorOptions,
	onProgress assessment.ProgressFunc,
) (*domain.AssessmentRun, *assessment.AssessmentResult, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, nil, err
	}

	var tgt *domain.Target
	if targetID != "" {
		tgt, err = a.GetTarget(targetID)
		if err != nil {
			return nil, nil, err
		}
		if tgt == nil {
			tgt, err = repo.GetTargetByNormalizedValue(a.ActiveWorkspace(), targetID)
			if err != nil || tgt == nil {
				return nil, nil, fmt.Errorf("target '%s' not found in workspace", targetID)
			}
		}
	} else {
		tgt, err = a.GetActiveTarget()
		if err != nil {
			return nil, nil, err
		}
		if tgt == nil {
			return nil, nil, fmt.Errorf("no active assessment target defined. Set a target first: target <value>")
		}
	}

	guard, err := a.BuildScopeGuard()
	if err != nil {
		return nil, nil, fmt.Errorf("building scope guard: %w", err)
	}

	pipeline := observation.NewPipeline(repo)
	engine := assessment.NewEngine(repo, nil)
	registry := collector.NewDefaultRegistry()
	executor := assessment.NewExecutor(repo, pipeline, engine, registry, guard)

	return executor.Execute(ctx, a.ActiveWorkspace(), tgt, opts, onProgress)
}

func (a *App) GetLatestAssessmentRun() (*domain.AssessmentRun, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetLatestAssessmentRun(a.ActiveWorkspace())
}

func (a *App) ListAssessmentRuns() ([]domain.AssessmentRun, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListAssessmentRuns(a.ActiveWorkspace())
}

// -------------------------------------------------------------------
// Engagements
// -------------------------------------------------------------------

func (a *App) CreateEngagement(name, engType, description string) (*domain.Engagement, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "engagement")
	eng := &domain.Engagement{
		ID:          domain.FormatEngagementID(seq),
		WorkspaceID: a.ActiveWorkspace(),
		Name:        name,
		Type:        engType,
		Status:      domain.EngagementActive,
		Description: description,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := repo.SaveEngagement(eng); err != nil {
		return nil, err
	}
	return eng, nil
}

func (a *App) GetActiveEngagement() (*domain.Engagement, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	eng, err := repo.GetActiveEngagement(a.ActiveWorkspace())
	if err != nil || eng == nil {
		// Return default engagement if none created yet
		return &domain.Engagement{
			ID:          "ENG-001",
			WorkspaceID: a.ActiveWorkspace(),
			Name:        "Default Red Team Engagement",
			Type:        "Internal Assessment",
			Status:      domain.EngagementActive,
			Objectives: []domain.Objective{
				{ID: "OBJ-1", Title: "External Surface Analysis", Completed: false},
				{ID: "OBJ-2", Title: "Internal Segmentation", Completed: false},
				{ID: "OBJ-3", Title: "OT / ICS Exposure", Completed: false},
				{ID: "OBJ-4", Title: "Technology Mapping", Completed: false},
				{ID: "OBJ-5", Title: "Trust Boundary Analysis", Completed: false},
			},
		}, nil
	}
	return eng, nil
}

func (a *App) ListEngagements() ([]domain.Engagement, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListEngagements(a.ActiveWorkspace())
}

func (a *App) AddObjective(engID, title string) error {
	repo, err := a.Repo()
	if err != nil {
		return err
	}
	seq, _ := repo.NextSequence(a.ActiveWorkspace(), "objective")
	obj := &domain.Objective{
		ID:           fmt.Sprintf("OBJ-%03d", seq),
		EngagementID: engID,
		Title:        title,
		Completed:    false,
		CreatedAt:    time.Now().UTC(),
	}
	return repo.SaveObjective(obj)
}

// -------------------------------------------------------------------
// Red Team Attack Surface & Analytics
// -------------------------------------------------------------------

func (a *App) GetAttackSurface(category string) (*domain.AttackSurfaceSummary, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	assets, _ := repo.ListAssets(a.ActiveWorkspace())
	networks, _ := repo.ListNetworks(a.ActiveWorkspace())
	services, _ := repo.ListServices(a.ActiveWorkspace())
	findings, _ := repo.ListFindings(a.ActiveWorkspace())

	otIndicators := domain.KnownOTIndicators()
	otPortMap := make(map[int]bool)
	for _, ind := range otIndicators {
		otPortMap[ind.Port] = true
	}

	summary := &domain.AttackSurfaceSummary{
		AssetCount:     len(assets),
		NetworkCount:   len(networks),
		ServiceCount:   len(services),
		FindingCount:   len(findings),
		CategoryCounts: make(map[string]int),
	}

	for _, s := range services {
		if s.Technology != "" {
			summary.TechnologyCount++
		} else {
			summary.UnknownTechnologies++
		}
		if otPortMap[s.Port] {
			summary.OTCount++
		}
		if s.ServiceName == "" && s.Technology == "" {
			summary.UnclassifiedServices++
		}
	}

	for _, asset := range assets {
		ifaces, _ := repo.ListInterfacesByAsset(asset.ID)
		if len(ifaces) > 1 {
			summary.MultiInterface++
			summary.CrossNetworkLinks += len(ifaces)
		}
		for _, ifc := range ifaces {
			ip := net.ParseIP(ifc.Address)
			if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
				summary.InternetAddressed++
			}
		}
	}

	boundaries, _ := a.GetTrustBoundaries()
	summary.TrustBoundaryCount = len(boundaries)

	return summary, nil
}

func (a *App) GetAttackPaths() ([]domain.AttackPath, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	g, err := a.BuildGraph()
	if err != nil {
		return nil, err
	}

	assets, _ := repo.ListAssets(a.ActiveWorkspace())
	services, _ := repo.ListServices(a.ActiveWorkspace())

	otIndicators := domain.KnownOTIndicators()
	otPortMap := make(map[int]string)
	for _, ind := range otIndicators {
		otPortMap[ind.Port] = ind.Name
	}

	type sensitiveTarget struct {
		assetID string
		service *domain.Service
		label   string
	}
	var sensitiveTargets []sensitiveTarget

	for _, s := range services {
		if otName, isOT := otPortMap[s.Port]; isOT {
			sensitiveTargets = append(sensitiveTargets, sensitiveTarget{
				assetID: s.AssetID,
				service: &s,
				label:   fmt.Sprintf("OT Protocol: %s on port %d", otName, s.Port),
			})
		} else if s.Port == 3389 || s.Port == 22 || s.Port == 5985 || s.Port == 5986 {
			sensitiveTargets = append(sensitiveTargets, sensitiveTarget{
				assetID: s.AssetID,
				service: &s,
				label:   fmt.Sprintf("Remote Access: %s on port %d", s.ServiceName, s.Port),
			})
		} else if s.Port == 389 || s.Port == 636 || s.Port == 88 {
			sensitiveTargets = append(sensitiveTargets, sensitiveTarget{
				assetID: s.AssetID,
				service: &s,
				label:   fmt.Sprintf("Directory Service: %s on port %d", s.ServiceName, s.Port),
			})
		} else if s.Port == 1433 || s.Port == 3306 || s.Port == 5432 || s.Port == 6379 {
			sensitiveTargets = append(sensitiveTargets, sensitiveTarget{
				assetID: s.AssetID,
				service: &s,
				label:   fmt.Sprintf("Database Service: %s on port %d", s.ServiceName, s.Port),
			})
		}
	}

	var paths []domain.AttackPath
	pathSeq := 1
	seenPaths := make(map[string]bool)

	// Identify potential entry assets
	var entryAssets []domain.Asset
	for _, asset := range assets {
		ifaces, _ := repo.ListInterfacesByAsset(asset.ID)
		isExternal := false
		for _, ifc := range ifaces {
			ip := net.ParseIP(ifc.Address)
			if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
				isExternal = true
				break
			}
		}
		if isExternal || len(ifaces) > 1 {
			entryAssets = append(entryAssets, asset)
		}
	}
	if len(entryAssets) == 0 && len(assets) > 0 {
		entryAssets = append(entryAssets, assets[0])
	}

	for _, entry := range entryAssets {
		for _, st := range sensitiveTargets {
			if entry.ID == st.assetID {
				key := fmt.Sprintf("%s->%s", entry.ID, st.service.ID)
				if !seenPaths[key] {
					seenPaths[key] = true
					var steps []string
					steps = append(steps, fmt.Sprintf("Observed Asset %s (%s)", entry.ID, entry.Hostname))
					steps = append(steps, fmt.Sprintf("Service %s on port %d/%s", st.service.ServiceName, st.service.Port, st.service.Protocol))
					if st.service.Technology != "" {
						steps = append(steps, fmt.Sprintf("Technology: %s %s", st.service.Technology, st.service.Version))
					}
					steps = append(steps, st.label)

					paths = append(paths, domain.AttackPath{
						ID:            fmt.Sprintf("PATH-%03d", pathSeq),
						Title:         fmt.Sprintf("Observed Path to %s on %s (%s)", st.label, entry.ID, entry.Hostname),
						Steps:         steps,
						EvidenceCount: len(steps),
						Confidence:    domain.ConfidenceObserved,
					})
					pathSeq++
				}
				continue
			}

			detailed := g.DetailedPath(entry.ID, st.assetID)
			if detailed != nil && len(detailed.Steps) > 0 {
				key := fmt.Sprintf("%s->%s->%s", entry.ID, st.assetID, st.service.ID)
				if !seenPaths[key] {
					seenPaths[key] = true
					var steps []string
					for _, step := range detailed.Steps {
						steps = append(steps, fmt.Sprintf("[%s (%s)] ──(%s)──▶ [%s (%s)]",
							step.FromNode.ID, step.FromNode.Type, step.EdgeType, step.ToNode.ID, step.ToNode.Type))
					}
					steps = append(steps, fmt.Sprintf("Service %s on port %d (%s)", st.service.ServiceName, st.service.Port, st.label))

					paths = append(paths, domain.AttackPath{
						ID:            fmt.Sprintf("PATH-%03d", pathSeq),
						Title:         fmt.Sprintf("Multi-Hop Path from %s to %s on %s", entry.ID, st.label, st.assetID),
						Steps:         steps,
						EvidenceCount: len(steps) + detailed.Hops,
						Confidence:    domain.ConfidenceObserved,
					})
					pathSeq++
				}
			}
		}
	}

	return paths, nil
}

func (a *App) GetPivotCandidates() ([]domain.PivotCandidate, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	assets, _ := repo.ListAssets(a.ActiveWorkspace())
	var candidates []domain.PivotCandidate

	for _, asset := range assets {
		ifaces, _ := repo.ListInterfacesByAsset(asset.ID)
		svcs, _ := repo.ListServicesByAsset(asset.ID)

		var addrs []string
		for _, ifc := range ifaces {
			addrs = append(addrs, ifc.Address)
		}

		// Pivot candidacy requires true evidence of multi-homing across distinct network segments
		if len(ifaces) > 1 {
			isMultiSubnet := false
			if len(addrs) >= 2 {
				ip1 := net.ParseIP(addrs[0])
				ip2 := net.ParseIP(addrs[1])
				if ip1 != nil && ip2 != nil {
					m1 := ip1.To4()
					m2 := ip2.To4()
					if m1 != nil && m2 != nil {
						isMultiSubnet = (m1[0] != m2[0] || m1[1] != m2[1] || m1[2] != m2[2])
					}
				}
			}

			reason := fmt.Sprintf("Multi-homed system with %d network interfaces", len(ifaces))
			if isMultiSubnet {
				reason = fmt.Sprintf("Multi-homed system spanning distinct network subnets (%d interfaces)", len(ifaces))
			}

			candidates = append(candidates, domain.PivotCandidate{
				AssetID:        asset.ID,
				Hostname:       asset.Hostname,
				Addresses:      addrs,
				InterfaceCount: len(ifaces),
				ServiceCount:   len(svcs),
				Reason:         reason,
			})
		}
	}

	return candidates, nil
}

func (a *App) GetTrustBoundaries() ([]domain.TrustBoundary, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	networks, _ := repo.ListNetworks(a.ActiveWorkspace())
	assets, _ := repo.ListAssets(a.ActiveWorkspace())

	var boundaries []domain.TrustBoundary
	seenBoundaries := make(map[string]bool)

	type netMembership struct {
		netName string
		netCIDR *net.IPNet
	}
	var netList []netMembership
	for _, n := range networks {
		_, ipNet, err := net.ParseCIDR(n.CIDR)
		if err == nil {
			netList = append(netList, netMembership{netName: n.Name, netCIDR: ipNet})
		} else {
			netList = append(netList, netMembership{netName: n.Name, netCIDR: nil})
		}
	}

	// 1. Detect observed cross-network connections via multi-homed assets
	for _, asset := range assets {
		ifaces, _ := repo.ListInterfacesByAsset(asset.ID)
		if len(ifaces) < 2 {
			continue
		}

		connectedNets := make(map[string]bool)
		for _, ifc := range ifaces {
			ip := net.ParseIP(ifc.Address)
			if ip == nil {
				continue
			}
			for _, nm := range netList {
				if nm.netCIDR != nil && nm.netCIDR.Contains(ip) {
					connectedNets[nm.netName] = true
				}
			}
		}

		var netNames []string
		for nn := range connectedNets {
			netNames = append(netNames, nn)
		}

		for i := 0; i < len(netNames); i++ {
			for j := i + 1; j < len(netNames); j++ {
				key := fmt.Sprintf("%s<->%s", netNames[i], netNames[j])
				if !seenBoundaries[key] {
					seenBoundaries[key] = true
					boundaries = append(boundaries, domain.TrustBoundary{
						FromZone:         netNames[i],
						ToZone:           netNames[j],
						ConnectingAssets: []string{fmt.Sprintf("%s (%s)", asset.ID, asset.Hostname)},
						IsInferred:       false,
					})
				}
			}
		}
	}

	// 2. If networks exist but no direct bridging asset was observed, note inferred/untested boundaries between network pairs
	if len(boundaries) == 0 && len(networks) >= 2 {
		for i := 0; i < len(networks)-1; i++ {
			boundaries = append(boundaries, domain.TrustBoundary{
				FromZone:         networks[i].Name,
				ToZone:           networks[i+1].Name,
				ConnectingAssets: []string{"Observed network boundary (isolated / untested)"},
				IsInferred:       true,
			})
		}
	}

	return boundaries, nil
}

func (a *App) GetTechnologies() ([]domain.Service, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	services, err := repo.ListServices(a.ActiveWorkspace())
	if err != nil {
		return nil, err
	}
	var techServices []domain.Service
	for _, s := range services {
		if s.Technology != "" {
			techServices = append(techServices, s)
		}
	}
	return techServices, nil
}

func (a *App) GetOTIndicators() ([]domain.Service, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	services, err := repo.ListServices(a.ActiveWorkspace())
	if err != nil {
		return nil, err
	}

	indicators := domain.KnownOTIndicators()
	otPortMap := make(map[int]bool)
	for _, ind := range indicators {
		otPortMap[ind.Port] = true
	}

	var otServices []domain.Service
	for _, s := range services {
		if otPortMap[s.Port] {
			otServices = append(otServices, s)
		}
	}
	return otServices, nil
}

func (a *App) CorrelateFindings() (map[string][]domain.Finding, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	findings, err := repo.ListFindings(a.ActiveWorkspace())
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]domain.Finding)
	for _, f := range findings {
		key := f.EntityID
		if key == "" {
			key = "Global / Network"
		}
		groups[key] = append(groups[key], f)
	}

	return groups, nil
}

func (a *App) GetTimeline() ([]domain.TimelineItem, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetTimeline(a.ActiveWorkspace())
}

func (a *App) GetCoverage() (map[string]interface{}, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	assets, _ := repo.ListAssets(a.ActiveWorkspace())
	services, _ := repo.ListServices(a.ActiveWorkspace())
	networks, _ := repo.ListNetworks(a.ActiveWorkspace())

	techIdentified := 0
	for _, s := range services {
		if s.Technology != "" {
			techIdentified++
		}
	}

	rate := 0.0
	if len(services) > 0 {
		rate = float64(techIdentified) / float64(len(services)) * 100.0
	}

	return map[string]interface{}{
		"total_networks":                len(networks),
		"total_assets":                  len(assets),
		"total_services":                len(services),
		"technology_identified":         techIdentified,
		"technology_identification_pct": fmt.Sprintf("%.1f%%", rate),
	}, nil
}

func (a *App) GlobalSearch(query string) ([]storage.SearchResult, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.Search(a.ActiveWorkspace(), query)
}

func (a *App) ListSnapshots() ([]domain.AssessmentSnapshot, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.ListAssessmentSnapshots(a.ActiveWorkspace())
}

func (a *App) CreateSnapshot(name string) (*domain.AssessmentSnapshot, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}

	ws := a.ActiveWorkspace()
	findings, _ := repo.ListFindings(ws)
	assets, _ := repo.ListAssets(ws)
	services, _ := repo.ListServices(ws)
	networks, _ := repo.ListNetworks(ws)

	snapID := name
	if snapID == "" {
		seq, _ := repo.NextSequence(ws, "snapshot")
		snapID = fmt.Sprintf("SNAP-%03d", seq)
	}

	fullData := struct {
		Name      string           `json:"name"`
		CreatedAt time.Time        `json:"created_at"`
		Findings  []domain.Finding `json:"findings"`
		Assets    []domain.Asset   `json:"assets"`
		Services  []domain.Service `json:"services"`
		Networks  []domain.Network `json:"networks"`
	}{
		Name:      snapID,
		CreatedAt: time.Now().UTC(),
		Findings:  findings,
		Assets:    assets,
		Services:  services,
		Networks:  networks,
	}

	dataBytes, err := json.Marshal(fullData)
	if err != nil {
		return nil, err
	}

	snap := &domain.AssessmentSnapshot{
		ID:           snapID,
		AssessmentID: snapID,
		WorkspaceID:  ws,
		SnapshotData: string(dataBytes),
		CreatedAt:    time.Now().UTC(),
	}

	if err := repo.SaveAssessmentSnapshot(snap); err != nil {
		return nil, err
	}

	return snap, nil
}

func (a *App) GetSnapshot(id string) (*domain.AssessmentSnapshot, error) {
	repo, err := a.Repo()
	if err != nil {
		return nil, err
	}
	return repo.GetAssessmentSnapshotByAssessmentID(id)
}
