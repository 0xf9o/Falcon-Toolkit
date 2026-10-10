package assessment

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/graph"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// Engine orchestrates assessment rule execution, deduplication, and persistence.
type Engine struct {
	repo  *storage.Repository
	rules []Rule
}

// NewEngine creates a new Assessment Engine with default or customized rules.
func NewEngine(repo *storage.Repository, rules []Rule) *Engine {
	if len(rules) == 0 {
		rules = BuiltinRules()
	}
	return &Engine{
		repo:  repo,
		rules: rules,
	}
}

// AssessmentResult holds the summary of an assessment run.
type AssessmentResult struct {
	AssessmentID   string           `json:"assessment_id"`
	WorkspaceID    string           `json:"workspace_id"`
	RulesetVersion string           `json:"ruleset_version"`
	SchemaVersion  string           `json:"schema_version"`
	TotalFindings  int              `json:"total_findings"`
	NewFindings    int              `json:"new_findings"`
	Findings       []domain.Finding `json:"findings"`
	CreatedAt      time.Time        `json:"created_at"`
}

// Run executes all rules against the workspace data and updates findings in SQLite.
func (e *Engine) Run(workspace string) (*AssessmentResult, error) {
	now := time.Now().UTC()

	// Build in-memory graph for topological rules
	g, err := graph.BuildFromStorage(e.repo, workspace)
	if err != nil {
		return nil, fmt.Errorf("building graph for assessment: %w", err)
	}

	ctx := &AssessmentContext{
		Workspace: workspace,
		Repo:      e.repo,
		Graph:     g,
		Timestamp: now,
	}

	// Fetch existing findings to compute deltas
	existingFindings, err := e.repo.ListFindings(workspace)
	if err != nil {
		return nil, fmt.Errorf("loading existing findings: %w", err)
	}
	existingMap := make(map[string]*domain.Finding)
	for _, f := range existingFindings {
		key := fmt.Sprintf("%s:%s:%s", f.RuleID, f.EntityType, f.EntityID)
		existingMap[key] = &f
	}

	var allEvaluatedFindings []domain.Finding
	for _, rule := range e.rules {
		findings, err := rule.Evaluate(ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluating rule %s: %w", rule.ID(), err)
		}
		allEvaluatedFindings = append(allEvaluatedFindings, findings...)
	}

	newCount := 0
	var finalFindings []domain.Finding

	for _, ef := range allEvaluatedFindings {
		key := fmt.Sprintf("%s:%s:%s", ef.RuleID, ef.EntityType, ef.EntityID)
		if existing, ok := existingMap[key]; ok {
			// Update last observed and evidence
			existing.LastObserved = now
			existing.EvidenceIDs = ef.EvidenceIDs
			existing.Description = ef.Description
			existing.Title = ef.Title
			existing.UpdatedAt = now
			if err := e.repo.SaveFinding(existing); err != nil {
				return nil, fmt.Errorf("updating finding: %w", err)
			}
			finalFindings = append(finalFindings, *existing)
		} else {
			// Create new finding
			seq, err := e.repo.NextSequence(workspace, "finding")
			if err != nil {
				return nil, fmt.Errorf("generating finding sequence: %w", err)
			}
			ef.ID = domain.FormatFindingID(seq)
			ef.CreatedAt = now
			ef.UpdatedAt = now
			if err := e.repo.SaveFinding(&ef); err != nil {
				return nil, fmt.Errorf("saving new finding: %w", err)
			}
			finalFindings = append(finalFindings, ef)
			newCount++
		}
	}

	// Record assessment run
	assessSeq, _ := e.repo.NextSequence(workspace, "assessment")
	assessID := domain.FormatAssessmentID(assessSeq)

	schemaVer, _ := e.repo.DB().SchemaVersion()
	assessRecord := &domain.Assessment{
		ID:             assessID,
		WorkspaceID:    workspace,
		RulesetVersion: "3.1.0",
		SchemaVersion:  fmt.Sprintf("%d", schemaVer),
		TotalFindings:  len(finalFindings),
		NewFindings:    newCount,
		CreatedAt:      now,
	}
	_ = e.repo.SaveAssessment(assessRecord)

	// Save Assessment Snapshot
	snapData, _ := json.Marshal(finalFindings)
	snapRecord := &domain.AssessmentSnapshot{
		ID:           fmt.Sprintf("SNAP-%s", assessID),
		AssessmentID: assessID,
		WorkspaceID:  workspace,
		SnapshotData: string(snapData),
		CreatedAt:    now,
	}
	_ = e.repo.SaveAssessmentSnapshot(snapRecord)

	// Sort findings deterministically by ID
	sort.Slice(finalFindings, func(i, j int) bool {
		return finalFindings[i].ID < finalFindings[j].ID
	})

	return &AssessmentResult{
		AssessmentID:   assessID,
		WorkspaceID:    workspace,
		RulesetVersion: "3.1.0",
		SchemaVersion:  fmt.Sprintf("%d", schemaVer),
		TotalFindings:  len(finalFindings),
		NewFindings:    newCount,
		Findings:       finalFindings,
		CreatedAt:      now,
	}, nil
}
