// Package evidence manages the evidence lifecycle, lineage tracing, and fact verification.
package evidence

import (
	"fmt"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// LineageNode represents one link in the evidence verification chain.
type LineageNode struct {
	Level       string    `json:"level"` // "finding", "rule", "evidence", "source"
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// Lineage represents the full trace: Finding -> Rule -> Evidence -> Source.
type Lineage struct {
	FindingID  string        `json:"finding_id"`
	RuleID     string        `json:"rule_id"`
	EntityID   string        `json:"entity_id"`
	EntityType string        `json:"entity_type"`
	Nodes      []LineageNode `json:"nodes"`
}

// Manager manages evidence queries and lineage reconstruction.
type Manager struct {
	repo *storage.Repository
}

// NewManager creates a new Evidence Manager.
func NewManager(repo *storage.Repository) *Manager {
	return &Manager{repo: repo}
}

// List returns all evidence items for the workspace.
func (m *Manager) List(workspace string) ([]domain.Evidence, error) {
	return m.repo.ListEvidence(workspace)
}

// GetByID retrieves a single evidence record by ID.
func (m *Manager) GetByID(id string) (*domain.Evidence, error) {
	return m.repo.GetEvidence(id)
}

// GetByEntity retrieves all evidence associated with a specific domain entity.
func (m *Manager) GetByEntity(entityType, entityID string) ([]domain.Evidence, error) {
	return m.repo.ListEvidenceByEntity(entityType, entityID)
}

// GetLineage reconstructs the evidence lineage for a finding.
func (m *Manager) GetLineage(workspace, findingID string) (*Lineage, error) {
	fnd, err := m.repo.GetFinding(findingID)
	if err != nil {
		return nil, fmt.Errorf("retrieving finding %s: %w", findingID, err)
	}
	if fnd == nil {
		return nil, fmt.Errorf("finding %s not found", findingID)
	}

	lineage := &Lineage{
		FindingID:  fnd.ID,
		RuleID:     fnd.RuleID,
		EntityID:   fnd.EntityID,
		EntityType: fnd.EntityType,
		Nodes: []LineageNode{
			{
				Level:       "finding",
				ID:          fnd.ID,
				Description: fmt.Sprintf("[%s] %s", fnd.RuleID, fnd.Title),
				Timestamp:   fnd.CreatedAt,
			},
			{
				Level:       "rule",
				ID:          fnd.RuleID,
				Description: fmt.Sprintf("Rule execution: %s against %s %s", fnd.RuleID, fnd.EntityType, fnd.EntityID),
				Timestamp:   fnd.CreatedAt,
			},
		},
	}

	// Fetch referenced evidence
	for _, evID := range fnd.EvidenceIDs {
		ev, err := m.repo.GetEvidence(evID)
		if err != nil || ev == nil {
			continue
		}

		lineage.Nodes = append(lineage.Nodes, LineageNode{
			Level:       "evidence",
			ID:          ev.ID,
			Description: fmt.Sprintf("[%s] %s (Entity: %s %s)", ev.Category, ev.Description, ev.EntityType, ev.EntityID),
			Timestamp:   ev.ObservedAt,
		})

		lineage.Nodes = append(lineage.Nodes, LineageNode{
			Level:       "source",
			ID:          ev.SourceID,
			Description: fmt.Sprintf("Source: %s (observed %s)", ev.SourceID, ev.ObservedAt.Format(time.RFC3339)),
			Timestamp:   ev.ObservedAt,
		})
	}

	return lineage, nil
}
