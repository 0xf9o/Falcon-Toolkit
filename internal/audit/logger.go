// Package audit provides structured audit logging for workspace mutations and critical operations.
package audit

import (
	"fmt"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// Logger writes audit events to the workspace database.
type Logger struct {
	repo *storage.Repository
}

// NewLogger creates a new audit Logger.
func NewLogger(repo *storage.Repository) *Logger {
	return &Logger{repo: repo}
}

// Log records an audit event in the database.
func (l *Logger) Log(workspace string, action domain.AuditAction, entityType, entityID, detail string) error {
	seq, err := l.repo.NextSequence(workspace, "audit")
	if err != nil {
		return fmt.Errorf("generating audit sequence: %w", err)
	}

	event := &domain.AuditEvent{
		ID:          domain.FormatAuditID(seq),
		WorkspaceID: workspace,
		Action:      action,
		EntityType:  entityType,
		EntityID:    entityID,
		Detail:      detail,
		CreatedAt:   time.Now().UTC(),
	}

	return l.repo.RecordAuditEvent(event)
}

// List returns all audit events for a workspace.
func (l *Logger) List(workspace string) ([]domain.AuditEvent, error) {
	return l.repo.ListAuditEvents(workspace)
}
