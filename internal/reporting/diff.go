package reporting

import (
	"encoding/json"
	"fmt"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// FindingDiffItem represents an individual finding comparison entry.
type FindingDiffItem struct {
	Status  string         `json:"status"` // ADDED, REMOVED, CHANGED, UNCHANGED
	Finding domain.Finding `json:"finding"`
	Changes []string       `json:"changes,omitempty"`
}

// AssessmentDiff represents the delta between two assessment snapshots.
type AssessmentDiff struct {
	BaseAssessmentID   string            `json:"base_assessment_id"`
	TargetAssessmentID string            `json:"target_assessment_id"`
	AddedFindings      []domain.Finding  `json:"added_findings"`
	RemovedFindings    []domain.Finding  `json:"removed_findings"`
	ChangedFindings    []domain.Finding  `json:"changed_findings"`
	UnchangedFindings  []domain.Finding  `json:"unchanged_findings"`
	PersistingFindings []domain.Finding  `json:"persisting_findings"`
	Items              []FindingDiffItem `json:"items,omitempty"`
	AddedCount         int               `json:"added_count"`
	RemovedCount       int               `json:"removed_count"`
	ChangedCount       int               `json:"changed_count"`
	UnchangedCount     int               `json:"unchanged_count"`
	PersistingCount    int               `json:"persisting_count"`
}

// CompareSnapshots calculates the differences between two assessment snapshots.
func CompareSnapshots(repo *storage.Repository, baseID, targetID string) (*AssessmentDiff, error) {
	baseSnap, err := repo.GetAssessmentSnapshotByAssessmentID(baseID)
	if err != nil {
		return nil, fmt.Errorf("loading base snapshot %s: %w", baseID, err)
	}
	if baseSnap == nil {
		return nil, fmt.Errorf("base snapshot %s not found", baseID)
	}

	targetSnap, err := repo.GetAssessmentSnapshotByAssessmentID(targetID)
	if err != nil {
		return nil, fmt.Errorf("loading target snapshot %s: %w", targetID, err)
	}
	if targetSnap == nil {
		return nil, fmt.Errorf("target snapshot %s not found", targetID)
	}

	baseFindings := extractSnapshotFindings(baseSnap.SnapshotData)
	targetFindings := extractSnapshotFindings(targetSnap.SnapshotData)

	baseMap := make(map[string]domain.Finding)
	for _, f := range baseFindings {
		key := fmt.Sprintf("%s:%s:%s", f.RuleID, f.EntityType, f.EntityID)
		baseMap[key] = f
	}

	targetMap := make(map[string]domain.Finding)
	for _, f := range targetFindings {
		key := fmt.Sprintf("%s:%s:%s", f.RuleID, f.EntityType, f.EntityID)
		targetMap[key] = f
	}

	diff := &AssessmentDiff{
		BaseAssessmentID:   baseID,
		TargetAssessmentID: targetID,
	}

	for key, tf := range targetMap {
		if bf, exists := baseMap[key]; exists {
			diff.PersistingFindings = append(diff.PersistingFindings, tf)
			var changes []string
			if bf.Confidence != tf.Confidence {
				changes = append(changes, fmt.Sprintf("confidence changed from %s to %s", bf.Confidence, tf.Confidence))
			}
			if bf.Status != tf.Status {
				changes = append(changes, fmt.Sprintf("status changed from %s to %s", bf.Status, tf.Status))
			}
			if bf.Title != tf.Title {
				changes = append(changes, fmt.Sprintf("title changed from %q to %q", bf.Title, tf.Title))
			}
			if bf.Description != tf.Description {
				changes = append(changes, "description updated")
			}

			if len(changes) > 0 {
				diff.ChangedFindings = append(diff.ChangedFindings, tf)
				diff.Items = append(diff.Items, FindingDiffItem{
					Status:  "CHANGED",
					Finding: tf,
					Changes: changes,
				})
			} else {
				diff.UnchangedFindings = append(diff.UnchangedFindings, tf)
				diff.Items = append(diff.Items, FindingDiffItem{
					Status:  "UNCHANGED",
					Finding: tf,
				})
			}
		} else {
			diff.AddedFindings = append(diff.AddedFindings, tf)
			diff.Items = append(diff.Items, FindingDiffItem{
				Status:  "ADDED",
				Finding: tf,
			})
		}
	}

	for _, bf := range baseMap {
		key := fmt.Sprintf("%s:%s:%s", bf.RuleID, bf.EntityType, bf.EntityID)
		if _, exists := targetMap[key]; !exists {
			diff.RemovedFindings = append(diff.RemovedFindings, bf)
			diff.Items = append(diff.Items, FindingDiffItem{
				Status:  "REMOVED",
				Finding: bf,
			})
		}
	}

	diff.AddedCount = len(diff.AddedFindings)
	diff.RemovedCount = len(diff.RemovedFindings)
	diff.ChangedCount = len(diff.ChangedFindings)
	diff.UnchangedCount = len(diff.UnchangedFindings)
	diff.PersistingCount = len(diff.PersistingFindings)

	return diff, nil
}

func extractSnapshotFindings(snapData string) []domain.Finding {
	var findings []domain.Finding
	var full struct {
		Findings []domain.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(snapData), &full); err == nil && len(full.Findings) > 0 {
		return full.Findings
	}
	_ = json.Unmarshal([]byte(snapData), &findings)
	return findings
}
