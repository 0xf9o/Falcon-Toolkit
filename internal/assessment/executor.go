package assessment

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/collector"
	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/scope"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// ProgressEvent notifies the caller of collector execution state transitions.
type ProgressEvent struct {
	Collector string
	Status    string // "running", "done", "failed", "skipped"
	Err       error
}

// ProgressFunc is a callback invoked during execution.
type ProgressFunc func(evt ProgressEvent)

// Executor orchestrates active and passive collectors, ScopeGuard validation,
// observation ingestion, and assessment findings generation.
type Executor struct {
	repo     *storage.Repository
	pipeline *observation.Pipeline
	engine   *Engine
	registry *collector.Registry
	guard    *scope.ScopeGuard
}

// NewExecutor creates a new assessment executor.
func NewExecutor(
	repo *storage.Repository,
	pipeline *observation.Pipeline,
	engine *Engine,
	registry *collector.Registry,
	guard *scope.ScopeGuard,
) *Executor {
	if registry == nil {
		registry = collector.NewDefaultRegistry()
	}
	if engine == nil {
		engine = NewEngine(repo, nil)
	}
	if pipeline == nil {
		pipeline = observation.NewPipeline(repo)
	}
	return &Executor{
		repo:     repo,
		pipeline: pipeline,
		engine:   engine,
		registry: registry,
		guard:    guard,
	}
}

// Execute performs an active assessment run against the given target.
func (e *Executor) Execute(
	ctx context.Context,
	workspace string,
	target *domain.Target,
	opts collector.CollectorOptions,
	onProgress ProgressFunc,
) (*domain.AssessmentRun, *AssessmentResult, error) {
	if target == nil {
		return nil, nil, fmt.Errorf("no target specified for assessment")
	}

	// 1. Scope Boundary Enforcement
	if e.guard != nil {
		allowed, reason := e.guard.IsAllowed(target)
		if !allowed {
			return nil, nil, fmt.Errorf("scope boundary violation: %s (%s)", target.NormalizedValue, reason)
		}
	}

	// 2. Generate Assessment Plan
	plan, err := GenerateAssessmentPlan(target, e.guard, "standard")
	if err != nil {
		return nil, nil, fmt.Errorf("generating assessment plan: %w", err)
	}

	// 3. Initialize AssessmentRun Lifecycle
	runSeq, err := e.repo.NextSequence(workspace, "assessment_run")
	if err != nil {
		return nil, nil, fmt.Errorf("generating run sequence: %w", err)
	}
	runID := domain.FormatRunID(runSeq)
	now := time.Now().UTC()

	run := &domain.AssessmentRun{
		ID:             runID,
		WorkspaceID:    workspace,
		TargetID:       target.ID,
		TargetValue:    target.NormalizedValue,
		Plan:           plan,
		Status:         domain.RunRunning,
		StartedAt:      now,
		CollectorStats: make(map[string]int),
		Errors:         nil,
		CreatedAt:      now,
	}

	if err := e.repo.SaveAssessmentRun(run); err != nil {
		return nil, nil, fmt.Errorf("persisting initial assessment run: %w", err)
	}

	if onProgress != nil {
		onProgress(ProgressEvent{
			Collector: runID,
			Status:    "start",
		})
	}

	// Determine applicable collectors
	collectors := e.registry.Applicable(*target)

	// Global assessment timeout (default 2 minutes if none specified)
	globalTimeout := 2 * time.Minute
	if opts.Timeout > 0 {
		globalTimeout = opts.Timeout * time.Duration(len(collectors)+2)
		if globalTimeout < 30*time.Second {
			globalTimeout = 30 * time.Second
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, globalTimeout)
	defer cancel()

	// 4. Sequential Collector Execution with Panic Isolation & Progress Updates
	for _, coll := range collectors {
		select {
		case <-runCtx.Done():
			run.Status = domain.RunCancelled
			run.CompletedAt = time.Now().UTC()
			run.Errors = append(run.Errors, fmt.Sprintf("execution interrupted: %v", runCtx.Err()))
			_ = e.repo.SaveAssessmentRun(run)
			return run, nil, runCtx.Err()
		default:
		}

		if onProgress != nil {
			onProgress(ProgressEvent{
				Collector: coll.Name(),
				Status:    "running",
			})
		}

		// Execute with panic recovery
		var observations []collector.ResultObservation
		var collErr error

		func() {
			defer func() {
				if r := recover(); r != nil {
					collErr = fmt.Errorf("panic in collector %s: %v", coll.Name(), r)
				}
			}()

			collTimeout := opts.Timeout
			if collTimeout <= 0 {
				collTimeout = 3 * time.Second
			}
			stepCtx, stepCancel := context.WithTimeout(runCtx, collTimeout*3)
			defer stepCancel()

			observations, collErr = coll.Run(stepCtx, *target, opts)
		}()

		if collErr != nil {
			run.Errors = append(run.Errors, fmt.Sprintf("%s: %v", coll.Name(), collErr))
			if onProgress != nil {
				onProgress(ProgressEvent{
					Collector: coll.Name(),
					Status:    "failed",
					Err:       collErr,
				})
			}
			continue
		}

		// Ingest collector results into the canonical pipeline
		ingestCount := 0
		for _, obs := range observations {
			if obs.Host != nil {
				_, err := e.pipeline.IngestHost(workspace, obs.Host)
				if err == nil {
					ingestCount++
				}
			}
			if obs.Network != nil {
				_, err := e.pipeline.IngestNetwork(workspace, obs.Network)
				if err == nil {
					ingestCount++
				}
			}

			// Store relationships emitted by collectors
			for _, rel := range obs.Relationships {
				rSeq, _ := e.repo.NextSequence(workspace, "relationship")
				rel.ID = domain.FormatRelationshipID(rSeq)
				_ = e.repo.SaveRelationship(&rel)
			}

			// Store raw observation for provenance
			if obs.RawData != "" {
				obsSeq, _ := e.repo.NextSequence(workspace, "observation")
				_ = e.repo.SaveObservation(&domain.Observation{
					ID:          domain.FormatObservationID(obsSeq),
					SourceID:    obs.SourceID,
					Kind:        domain.ObservationKind(obs.Kind),
					RawData:     obs.RawData,
					ObservedAt:  obs.Timestamp,
					WorkspaceID: workspace,
					CreatedAt:   time.Now().UTC(),
				})
			}
		}

		run.CollectorStats[coll.Name()] = len(observations)

		if onProgress != nil {
			onProgress(ProgressEvent{
				Collector: coll.Name(),
				Status:    "done",
			})
		}
	}

	// 5. Correlate and Evaluate Findings
	evalResult, evalErr := e.engine.Run(workspace)
	if evalErr != nil {
		run.Errors = append(run.Errors, fmt.Sprintf("rules evaluation: %v", evalErr))
	}

	// 6. Complete Run Lifecycle
	run.Status = domain.RunCompleted
	run.CompletedAt = time.Now().UTC()
	if err := e.repo.SaveAssessmentRun(run); err != nil {
		return run, evalResult, fmt.Errorf("finalizing assessment run: %w", err)
	}

	return run, evalResult, nil
}

// FormatProgressLine formats a progress indicator matching the required terminal format:
// DNS ........ done
func FormatProgressLine(collectorName string, status string) string {
	nameUpper := strings.ToUpper(collectorName)
	if collectorName == "host-discovery" {
		nameUpper = "HOST"
	}
	dots := 12 - len(nameUpper) - 1
	if dots < 2 {
		dots = 2
	}
	dotStr := strings.Repeat(".", dots)
	return fmt.Sprintf("%s %s %s", nameUpper, dotStr, status)
}
