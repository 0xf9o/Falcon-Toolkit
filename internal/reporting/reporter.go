package reporting

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// ReportFormat specifies the serialization format.
type ReportFormat string

const (
	FormatTable    ReportFormat = "table"
	FormatJSON     ReportFormat = "json"
	FormatNDJSON   ReportFormat = "ndjson"
	FormatMarkdown ReportFormat = "markdown"
)

// SummaryReport contains high-level metrics for the workspace.
type SummaryReport struct {
	FalconVersion string           `json:"falcon_version"`
	Workspace     string           `json:"workspace"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Fingerprint   string           `json:"dataset_fingerprint"`
	TotalAssets   int              `json:"total_assets"`
	TotalServices int              `json:"total_services"`
	TotalNetworks int              `json:"total_networks"`
	TotalEvidence int              `json:"total_evidence"`
	TotalFindings int              `json:"total_findings"`
	CategoryStats map[string]int   `json:"findings_by_category"`
	Assets        []domain.Asset   `json:"assets,omitempty"`
	Services      []domain.Service `json:"services,omitempty"`
	Networks      []domain.Network `json:"networks,omitempty"`
	Findings      []domain.Finding `json:"findings,omitempty"`
}

// Reporter coordinates report generation in multiple formats.
type Reporter struct {
	repo *storage.Repository
}

// NewReporter creates a new Reporter.
func NewReporter(repo *storage.Repository) *Reporter {
	return &Reporter{repo: repo}
}

// GenerateSummary builds the SummaryReport data structure for a workspace.
func (r *Reporter) GenerateSummary(workspace string, includeEntities bool) (*SummaryReport, error) {
	fp, err := CalculateDatasetFingerprint(r.repo, workspace)
	if err != nil {
		return nil, fmt.Errorf("calculating fingerprint: %w", err)
	}

	assets, err := r.repo.ListAssets(workspace)
	if err != nil {
		return nil, err
	}
	services, err := r.repo.ListServices(workspace)
	if err != nil {
		return nil, err
	}
	networks, err := r.repo.ListNetworks(workspace)
	if err != nil {
		return nil, err
	}
	evidence, err := r.repo.ListEvidence(workspace)
	if err != nil {
		return nil, err
	}
	findings, err := r.repo.ListFindings(workspace)
	if err != nil {
		return nil, err
	}

	categoryStats := make(map[string]int)
	for _, f := range findings {
		categoryStats[string(f.Category)]++
	}

	report := &SummaryReport{
		FalconVersion: "3.1.0",
		Workspace:     workspace,
		GeneratedAt:   time.Now().UTC(),
		Fingerprint:   fp,
		TotalAssets:   len(assets),
		TotalServices: len(services),
		TotalNetworks: len(networks),
		TotalEvidence: len(evidence),
		TotalFindings: len(findings),
		CategoryStats: categoryStats,
	}

	if includeEntities {
		report.Assets = assets
		report.Services = services
		report.Networks = networks
		report.Findings = findings
	}

	return report, nil
}

// Render formats a SummaryReport according to the specified format.
func (r *Reporter) Render(report *SummaryReport, format ReportFormat) (string, error) {
	switch format {
	case FormatJSON:
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case FormatNDJSON:
		var sb strings.Builder
		headerLine, _ := json.Marshal(map[string]interface{}{
			"type":        "summary",
			"workspace":   report.Workspace,
			"fingerprint": report.Fingerprint,
			"assets":      report.TotalAssets,
			"findings":    report.TotalFindings,
		})
		sb.Write(headerLine)
		sb.WriteString("\n")

		for _, f := range report.Findings {
			fLine, _ := json.Marshal(map[string]interface{}{
				"type":     "finding",
				"id":       f.ID,
				"rule":     f.RuleID,
				"category": f.Category,
				"title":    f.Title,
				"entity":   f.EntityID,
			})
			sb.Write(fLine)
			sb.WriteString("\n")
		}
		return sb.String(), nil

	case FormatMarkdown:
		return r.renderMarkdown(report), nil

	case FormatTable:
		fallthrough
	default:
		return r.renderTable(report), nil
	}
}

func (r *Reporter) renderMarkdown(report *SummaryReport) string {
	var sb strings.Builder
	sb.WriteString("# Falcon ToolKit Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Workspace**: `%s`\n", report.Workspace))
	sb.WriteString(fmt.Sprintf("- **Generated At**: `%s`\n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Dataset Fingerprint**: `%s`\n\n", report.Fingerprint))

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|---|---:|\n")
	sb.WriteString(fmt.Sprintf("| Total Assets | %d |\n", report.TotalAssets))
	sb.WriteString(fmt.Sprintf("| Total Services | %d |\n", report.TotalServices))
	sb.WriteString(fmt.Sprintf("| Total Networks | %d |\n", report.TotalNetworks))
	sb.WriteString(fmt.Sprintf("| Total Evidence | %d |\n", report.TotalEvidence))
	sb.WriteString(fmt.Sprintf("| Total Findings | %d |\n\n", report.TotalFindings))

	if len(report.CategoryStats) > 0 {
		sb.WriteString("### Findings by Category\n\n")
		sb.WriteString("| Category | Findings |\n")
		sb.WriteString("|---|---:|\n")
		var cats []string
		for cat := range report.CategoryStats {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, report.CategoryStats[cat]))
		}
		sb.WriteString("\n")
	}

	if len(report.Findings) > 0 {
		sb.WriteString("## Findings Detail\n\n")
		sb.WriteString("| ID | Category | Rule | Entity | Title |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, f := range report.Findings {
			sb.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | `%s` | %s |\n", f.ID, f.Category, f.RuleID, f.EntityID, f.Title))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func (r *Reporter) renderTable(report *SummaryReport) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Falcon ToolKit Assessment Summary (Workspace: %s)\n", report.Workspace))
	sb.WriteString(strings.Repeat("-", 60))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Dataset Fingerprint : %s\n", report.Fingerprint))
	sb.WriteString(fmt.Sprintf("Generated At        : %s\n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Assets / Services   : %d / %d\n", report.TotalAssets, report.TotalServices))
	sb.WriteString(fmt.Sprintf("Networks / Evidence : %d / %d\n", report.TotalNetworks, report.TotalEvidence))
	sb.WriteString(fmt.Sprintf("Total Findings      : %d\n", report.TotalFindings))
	sb.WriteString(strings.Repeat("-", 60))
	sb.WriteString("\n")

	if len(report.CategoryStats) > 0 {
		sb.WriteString("Findings by Category:\n")
		var cats []string
		for cat := range report.CategoryStats {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			sb.WriteString(fmt.Sprintf("  • %-15s : %d\n", cat, report.CategoryStats[cat]))
		}
	}

	return sb.String()
}
