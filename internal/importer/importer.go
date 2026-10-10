// Package importer provides the unified ingestion orchestrator for all supported file formats.
package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/importer/arp"
	"github.com/falcon-toolkit/falcon/internal/importer/dnsdata"
	jsonparser "github.com/falcon-toolkit/falcon/internal/importer/json"
	"github.com/falcon-toolkit/falcon/internal/importer/nmapxml"
	"github.com/falcon-toolkit/falcon/internal/importer/pcapmeta"
	"github.com/falcon-toolkit/falcon/internal/importer/routing"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/storage"
)

// ImportOptions configures an import run.
type ImportOptions struct {
	Format   string
	DryRun   bool
	SourceID string
}

// ImportSummary summarizes the outcome of an import operation.
type ImportSummary struct {
	Format             string `json:"format"`
	File               string `json:"file"`
	DryRun             bool   `json:"dry_run"`
	AssetsCreated      int    `json:"assets_created"`
	InterfacesCreated  int    `json:"interfaces_created"`
	ServicesCreated    int    `json:"services_created"`
	NetworksCreated    int    `json:"networks_created"`
	EvidenceRecorded   int    `json:"evidence_recorded"`
	ObservationsStored int    `json:"observations_stored"`
	TotalHosts         int    `json:"total_hosts"`
	TotalNetworks      int    `json:"total_networks"`
}

// Importer coordinates format detection, parsing, and pipeline ingestion.
type Importer struct {
	repo     *storage.Repository
	pipeline *observation.Pipeline
}

// New creates a new Importer.
func New(repo *storage.Repository) *Importer {
	return &Importer{
		repo:     repo,
		pipeline: observation.NewPipeline(repo),
	}
}

// DetectFormat attempts to identify the file format based on extension and content.
func DetectFormat(filePath string) (string, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".xml":
		return "nmapxml", nil
	case ".json":
		// Distinguish between Falcon JSON and PCAP meta JSON
		content, err := os.ReadFile(filePath)
		if err == nil && strings.Contains(string(content), `"flows"`) {
			return "pcapmeta", nil
		}
		return "json", nil
	case ".txt", ".hosts", ".zone":
		return "dnsdata", nil
	case ".arp":
		return "arp", nil
	case ".routes", ".rt":
		return "routing", nil
	default:
		// Check content prefix
		content, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("reading file for format detection: %w", err)
		}
		str := string(content)
		if strings.Contains(str, "<nmaprun") {
			return "nmapxml", nil
		}
		if strings.HasPrefix(strings.TrimSpace(str), "{") {
			if strings.Contains(str, `"flows"`) {
				return "pcapmeta", nil
			}
			return "json", nil
		}
		return "dnsdata", nil
	}
}

// ImportFile executes the import workflow against a file path.
func (imp *Importer) ImportFile(workspace, filePath string, opts ImportOptions) (*ImportSummary, error) {
	format := opts.Format
	if format == "" {
		detected, err := DetectFormat(filePath)
		if err != nil {
			return nil, err
		}
		format = detected
	}

	sourceID := opts.SourceID
	if sourceID == "" {
		sourceID = fmt.Sprintf("import:%s", filepath.Base(filePath))
	}

	var hostObs []observation.HostObservation
	var netObs []observation.NetworkObservation

	switch format {
	case "json":
		doc, err := jsonparser.ParseFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing JSON: %w", err)
		}
		hostObs, netObs = doc.ConvertToObservations()

	case "nmapxml":
		run, err := nmapxml.ParseFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing Nmap XML: %w", err)
		}
		hostObs = run.ConvertToObservations(sourceID)

	case "dnsdata":
		records, err := dnsdata.ParseFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing DNS data: %w", err)
		}
		hostObs = dnsdata.ConvertToObservations(records, sourceID)

	case "arp":
		entries, err := arp.ParseFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing ARP data: %w", err)
		}
		hostObs = arp.ConvertToObservations(entries, sourceID)

	case "routing":
		entries, err := routing.ParseFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing routing table: %w", err)
		}
		netObs = routing.ConvertToObservations(entries, sourceID)

	case "pcapmeta":
		doc, err := pcapmeta.ParseFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing PCAP metadata: %w", err)
		}
		hostObs = doc.ConvertToObservations(sourceID)

	default:
		return nil, fmt.Errorf("unsupported import format %q", format)
	}

	summary := &ImportSummary{
		Format:        format,
		File:          filePath,
		DryRun:        opts.DryRun,
		TotalHosts:    len(hostObs),
		TotalNetworks: len(netObs),
	}

	if opts.DryRun {
		// Dry run mode - calculate estimated entities
		summary.AssetsCreated = len(hostObs)
		summary.InterfacesCreated = len(hostObs)
		summary.NetworksCreated = len(netObs)
		for _, h := range hostObs {
			summary.ServicesCreated += len(h.Services)
		}
		summary.EvidenceRecorded = summary.AssetsCreated + summary.ServicesCreated + summary.NetworksCreated
		return summary, nil
	}

	// Commit Mode: Ingest through pipeline
	for _, h := range hostObs {
		h.SourceID = sourceID
		res, err := imp.pipeline.IngestHost(workspace, &h)
		if err != nil {
			return nil, fmt.Errorf("ingesting host %s: %w", h.IPAddress, err)
		}
		summary.AssetsCreated += res.AssetsCreated
		summary.InterfacesCreated += res.InterfacesCreated
		summary.ServicesCreated += res.ServicesCreated
		summary.EvidenceRecorded += res.EvidenceRecorded
	}

	for _, n := range netObs {
		n.SourceID = sourceID
		res, err := imp.pipeline.IngestNetwork(workspace, &n)
		if err != nil {
			return nil, fmt.Errorf("ingesting network %s: %w", n.CIDR, err)
		}
		summary.NetworksCreated += res.NetworksCreated
		summary.EvidenceRecorded += res.EvidenceRecorded
	}

	// Record Audit Event
	_ = imp.repo.RecordAuditEvent(&domain.AuditEvent{
		ID:          domain.FormatAuditID(int(time.Now().UnixNano() % 10000)),
		WorkspaceID: workspace,
		Action:      domain.AuditImport,
		Detail:      fmt.Sprintf("Imported %s format=%s assets=%d services=%d networks=%d", filepath.Base(filePath), format, summary.AssetsCreated, summary.ServicesCreated, summary.NetworksCreated),
		CreatedAt:   time.Now().UTC(),
	})

	return summary, nil
}
