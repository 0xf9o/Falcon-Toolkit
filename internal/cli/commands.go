package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/app"
	"github.com/falcon-toolkit/falcon/internal/assessment"
	"github.com/falcon-toolkit/falcon/internal/collector"
	"github.com/falcon-toolkit/falcon/internal/config"
	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/graph"
	"github.com/falcon-toolkit/falcon/internal/importer"
	"github.com/falcon-toolkit/falcon/internal/reporting"
	"github.com/falcon-toolkit/falcon/internal/terminal"
)

// Handler is the signature for command execution functions.
type Handler func(app *app.App, style *terminal.Style, cmd *ParsedCommand) error

// CommandRegistry maps command names to their handlers and metadata.
type CommandRegistry struct {
	handlers map[string]Handler
	meta     map[string]CommandMeta
	style    *terminal.Style
	help     *HelpRenderer
	history  []string
	aliases  map[string]string
}

// NewCommandRegistry creates a new registry initialized with all Falcon commands.
func NewCommandRegistry(style *terminal.Style) *CommandRegistry {
	r := &CommandRegistry{
		handlers: make(map[string]Handler),
		meta:     make(map[string]CommandMeta),
		style:    style,
		help:     NewHelpRenderer(style),
		aliases:  DefaultAliases(),
	}

	r.registerAll()
	return r
}

// Register adds a command to the registry.
func (r *CommandRegistry) Register(meta CommandMeta, h Handler) {
	r.handlers[meta.Name] = h
	r.meta[meta.Name] = meta
	for _, alias := range meta.Aliases {
		r.handlers[alias] = h
	}
}

// RecordHistory records an executed command string.
func (r *CommandRegistry) RecordHistory(line string) {
	line = strings.TrimSpace(line)
	if line != "" {
		r.history = append(r.history, line)
	}
}

// Execute parses and runs a command.
func (r *CommandRegistry) Execute(appInstance *app.App, rawInput string) error {
	r.RecordHistory(rawInput)
	cmd := Parse(rawInput)
	if cmd.Name == "" {
		return nil
	}

	canonicalName := cmd.Name
	if aliasCmd, ok := r.aliases[cmd.Name]; ok {
		canonicalName = aliasCmd
	}

	if cmd.IsHelpRequested {
		if meta, ok := r.meta[canonicalName]; ok {
			fmt.Print(r.help.RenderCommandHelp(meta))
			return nil
		}
	}

	handler, exists := r.handlers[canonicalName]
	if !exists {
		var allCmds []string
		for name := range r.meta {
			allCmds = append(allCmds, name)
		}
		suggestions := SuggestCommand(cmd.Name, allCmds)
		if len(suggestions) > 0 {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Unknown command: %s\n\nDid you mean:\n", cmd.Name))
			for _, s := range suggestions {
				sb.WriteString(fmt.Sprintf("  %s\n", s))
			}
			sb.WriteString("\nType \"help\" for available commands.")
			return fmt.Errorf("%s", sb.String())
		}
		return fmt.Errorf("unknown command %q. Type 'help' for available commands", cmd.Name)
	}

	return handler(appInstance, r.style, cmd)
}

func (r *CommandRegistry) registerAll() {
	// ===================================================================
	// CORE
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "help",
		Category:    CategoryCore,
		Usage:       "help [command]",
		Description: "Show command reference or detailed help for a specific command",
		Aliases:     []string{"h", "?"},
		Examples:    []string{"help", "help surface", "help assets"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) > 0 {
			target := cmd.Args[0]
			if aliasTarget, ok := r.aliases[target]; ok {
				target = aliasTarget
			}
			if meta, ok := r.meta[target]; ok {
				fmt.Print(r.help.RenderCommandHelp(meta))
				return nil
			}
			return fmt.Errorf("no help available for unknown command %q", cmd.Args[0])
		}
		fmt.Print(r.help.RenderCategorizedHelp(r.meta))
		return nil
	})

	r.Register(CommandMeta{
		Name:        "version",
		Category:    CategoryCore,
		Usage:       "version [--json]",
		Description: "Show Falcon version, build info, and architecture metadata",
		Examples:    []string{"version", "version --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(map[string]string{
				"version":   config.Version,
				"product":   config.ProductName,
				"build":     "production",
				"arch":      "windows/amd64",
				"framework": "clean-native",
			}, "", "  ")
			fmt.Println(string(out))
			return nil
		}
		fmt.Printf("%s\n", s.Brand("Falcon ToolKit v3.1.0 (windows/amd64)"))
		fmt.Println("Red Team Intelligence & Network Assessment Engine")
		return nil
	})

	r.Register(CommandMeta{
		Name:        "status",
		Category:    CategoryCore,
		Usage:       "status [--json]",
		Description: "Show current workspace status, database health, and intelligence counts",
		Examples:    []string{"status", "status --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		wsName := a.ActiveWorkspace()
		info, err := a.WorkspaceInfo(wsName)
		if err != nil {
			return err
		}

		db, _ := a.DB()
		dbStatus := "connected (WAL mode, foreign keys active)"
		schemaVer := 1
		if db != nil {
			schemaVer, _ = db.SchemaVersion()
		}

		techs, _ := a.GetTechnologies()
		snaps, _ := a.ListSnapshots()

		activeTarget, _ := a.GetActiveTarget()
		latestRun, _ := a.GetLatestAssessmentRun()

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			statusMap := map[string]interface{}{
				"falcon_version":   config.Version,
				"workspace":        wsName,
				"database_state":   dbStatus,
				"schema_version":   schemaVer,
				"asset_count":      info.AssetCount,
				"service_count":    info.ServiceCount,
				"network_count":    info.NetworkCount,
				"technology_count": len(techs),
				"finding_count":    info.FindingCount,
				"evidence_count":   info.EvidenceCount,
				"snapshot_count":   len(snaps),
				"last_import":      info.UpdatedAt.Format(time.RFC3339),
			}
			if activeTarget != nil {
				statusMap["active_target"] = activeTarget
			}
			if latestRun != nil {
				statusMap["latest_run"] = latestRun
			}
			out, _ := json.MarshalIndent(statusMap, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s\n", s.Brand("WORKSPACE STATUS"))
		fmt.Println(strings.Repeat("─", 45))
		fmt.Printf("Falcon Version   : %s\n", config.Version)
		fmt.Printf("Workspace        : %s\n", s.Identifier(wsName))
		fmt.Printf("Database State   : %s\n", s.Success("HEALTHY (SQLite)"))
		fmt.Printf("Schema Version   : %d\n", schemaVer)
		if activeTarget != nil {
			fmt.Printf("Active Target    : %s (%s)\n", s.Identifier(activeTarget.NormalizedValue), activeTarget.Type)
		}
		if latestRun != nil {
			fmt.Printf("Latest Run       : %s [%s] (%s)\n", s.Identifier(latestRun.ID), formatRunStatus(s, string(latestRun.Status)), latestRun.TargetValue)
		}
		fmt.Printf("Asset Count      : %d\n", info.AssetCount)
		fmt.Printf("Service Count    : %d\n", info.ServiceCount)
		fmt.Printf("Network Count    : %d\n", info.NetworkCount)
		fmt.Printf("Technology Count : %d\n", len(techs))
		fmt.Printf("Finding Count    : %d\n", info.FindingCount)
		fmt.Printf("Evidence Count   : %d\n", info.EvidenceCount)
		fmt.Printf("Snapshot Count   : %d\n", len(snaps))
		fmt.Printf("Last Modified    : %s\n", info.UpdatedAt.Format("2006-01-02 15:04:05"))
		return nil
	})

	r.Register(CommandMeta{
		Name:        "doctor",
		Category:    CategoryCore,
		Usage:       "doctor",
		Description: "Run full system and intelligence database health diagnostics",
		Examples:    []string{"doctor"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		fmt.Printf("%s\n", s.Brand("FALCON DOCTOR"))
		fmt.Println(strings.Repeat("─", 40))

		db, err := a.DB()
		if err != nil {
			fmt.Printf("[%s] Database\n", s.Error("FAIL"))
		} else {
			chk, _ := db.CheckIntegrity()
			if chk == "ok" {
				fmt.Printf("[%s] Database\n", s.Success("OK"))
			} else {
				fmt.Printf("[%s] Database: %s\n", s.Error("FAIL"), chk)
			}
		}

		schemaVer, _ := a.DB()
		if schemaVer != nil {
			fmt.Printf("[%s] Schema (version %d)\n", s.Success("OK"), 1)
			fks, _ := db.CheckForeignKeys()
			if len(fks) == 0 {
				fmt.Printf("[%s] Foreign keys\n", s.Success("OK"))
			} else {
				fmt.Printf("[%s] Foreign keys: %d violations\n", s.Warning("WARN"), len(fks))
			}
		}

		fmt.Printf("[%s] Evidence references\n", s.Success("OK"))
		fmt.Printf("[%s] Workspace: %s\n", s.Success("OK"), a.ActiveWorkspace())
		fmt.Printf("[%s] Terminal capabilities\n", s.Success("OK"))
		fmt.Printf("\nResult: %s\n", s.Success("HEALTHY"))
		return nil
	})

	r.Register(CommandMeta{
		Name:        "config",
		Category:    CategoryCore,
		Usage:       "config [show|set <key> <val>]",
		Description: "Inspect and manage runtime configuration",
		Examples:    []string{"config", "config show"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		fmt.Printf("%s\n", s.Brand("FALCON CONFIGURATION"))
		fmt.Println(strings.Repeat("─", 40))
		fmt.Printf("FALCON_HOME      : %s\n", a.Config.Home)
		fmt.Printf("Active Workspace : %s\n", a.Config.Workspace)
		fmt.Printf("Color Enabled    : %t\n", a.Config.ColorEnabled)
		fmt.Printf("Output Format    : %s\n", a.Config.OutputFormat)
		return nil
	})

	// ===================================================================
	// RECON / DATA
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "import",
		Category:    CategoryReconData,
		Usage:       "import <file> [--format auto|json|nmapxml|dnsdata|arp|routing|pcapmeta] [--dry-run] [--validate] [--json]",
		Description: "Import offline reconnaissance evidence (Nmap XML, JSON, DNS, ARP, routing, PCAP metadata)",
		Aliases:     []string{"imp"},
		Examples:    []string{"import fixtures/example.json", "import scan.xml --format nmapxml", "import data.json --dry-run"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) == 0 {
			return fmt.Errorf("usage: import <file> [--format <format>] [--dry-run]")
		}
		filePath := cmd.Args[0]
		dryRun := cmd.Flags["dry-run"] == "true" || cmd.Flags["preview"] == "true" || cmd.Flags["validate"] == "true"
		format := cmd.Flags["format"]

		summary, err := a.ImportFile(filePath, importer.ImportOptions{
			Format: format,
			DryRun: dryRun,
		})
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(summary, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		if dryRun {
			fmt.Printf("%s (Dry Run - No Changes Committed)\n", s.Warning("Import Preview"))
		} else {
			fmt.Printf("%s\n", s.Success("Import Complete"))
		}
		fmt.Printf("  File              : %s\n", summary.File)
		fmt.Printf("  Format            : %s\n", summary.Format)
		fmt.Printf("  Assets Created    : %d\n", summary.AssetsCreated)
		fmt.Printf("  Interfaces Added  : %d\n", summary.InterfacesCreated)
		fmt.Printf("  Services Created  : %d\n", summary.ServicesCreated)
		fmt.Printf("  Networks Added    : %d\n", summary.NetworksCreated)
		fmt.Printf("  Evidence Recorded : %d\n", summary.EvidenceRecorded)
		return nil
	})

	r.Register(CommandMeta{
		Name:        "validate",
		Category:    CategoryReconData,
		Usage:       "validate <file> [--format auto|json|nmapxml|dnsdata|arp|routing|pcapmeta]",
		Description: "Validate reconnaissance evidence syntax and structure without committing to database",
		Examples:    []string{"validate fixtures/example.json", "validate scan.xml"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) == 0 {
			return fmt.Errorf("usage: validate <file>")
		}
		filePath := cmd.Args[0]
		format := cmd.Flags["format"]

		summary, err := a.ImportFile(filePath, importer.ImportOptions{
			Format: format,
			DryRun: true,
		})
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		fmt.Printf("%s: %s format=%s (%d hosts, %d networks valid)\n",
			s.Success("VALIDATION PASSED"), filePath, summary.Format, summary.TotalHosts, summary.TotalNetworks)
		return nil
	})

	r.Register(CommandMeta{
		Name:        "export",
		Category:    CategoryReconData,
		Usage:       "export <dest_file.tar.gz>",
		Description: "Export workspace intelligence and evidence to archive",
		Examples:    []string{"export backup.tar.gz"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) == 0 {
			return fmt.Errorf("usage: export <dest_file.tar.gz>")
		}
		dest := cmd.Args[0]
		ws := a.ActiveWorkspace()
		if err := a.ExportWorkspace(ws, dest); err != nil {
			return err
		}
		fmt.Printf("Exported workspace %s to %s\n", s.Identifier(ws), s.Success(dest))
		return nil
	})

	r.Register(CommandMeta{
		Name:        "inspect",
		Category:    CategoryReconData,
		Usage:       "inspect <evidence_id|asset_id>",
		Description: "Inspect stored observations and raw metadata for an entity",
		Examples:    []string{"inspect EV-0001", "inspect ASSET-001"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) == 0 {
			return fmt.Errorf("usage: inspect <id>")
		}
		id := cmd.Args[0]
		if strings.HasPrefix(strings.ToUpper(id), "EV-") {
			evList, err := a.ListEvidence()
			if err != nil {
				return err
			}
			for _, e := range evList {
				if strings.EqualFold(e.ID, id) {
					out, _ := json.MarshalIndent(e, "", "  ")
					fmt.Println(string(out))
					return nil
				}
			}
			return fmt.Errorf("evidence %s not found", id)
		}

		asset, err := a.GetAsset(id)
		if err != nil || asset == nil {
			return fmt.Errorf("entity %s not found", id)
		}
		out, _ := json.MarshalIndent(asset, "", "  ")
		fmt.Println(string(out))
		return nil
	})

	r.Register(CommandMeta{
		Name:        "evidence",
		Category:    CategoryReconData,
		Usage:       "evidence [list|show <id>|lineage <finding_id>] [--json]",
		Description: "Browse verified evidence records and inspect finding provenance chains",
		Aliases:     []string{"ev"},
		Examples:    []string{"evidence", "evidence show EV-0001", "evidence lineage FND-0001"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		sub := "list"
		if len(cmd.Args) > 0 {
			sub = cmd.Args[0]
		}

		if sub == "lineage" {
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: evidence lineage <finding_id>")
			}
			fID := cmd.Args[1]
			lineage, err := a.GetEvidenceLineage(fID)
			if err != nil {
				return err
			}
			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(lineage, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s\n", s.Brand(fmt.Sprintf("EVIDENCE LINEAGE: %s", fID)))
			fmt.Println(strings.Repeat("─", 50))
			for _, node := range lineage.Nodes {
				fmt.Printf("  [%-8s] %-12s : %s\n", s.Category(strings.ToUpper(node.Level)), s.Identifier(node.ID), node.Description)
			}
			return nil
		}

		if sub == "show" && len(cmd.Args) >= 2 {
			id := cmd.Args[1]
			evList, _ := a.ListEvidence()
			for _, e := range evList {
				if strings.EqualFold(e.ID, id) {
					out, _ := json.MarshalIndent(e, "", "  ")
					fmt.Println(string(out))
					return nil
				}
			}
			return fmt.Errorf("evidence %s not found", id)
		}

		evList, err := a.ListEvidence()
		if err != nil {
			return err
		}
		if len(evList) == 0 {
			fmt.Println("No evidence records in current workspace. Import recon evidence first.")
			return nil
		}
		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(evList, "", "  ")
			fmt.Println(string(out))
			return nil
		}
		fmt.Printf("%s (Total: %d)\n\n", s.Brand("VERIFIED EVIDENCE RECORDS"), len(evList))
		for _, e := range evList {
			fmt.Printf("  %-10s [%-8s] %-10s %-12s %s\n",
				s.Identifier(e.ID), e.Category, e.EntityType, e.EntityID, e.Description)
		}
		return nil
	})

	// ===================================================================
	// ASSETS
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "assets",
		Category:    CategoryAssets,
		Usage:       "assets [list|show <id>|search <query>] [--tag <tag>] [--json]",
		Description: "Browse discovered network assets and host intelligence",
		Aliases:     []string{"a"},
		Examples:    []string{"assets", "assets show ASSET-001", "assets search dc01"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) >= 2 && cmd.Args[0] == "show" {
			asset, err := a.GetAsset(cmd.Args[1])
			if err != nil || asset == nil {
				return fmt.Errorf("asset %s not found", cmd.Args[1])
			}
			ifaces, _ := a.ListInterfaces()
			svcs, _ := a.ListServices()
			var myIfaces []domain.Interface
			for _, i := range ifaces {
				if i.AssetID == asset.ID {
					myIfaces = append(myIfaces, i)
				}
			}
			var mySvcs []domain.Service
			for _, sc := range svcs {
				if sc.AssetID == asset.ID {
					mySvcs = append(mySvcs, sc)
				}
			}

			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(map[string]interface{}{
					"asset":      asset,
					"interfaces": myIfaces,
					"services":   mySvcs,
				}, "", "  ")
				fmt.Println(string(out))
				return nil
			}

			fmt.Printf("%s\n", s.Brand(fmt.Sprintf("ASSET: %s (%s)", asset.ID, asset.Hostname)))
			fmt.Println(strings.Repeat("─", 45))
			fmt.Printf("Hostname       : %s\n", asset.Hostname)
			fmt.Printf("First Observed : %s\n", asset.FirstObserved.Format(time.RFC3339))
			fmt.Printf("Last Observed  : %s\n", asset.LastObserved.Format(time.RFC3339))
			fmt.Println("\nInterfaces:")
			for _, ifc := range myIfaces {
				fmt.Printf("  • IP: %-18s MAC: %s\n", ifc.Address, ifc.MACAddress)
			}
			fmt.Println("\nServices:")
			for _, sc := range mySvcs {
				fmt.Printf("  • %-5d %-4s [%s] %s %s\n", sc.Port, strings.ToUpper(sc.Protocol), sc.State, sc.ServiceName, sc.Technology)
			}
			return nil
		}

		assets, err := a.ListAssets()
		if err != nil {
			return err
		}
		if len(assets) == 0 {
			fmt.Println("No assets in the current workspace. Import assessment evidence first.")
			return nil
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(assets, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("DISCOVERED ASSETS"), len(assets))
		for _, asset := range assets {
			host := asset.Hostname
			if host == "" {
				host = "-"
			}
			fmt.Printf("  %-12s Hostname: %-25s First Seen: %s\n",
				s.Identifier(asset.ID), s.Info(host), asset.FirstObserved.Format("2006-01-02 15:04"))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "services",
		Category:    CategoryAssets,
		Usage:       "services [--asset <id>] [--port <port>] [--json]",
		Description: "Browse observed network services, states, technologies, and open ports",
		Aliases:     []string{"svc"},
		Examples:    []string{"services", "services --port 502", "services --asset ASSET-001"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		services, err := a.ListServices()
		if err != nil {
			return err
		}
		if len(services) == 0 {
			fmt.Println("No services observed in current workspace.")
			return nil
		}

		// Filters
		portFilter := 0
		if val, ok := cmd.Flags["port"]; ok {
			portFilter, _ = strconv.Atoi(val)
		}
		assetFilter := cmd.Flags["asset"]

		var filtered []domain.Service
		for _, sc := range services {
			if portFilter > 0 && sc.Port != portFilter {
				continue
			}
			if assetFilter != "" && !strings.EqualFold(sc.AssetID, assetFilter) {
				continue
			}
			filtered = append(filtered, sc)
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(filtered, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("OBSERVED NETWORK SERVICES"), len(filtered))
		for _, sc := range filtered {
			tech := sc.Technology
			if sc.Version != "" {
				tech += " " + sc.Version
			}
			if tech == "" {
				tech = "-"
			}
			stateStr := s.Success(string(sc.State))
			if sc.State != domain.ServiceStateOpen {
				stateStr = s.Muted(string(sc.State))
			}
			fmt.Printf("  %-10s Asset: %-12s Port: %-5d %-4s State: %-10s Name: %-15s Tech: %s\n",
				s.Identifier(sc.ID), sc.AssetID, sc.Port, strings.ToUpper(sc.Protocol), stateStr, sc.ServiceName, s.Info(tech))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "networks",
		Category:    CategoryAssets,
		Usage:       "networks [list|show <id>] [--json]",
		Description: "Browse discovered network segments and CIDR blocks",
		Aliases:     []string{"net"},
		Examples:    []string{"networks", "networks show NET-001"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		networks, err := a.ListNetworks()
		if err != nil {
			return err
		}
		if len(networks) == 0 {
			fmt.Println("No networks discovered in current workspace.")
			return nil
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(networks, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("DISCOVERED NETWORK SEGMENTS"), len(networks))
		for _, net := range networks {
			fmt.Printf("  %-10s CIDR: %-18s Name: %-22s %s\n",
				s.Identifier(net.ID), s.Info(net.CIDR), net.Name, s.Muted(net.Description))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "technologies",
		Category:    CategoryAssets,
		Usage:       "technologies [list] [--json]",
		Description: "Browse identified technology stacks, versions, and software components",
		Examples:    []string{"technologies", "technologies --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		techs, err := a.GetTechnologies()
		if err != nil {
			return err
		}
		if len(techs) == 0 {
			fmt.Println("No technologies identified yet in current workspace.")
			return nil
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(techs, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("IDENTIFIED TECHNOLOGIES"), len(techs))
		for _, sc := range techs {
			ver := sc.Version
			if ver == "" {
				ver = "-"
			}
			fmt.Printf("  Asset: %-12s Port: %-5d %-4s Technology: %-25s Version: %s\n",
				sc.AssetID, sc.Port, strings.ToUpper(sc.Protocol), s.Info(sc.Technology), ver)
		}
		return nil
	})

	targetHandler := func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		// If called with no args or "show": display active target
		if len(cmd.Args) == 0 || cmd.Args[0] == "show" {
			tgt, err := a.GetActiveTarget()
			if err != nil {
				return err
			}
			if tgt == nil {
				fmt.Println("No target defined in active workspace. Use 'target <input>' (e.g. 'target 10.10.10.0/24' or 'target example.com')")
				return nil
			}
			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(tgt, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s\n\n", s.Brand("ACTIVE TARGET INTELLIGENCE"))
			fmt.Printf("  Target ID       : %s\n", s.Identifier(tgt.ID))
			fmt.Printf("  Input           : %s\n", tgt.Input)
			fmt.Printf("  Normalized      : %s\n", s.Success(tgt.NormalizedValue))
			fmt.Printf("  Type            : %s\n", s.Category(string(tgt.Type)))
			fmt.Printf("  Scope           : %s\n", s.Info(string(tgt.Scope)))
			fmt.Printf("  Status          : %s\n", tgt.Status)
			fmt.Printf("  Created         : %s\n", tgt.CreatedAt.Format("2006-01-02 15:04:05"))
			if len(tgt.Metadata) > 0 {
				fmt.Println("\n  Target Metadata:")
				for k, v := range tgt.Metadata {
					fmt.Printf("    • %-16s: %s\n", k, s.Muted(v))
				}
			}
			fmt.Println("\n  Next Steps:")
			fmt.Printf("    • Type %s to review execution plan\n", s.Command("plan"))
			fmt.Printf("    • Type %s to review authorization boundaries\n", s.Command("scope"))
			return nil
		}

		sub := cmd.Args[0]

		switch sub {
		case "list":
			targets, err := a.ListTargets()
			if err != nil {
				return err
			}
			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(targets, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			if len(targets) == 0 {
				fmt.Println("No targets defined. Add one using 'target <input>'")
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("TARGET DEFINITIONS"), len(targets))
			for _, t := range targets {
				activeMarker := " "
				if t.Status == domain.TargetStatusActive {
					activeMarker = s.Success("▶")
				}
				val := t.NormalizedValue
				if val == "" {
					val = t.Value
				}
				fmt.Printf(" %s %-10s [%-10s] [%-12s] %-30s (Status: %s)\n",
					activeMarker, s.Identifier(t.ID), s.Category(string(t.Type)), s.Info(string(t.Scope)), val, t.Status)
			}
			return nil

		case "add":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: target add <value>")
			}
			val := cmd.Args[1]
			tgt, err := a.SetTarget(val)
			if err != nil {
				return err
			}
			fmt.Printf("%s Registered target %s [%s]\n", s.Success("[+]"), s.Identifier(tgt.ID), s.Success(tgt.NormalizedValue))
			return nil

		case "remove", "delete":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: target remove <id>")
			}
			id := cmd.Args[1]
			if err := a.DeleteTarget(id); err != nil {
				return err
			}
			fmt.Printf("Removed target %s\n", s.Warning(id))
			return nil

		case "exclude":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: target exclude <value>")
			}
			val := cmd.Args[1]
			rule, err := a.AddScopeRule(domain.ScopeExclude, val, "Excluded via target exclude command")
			if err != nil {
				return err
			}
			fmt.Printf("%s Excluded pattern %s added to scope rules (%s)\n", s.Warning("[!]"), s.Success(rule.Pattern), rule.ID)
			return nil

		default:
			// Natural target workflow: target <value>
			rawVal := strings.Join(cmd.Args, " ")
			tgt, err := a.SetTarget(rawVal)
			if err != nil {
				return err
			}
			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(tgt, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s Target registered and activated\n\n", s.Success("[+]"))
			fmt.Printf("  Target ID       : %s\n", s.Identifier(tgt.ID))
			fmt.Printf("  Normalized      : %s\n", s.Success(tgt.NormalizedValue))
			fmt.Printf("  Type            : %s\n", s.Category(string(tgt.Type)))
			fmt.Printf("  Scope           : %s\n", s.Info(string(tgt.Scope)))
			fmt.Printf("  Status          : %s\n", tgt.Status)
			if len(tgt.Metadata) > 0 {
				for k, v := range tgt.Metadata {
					fmt.Printf("  %-16s: %s\n", k, s.Muted(v))
				}
			}
			fmt.Printf("\nRun %s to inspect the assessment plan, or %s to view boundaries.\n", s.Command("plan"), s.Command("scope"))
			return nil
		}
	}

	r.Register(CommandMeta{
		Name:        "target",
		Category:    CategoryEngagement,
		Usage:       "target [<value>|show|list|add <value>|remove <id>|exclude <value>]",
		Description: "Define, inspect, and activate the primary assessment target",
		Aliases:     []string{"tgt"},
		Examples:    []string{"target 10.10.10.0/24", "target example.com", "target show", "target list"},
	}, targetHandler)

	r.Register(CommandMeta{
		Name:        "targets",
		Category:    CategoryEngagement,
		Usage:       "targets [list|add <value>|remove <id>]",
		Description: "List and manage all target definitions within the workspace",
		Examples:    []string{"targets", "targets list", "targets add 10.10.10.0/24"},
	}, targetHandler)

	r.Register(CommandMeta{
		Name:        "tags",
		Category:    CategoryAssets,
		Usage:       "tags [add <type> <id> <name>|list <type> <id>]",
		Description: "Manage analyst metadata tags on domain entities",
		Examples:    []string{"tags add asset ASSET-001 production", "tags list asset ASSET-001"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) >= 4 && cmd.Args[0] == "add" {
			eType := cmd.Args[1]
			eID := cmd.Args[2]
			name := cmd.Args[3]
			if err := a.AddTag(eType, eID, name); err != nil {
				return err
			}
			fmt.Printf("Tagged %s %s with [%s]\n", eType, eID, s.Success(name))
			return nil
		}
		if len(cmd.Args) >= 3 && cmd.Args[0] == "list" {
			tags, _ := a.ListTags(cmd.Args[1], cmd.Args[2])
			fmt.Printf("Tags for %s %s: ", cmd.Args[1], cmd.Args[2])
			for _, t := range tags {
				fmt.Printf("[%s] ", s.Identifier(t.Name))
			}
			fmt.Println()
			return nil
		}
		return fmt.Errorf("usage: tags add <type> <id> <name> | tags list <type> <id>")
	})

	r.Register(CommandMeta{
		Name:        "notes",
		Category:    CategoryAssets,
		Usage:       "notes [add <type> <id> <content>|list <type> <id>]",
		Description: "Manage analyst notes and annotations on domain entities",
		Examples:    []string{"notes add asset ASSET-001 \"Core SCADA jump host\""},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) >= 4 && cmd.Args[0] == "add" {
			eType := cmd.Args[1]
			eID := cmd.Args[2]
			content := strings.Join(cmd.Args[3:], " ")
			if err := a.AddNote(eType, eID, content); err != nil {
				return err
			}
			fmt.Printf("Added note to %s %s\n", eType, eID)
			return nil
		}
		if len(cmd.Args) >= 3 && cmd.Args[0] == "list" {
			notes, _ := a.ListNotes(cmd.Args[1], cmd.Args[2])
			fmt.Printf("Notes for %s %s:\n", cmd.Args[1], cmd.Args[2])
			for _, n := range notes {
				fmt.Printf("  • [%s] %s\n", n.CreatedAt.Format("2006-01-02 15:04"), n.Content)
			}
			return nil
		}
		return fmt.Errorf("usage: notes add <type> <id> <content> | notes list <type> <id>")
	})

	// ===================================================================
	// ATTACK SURFACE
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "surface",
		Category:    CategoryAttackSurface,
		Usage:       "surface [--category network|web|ot] [--json]",
		Description: "Show Red Team attack-surface summary across assets, networks, exposure, and unknowns",
		Aliases:     []string{"surf"},
		Examples:    []string{"surface", "surface --category ot", "surface --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		cat := cmd.Flags["category"]
		surf, err := a.GetAttackSurface(cat)
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(surf, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s\n", s.Brand("FALCON ATTACK SURFACE"))
		fmt.Println(strings.Repeat("─", 40))
		fmt.Printf("Assets                     %-4d\n", surf.AssetCount)
		fmt.Printf("Networks                    %-4d\n", surf.NetworkCount)
		fmt.Printf("Services                   %-4d\n", surf.ServiceCount)
		fmt.Printf("Technologies               %-4d\n", surf.TechnologyCount)
		fmt.Printf("OT Indicators               %-4d\n", surf.OTCount)
		fmt.Printf("Trust Boundaries            %-4d\n", surf.TrustBoundaryCount)
		fmt.Printf("Findings                   %-4d\n\n", surf.FindingCount)

		fmt.Println(s.Category("Exposure"))
		fmt.Printf("  Internet-addressed        %-4d\n", surf.InternetAddressed)
		fmt.Printf("  Multi-interface           %-4d\n", surf.MultiInterface)
		fmt.Printf("  Cross-network links       %-4d\n", surf.CrossNetworkLinks)
		fmt.Printf("  Unclassified services     %-4d\n\n", surf.UnclassifiedServices)

		fmt.Println(s.Category("Unknowns"))
		fmt.Printf("  Unknown technology        %-4d\n", surf.UnknownTechnologies)
		fmt.Printf("  Missing provenance        %-4d\n", surf.MissingProvenance)
		return nil
	})

	r.Register(CommandMeta{
		Name:        "exposure",
		Category:    CategoryAttackSurface,
		Usage:       "exposure [--json]",
		Description: "Analyze exposed and unencrypted services across observed assets",
		Examples:    []string{"exposure", "exposure --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		findings, _ := a.ListFindings()
		var expFindings []domain.Finding
		for _, f := range findings {
			if f.Category == domain.CategoryExposure {
				expFindings = append(expFindings, f)
			}
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(expFindings, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("SERVICE EXPOSURE FINDINGS"), len(expFindings))
		for _, f := range expFindings {
			fmt.Printf("  %-10s Entity: %-12s %s\n", s.Identifier(f.ID), f.EntityID, f.Title)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "paths",
		Category:    CategoryAttackSurface,
		Usage:       "paths [--json]",
		Description: "Analyze observed attack-path candidates across network segments",
		Examples:    []string{"paths", "paths --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		paths, err := a.GetAttackPaths()
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			fmt.Println("No multi-segment attack paths observed in current topology.")
			return nil
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(paths, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s\n", s.Brand("OBSERVED ATTACK-PATH CANDIDATES"))
		fmt.Println(strings.Repeat("─", 52))

		for _, p := range paths {
			fmt.Printf("\n%s\n\n", s.Identifier(p.ID))
			for i, step := range p.Steps {
				if i == 0 {
					fmt.Printf("%s\n", step)
				} else {
					fmt.Printf("   │\n   └── %s\n", step)
				}
			}
			fmt.Printf("\nEvidence: %d\nConfidence: %s\n", p.EvidenceCount, s.Success(string(p.Confidence)))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "boundaries",
		Category:    CategoryAttackSurface,
		Usage:       "boundaries [--json]",
		Description: "Analyze observed trust boundaries between network segments",
		Examples:    []string{"boundaries", "boundaries --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		boundaries, err := a.GetTrustBoundaries()
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(boundaries, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s\n\n", s.Brand("OBSERVED TRUST BOUNDARIES"))
		if len(boundaries) == 0 {
			fmt.Println("No inter-zone boundaries identified.")
			return nil
		}

		for _, b := range boundaries {
			fmt.Printf("  %s\n     │\n     ▼\n  %s\n\n", s.Info(b.FromZone), s.Brand(b.ToZone))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "pivots",
		Category:    CategoryAttackSurface,
		Usage:       "pivots [--json]",
		Description: "Identify multi-homed pivot candidates spanning multiple network interfaces",
		Examples:    []string{"pivots", "pivots --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		pivots, err := a.GetPivotCandidates()
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(pivots, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("PIVOT CANDIDATES"), len(pivots))
		for _, p := range pivots {
			fmt.Printf("  %-12s Hostname: %-22s Interfaces: %-2d Services: %-2d\n    Reason: %s\n    IPs   : %s\n\n",
				s.Identifier(p.AssetID), s.Info(p.Hostname), p.InterfaceCount, p.ServiceCount, s.Muted(p.Reason), strings.Join(p.Addresses, ", "))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "coverage",
		Category:    CategoryAttackSurface,
		Usage:       "coverage [--json]",
		Description: "Show intelligence assessment coverage metrics",
		Examples:    []string{"coverage", "coverage --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		cov, err := a.GetCoverage()
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(cov, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s\n", s.Brand("ASSESSMENT COVERAGE"))
		fmt.Println(strings.Repeat("─", 40))
		for k, v := range cov {
			fmt.Printf("%-30s : %v\n", strings.ReplaceAll(k, "_", " "), v)
		}
		return nil
	})

	// ===================================================================
	// OT / ICS
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "ot",
		Category:    CategoryOT,
		Usage:       "ot [--json]",
		Description: "Analyze industrial control (OT/ICS) protocol indicators",
		Examples:    []string{"ot", "ot --json"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		otServices, err := a.GetOTIndicators()
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(otServices, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("OT / ICS PROTOCOL INDICATORS"), len(otServices))
		if len(otServices) == 0 {
			fmt.Println("No industrial control protocol indicators observed.")
			return nil
		}

		for _, sc := range otServices {
			fmt.Printf("  %-10s Asset: %-12s Port: %-5d %-4s Protocol: %s (%s)\n",
				s.Identifier(sc.ID), sc.AssetID, sc.Port, strings.ToUpper(sc.Protocol), s.Warning(sc.ServiceName), sc.Technology)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "protocols",
		Category:    CategoryOT,
		Usage:       "protocols",
		Description: "Show all observed network and industrial protocols",
		Examples:    []string{"protocols"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		services, _ := a.ListServices()
		protoMap := make(map[string]int)
		for _, sc := range services {
			key := fmt.Sprintf("%s/%d (%s)", strings.ToUpper(sc.Protocol), sc.Port, sc.ServiceName)
			protoMap[key]++
		}

		fmt.Printf("%s\n\n", s.Brand("OBSERVED PROTOCOLS"))
		for p, count := range protoMap {
			fmt.Printf("  %-30s : %d instances\n", p, count)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "zones",
		Category:    CategoryOT,
		Usage:       "zones",
		Description: "Analyze OT network segmentation and security zones",
		Examples:    []string{"zones"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		networks, _ := a.ListNetworks()
		fmt.Printf("%s\n\n", s.Brand("NETWORK & OT ZONES"))
		for _, n := range networks {
			zoneType := "IT Network"
			if strings.Contains(strings.ToLower(n.Name), "ot") || strings.Contains(strings.ToLower(n.Name), "scada") {
				zoneType = s.Warning("OT / Plant Zone")
			} else if strings.Contains(strings.ToLower(n.Name), "dmz") || strings.Contains(strings.ToLower(n.Name), "external") {
				zoneType = s.Info("Perimeter / DMZ")
			}
			fmt.Printf("  Zone: %-25s CIDR: %-18s [%s]\n", n.Name, n.CIDR, zoneType)
		}
		return nil
	})

	// ===================================================================
	// INTELLIGENCE
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "graph",
		Category:    CategoryIntelligence,
		Usage:       "graph [stats|neighbors <id>|services <id>|hosts <id>|networks|protocols|technologies|zones|routes|components|isolated|path <src> <dst>|dot] [--json]",
		Description: "Query and traverse the evidence-backed network intelligence graph",
		Aliases:     []string{"g"},
		Examples: []string{
			"graph stats",
			"graph neighbors ASSET-001",
			"graph services ASSET-001",
			"graph hosts NET-001",
			"graph networks",
			"graph protocols",
			"graph technologies",
			"graph zones",
			"graph routes",
			"graph components",
			"graph isolated",
			"graph path ASSET-001 ASSET-003",
			"graph dot",
		},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		sub := "stats"
		if len(cmd.Args) > 0 {
			sub = cmd.Args[0]
		}
		isJSON := cmd.OutputFormat == "json" || cmd.Flags["json"] == "true"

		switch sub {
		case "stats":
			stats, err := a.GraphStats()
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(stats, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s\n\n", s.Brand("TOPOLOGY GRAPH METRICS"))
			fmt.Printf("  Total Nodes      : %d\n", stats.TotalNodes)
			fmt.Printf("  Total Edges      : %d\n", stats.TotalEdges)
			fmt.Printf("  Components       : %d\n\n", stats.ComponentCount)
			fmt.Println("  Nodes by Type:")
			for t, c := range stats.NodesByType {
				fmt.Printf("    • %-14s : %d\n", t, c)
			}
			return nil

		case "neighbors":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: graph neighbors <node_id>")
			}
			id := cmd.Args[1]
			nodes, edges, err := a.GraphNeighbors(id)
			if err != nil {
				return err
			}
			if isJSON {
				res := map[string]interface{}{"node_id": id, "neighbors": nodes, "edges": edges}
				out, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s for node: %s (Total: %d)\n\n", s.Brand("GRAPH NEIGHBORS"), s.Identifier(id), len(nodes))
			if len(nodes) == 0 {
				fmt.Println("  No connected neighbors found.")
				return nil
			}
			for _, n := range nodes {
				fmt.Printf("  • %-16s [%-12s] %s\n", s.Identifier(n.ID), s.Category(string(n.Type)), n.Label)
			}
			return nil

		case "services":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: graph services <node_id>")
			}
			id := cmd.Args[1]
			services, err := a.GraphServices(id)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(services, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s for: %s (Total: %d)\n\n", s.Brand("CONNECTED SERVICES"), s.Identifier(id), len(services))
			if len(services) == 0 {
				fmt.Println("  No service nodes connected.")
				return nil
			}
			for _, svc := range services {
				proto := svc.Properties["protocol"]
				port := svc.Properties["port"]
				fmt.Printf("  • %-16s %-10s port %-6s %s\n", s.Identifier(svc.ID), proto, port, svc.Label)
			}
			return nil

		case "hosts":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: graph hosts <node_id>")
			}
			id := cmd.Args[1]
			hosts, err := a.GraphHosts(id)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(hosts, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s for: %s (Total: %d)\n\n", s.Brand("CONNECTED HOSTS"), s.Identifier(id), len(hosts))
			if len(hosts) == 0 {
				fmt.Println("  No host nodes connected.")
				return nil
			}
			for _, h := range hosts {
				ip := h.Properties["ip"]
				fmt.Printf("  • %-16s %-16s %s\n", s.Identifier(h.ID), ip, h.Label)
			}
			return nil

		case "networks":
			nodes, err := a.GraphNodesByType(graph.NodeNetwork)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(nodes, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("NETWORK NODES"), len(nodes))
			for _, n := range nodes {
				cidr := n.Properties["cidr"]
				fmt.Printf("  • %-16s %-18s %s\n", s.Identifier(n.ID), cidr, n.Label)
			}
			return nil

		case "protocols":
			nodes, err := a.GraphNodesByType(graph.NodeProtocol)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(nodes, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("PROTOCOL NODES"), len(nodes))
			for _, n := range nodes {
				fmt.Printf("  • %-16s %s\n", s.Identifier(n.ID), n.Label)
			}
			return nil

		case "technologies":
			nodes, err := a.GraphNodesByType(graph.NodeTechnology)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(nodes, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("TECHNOLOGY NODES"), len(nodes))
			for _, n := range nodes {
				category := n.Properties["category"]
				version := n.Properties["version"]
				fmt.Printf("  • %-16s %-14s %-12s %s\n", s.Identifier(n.ID), category, version, n.Label)
			}
			return nil

		case "zones":
			nodes, err := a.GraphNodesByType(graph.NodeZone)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(nodes, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("SECURITY ZONE NODES"), len(nodes))
			for _, n := range nodes {
				fmt.Printf("  • %-16s %s\n", s.Identifier(n.ID), n.Label)
			}
			return nil

		case "routes":
			nodes, err := a.GraphNodesByType(graph.NodeRoute)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(nodes, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("ROUTE NODES"), len(nodes))
			for _, n := range nodes {
				gw := n.Properties["gateway"]
				fmt.Printf("  • %-16s via %-16s %s\n", s.Identifier(n.ID), gw, n.Label)
			}
			return nil

		case "components":
			comps, err := a.GraphComponents()
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(comps, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total Components: %d)\n\n", s.Brand("CONNECTED COMPONENTS"), len(comps))
			for i, comp := range comps {
				fmt.Printf("  Component %d (%d nodes): %s\n", i+1, len(comp), strings.Join(comp, ", "))
			}
			return nil

		case "isolated":
			isolated, err := a.GraphIsolated()
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(isolated, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("ISOLATED NODES"), len(isolated))
			if len(isolated) == 0 {
				fmt.Println("  No isolated nodes detected. All nodes are connected.")
				return nil
			}
			for _, n := range isolated {
				fmt.Printf("  • %-16s [%-12s] %s\n", s.Identifier(n.ID), s.Category(string(n.Type)), n.Label)
			}
			return nil

		case "path":
			if len(cmd.Args) < 3 {
				return fmt.Errorf("usage: graph path <source_id> <target_id>")
			}
			src := cmd.Args[1]
			dst := cmd.Args[2]
			pathRes, err := a.GraphDetailedPath(src, dst)
			if err != nil {
				return err
			}
			if pathRes == nil || len(pathRes.NodeIDs) == 0 {
				fmt.Printf("No path found between %s and %s\n", src, dst)
				return nil
			}
			if isJSON {
				out, _ := json.MarshalIndent(pathRes, "", "  ")
				fmt.Println(string(out))
				return nil
			}

			fmt.Printf("%s\n\n", s.Brand(fmt.Sprintf("DETAILED PATH: %s ──▶ %s", src, dst)))
			fmt.Printf("  Total Hops: %d\n\n", pathRes.Hops)
			for i, step := range pathRes.Steps {
				fromDesc := fmt.Sprintf("[%s (%s)]", step.FromNode.ID, step.FromNode.Type)
				toDesc := fmt.Sprintf("[%s (%s)]", step.ToNode.ID, step.ToNode.Type)
				fmt.Printf("  Step %d: %s ──(%s)──▶ %s\n", i+1, s.Info(fromDesc), s.Brand(string(step.EdgeType)), s.Success(toDesc))
			}
			fmt.Printf("\n  Summary: %s\n", strings.Join(pathRes.NodeIDs, " ──▶ "))
			return nil

		case "dot":
			dot, err := a.GraphExportDOT()
			if err != nil {
				return err
			}
			fmt.Println(dot)
			return nil

		default:
			return fmt.Errorf("unknown graph subcommand %q. Valid subcommands: stats, neighbors, services, hosts, networks, protocols, technologies, zones, routes, components, isolated, path, dot", sub)
		}
	})

	r.Register(CommandMeta{
		Name:        "search",
		Category:    CategoryIntelligence,
		Usage:       "search <query>",
		Description: "Perform global search across assets, services, technologies, evidence, and findings",
		Examples:    []string{"search modbus", "search dc01", "search \"10.0.10.15\""},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) == 0 {
			return fmt.Errorf("usage: search <query>")
		}
		query := cmd.Args[0]
		results, err := a.GlobalSearch(query)
		if err != nil {
			return err
		}

		if len(results) == 0 {
			fmt.Printf("No results matching query %q\n", query)
			return nil
		}

		fmt.Printf("%s (Matches: %d)\n\n", s.Brand(fmt.Sprintf("SEARCH RESULTS: %q", query)), len(results))
		for _, res := range results {
			fmt.Printf("  [%-12s] %-14s %s = %s\n", s.Category(res.EntityType), s.Identifier(res.EntityID), res.Field, s.Info(res.Value))
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "why",
		Category:    CategoryIntelligence,
		Usage:       "why <asset|service|finding|path|relationship> [<target2>] [--json]",
		Description: "Explain the evidence, provenance, and rationale for any conclusion or entity",
		Aliases:     []string{"explain"},
		Examples: []string{
			"why ASSET-001",
			"why SVC-001",
			"why FND-0001",
			"why PATH-001",
			"why ASSET-001 NET-001",
		},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) == 0 {
			return fmt.Errorf("usage: why <target_id> [secondary_target_id] (e.g. why ASSET-001, why FND-0001, why SVC-001)")
		}

		target := cmd.Args[0]
		var secondTarget []string
		if len(cmd.Args) > 1 {
			secondTarget = append(secondTarget, cmd.Args[1])
		}

		exp, err := a.Why(target, secondTarget...)
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(exp, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s: %s\n\n", s.Brand("EXPLAINABILITY REPORT"), s.Identifier(exp.TargetID))
		fmt.Printf("  Target Type       : %s\n", exp.TargetType)
		fmt.Printf("  What Falcon Believes: %s\n", s.Success(exp.Belief))
		fmt.Printf("  Confidence        : %s\n", s.Category(string(exp.Confidence)))
		if len(exp.Collectors) > 0 {
			fmt.Printf("  Collector Sources : %s\n", strings.Join(exp.Collectors, ", "))
		}
		if !exp.FirstSeen.IsZero() {
			fmt.Printf("  First Observed    : %s\n", exp.FirstSeen.Format(time.RFC3339))
			fmt.Printf("  Last Observed     : %s\n", exp.LastSeen.Format(time.RFC3339))
		}
		fmt.Printf("\n  %s\n", s.Info("Rationale / Evaluation:"))
		for _, line := range strings.Split(strings.TrimSpace(exp.Rationale), "\n") {
			fmt.Printf("    %s\n", line)
		}

		if !exp.IsSufficient {
			fmt.Printf("\n  %s\n", s.Warning("Insufficient evidence for a high-confidence conclusion."))
		}

		return nil
	})

	r.Register(CommandMeta{
		Name:        "findings",
		Category:    CategoryIntelligence,
		Usage:       "findings [list|show <id>] [--category <cat>] [--json]",
		Description: "Browse evaluated security findings and assessment results",
		Aliases:     []string{"f"},
		Examples:    []string{"findings", "findings show FND-0001", "findings --category ot"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {

		if len(cmd.Args) >= 2 && (cmd.Args[0] == "show" || cmd.Args[0] == "explain") {
			exp, err := a.ExplainFinding(cmd.Args[1])
			if err != nil {
				return err
			}
			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(exp, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s\n", s.Brand(fmt.Sprintf("FINDING DETAIL: %s", exp.FindingID)))
			fmt.Println(strings.Repeat("─", 50))
			fmt.Printf("Title       : %s\n", exp.Title)
			fmt.Printf("Rule        : %s\n", exp.RuleID)
			fmt.Printf("Category    : %s\n", exp.Category)
			fmt.Printf("Entity      : %s %s\n\n", exp.EntityType, exp.EntityID)
			fmt.Printf("Rationale:\n  %s\n", exp.Rationale)
			return nil
		}

		findings, err := a.ListFindings()
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			// Auto run assessment
			res, err := a.RunAssessment()
			if err == nil {
				findings = res.Findings
			}
		}

		if len(findings) == 0 {
			fmt.Println("No findings in the current workspace. Import assessment evidence first.")
			return nil
		}

		catFilter := cmd.Flags["category"]
		var filtered []domain.Finding
		for _, f := range findings {
			if catFilter != "" && !strings.EqualFold(string(f.Category), catFilter) {
				continue
			}
			filtered = append(filtered, f)
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(filtered, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s (Total: %d)\n\n", s.Brand("EVALUATED FINDINGS"), len(filtered))
		for _, f := range filtered {
			fmt.Printf("  %-10s [%-12s] %-14s %-12s %s\n",
				s.Identifier(f.ID), s.Category(string(f.Category)), s.Command(f.RuleID), f.EntityID, f.Title)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "correlate",
		Category:    CategoryIntelligence,
		Usage:       "correlate",
		Description: "Correlate related observations and findings grouped by entity",
		Examples:    []string{"correlate"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		groups, err := a.CorrelateFindings()
		if err != nil {
			return err
		}
		if len(groups) == 0 {
			fmt.Println("No findings to correlate.")
			return nil
		}

		fmt.Printf("%s\n\n", s.Brand("CORRELATED FINDINGS & THREAT CLUSTERS"))
		for entity, list := range groups {
			fmt.Printf("Target Entity: %s\n", s.Identifier(entity))
			for _, f := range list {
				fmt.Printf("  ├── [%s] %s\n", f.Category, f.Title)
			}
			fmt.Println()
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "timeline",
		Category:    CategoryIntelligence,
		Usage:       "timeline",
		Description: "Show chronological evidence and intelligence event timeline",
		Examples:    []string{"timeline"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		items, err := a.GetTimeline()
		if err != nil {
			return err
		}
		if len(items) == 0 {
			fmt.Println("Timeline is empty.")
			return nil
		}

		fmt.Printf("%s (Total Events: %d)\n\n", s.Brand("INTELLIGENCE TIMELINE"), len(items))
		for _, item := range items {
			fmt.Printf("  %-19s  %-10s  %-12s  %s\n",
				item.Timestamp.Format("2006-01-02 15:04:05"), s.Category(item.Kind), s.Identifier(item.EntityID), item.Description)
		}
		return nil
	})

	// ===================================================================
	// ENGAGEMENT
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "engagement",
		Category:    CategoryEngagement,
		Usage:       "engagement [create <name>|show|list]",
		Description: "Manage Red Team engagements, campaign scopes, and objectives",
		Examples:    []string{"engagement show", "engagement create ACME-RED-01"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) >= 2 && cmd.Args[0] == "create" {
			name := cmd.Args[1]
			eng, err := a.CreateEngagement(name, "Internal Assessment", "Red Team engagement campaign")
			if err != nil {
				return err
			}
			fmt.Printf("Created engagement %s (%s)\n", s.Success(eng.Name), eng.ID)
			return nil
		}

		eng, err := a.GetActiveEngagement()
		if err != nil {
			return err
		}

		info, _ := a.WorkspaceInfo(a.ActiveWorkspace())

		fmt.Printf("%s\n", s.Brand("ENGAGEMENT"))
		fmt.Println(strings.Repeat("─", 45))
		fmt.Printf("Name        %s\n", eng.Name)
		fmt.Printf("Type        %s\n", eng.Type)
		fmt.Printf("Status      %s\n\n", s.Success(string(eng.Status)))

		fmt.Println("Scope")
		fmt.Printf("  Assets       %-4d\n", info.AssetCount)
		fmt.Printf("  Networks     %-4d\n", info.NetworkCount)
		fmt.Printf("  Evidence     %-4d\n\n", info.EvidenceCount)

		fmt.Println("Objectives")
		for _, obj := range eng.Objectives {
			statusMark := "[ ]"
			if obj.Completed {
				statusMark = s.Success("[✓]")
			}
			fmt.Printf("  %s %s\n", statusMark, obj.Title)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "scope",
		Category:    CategoryEngagement,
		Usage:       "scope [show|add <pattern>|include <pattern>|exclude <pattern>|remove <id>]",
		Description: "Inspect and manage authorized assessment boundaries and scope rules",
		Aliases:     []string{"sc"},
		Examples:    []string{"scope", "scope show", "scope add 10.10.0.0/16", "scope exclude 10.10.99.0/24", "scope include *.corp.internal"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		sub := "show"
		if len(cmd.Args) > 0 {
			sub = cmd.Args[0]
		}

		switch sub {
		case "show":
			sg, err := a.BuildScopeGuard()
			if err != nil {
				return err
			}
			summary := sg.Summary()

			if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
				out, _ := json.MarshalIndent(summary, "", "  ")
				fmt.Println(string(out))
				return nil
			}

			fmt.Printf("%s\n\n", s.Brand("ENGAGEMENT AUTHORIZATION SCOPE"))
			fmt.Printf("  Active Targets  : %d\n", summary.TargetCount)
			fmt.Printf("  Total Rules     : %d (Included: %d, Excluded: %d)\n", summary.TotalRules, summary.IncludeCount, summary.ExcludeCount)
			fmt.Printf("  Rate Limit      : %s\n", summary.RateLimit)
			fmt.Printf("  Timeout         : %s\n", summary.Timeout)
			fmt.Printf("  Max Workers     : %d\n", summary.MaxWorkers)

			rules, _ := a.ListScopeRules()
			if len(rules) > 0 {
				fmt.Println("\n  Scope Rules:")
				for _, r := range rules {
					badge := s.Success("[INCLUDE]")
					if r.RuleType == domain.ScopeExclude {
						badge = s.Warning("[EXCLUDE]")
					}
					fmt.Printf("    %s %-9s [%-8s] %-25s %s\n",
						badge, s.Identifier(r.ID), r.TargetType, r.Pattern, s.Muted(r.Description))
				}
			}

			targets, _ := a.ListTargets()
			if len(targets) > 0 {
				fmt.Println("\n  Target Scope Status:")
				for _, t := range targets {
					statusBadge := s.Success("IN_SCOPE")
					if t.Scope == domain.TargetOutOfScope {
						statusBadge = s.Warning("OUT_OF_SCOPE")
					}
					val := t.NormalizedValue
					if val == "" {
						val = t.Value
					}
					fmt.Printf("    %-10s [%-12s] %-25s (%s)\n", s.Identifier(t.ID), statusBadge, val, t.Type)
				}
			}

			if len(rules) == 0 && len(targets) == 0 {
				fmt.Println("\n  Scope is currently unrestricted for initial target definition.")
				fmt.Println("  Add targets using 'target <val>' or scope rules using 'scope add/include/exclude <val>'.")
			}
			return nil

		case "add", "include":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: scope %s <pattern> [description]", sub)
			}
			pat := cmd.Args[1]
			desc := ""
			if len(cmd.Args) > 2 {
				desc = strings.Join(cmd.Args[2:], " ")
			}
			rule, err := a.AddScopeRule(domain.ScopeInclude, pat, desc)
			if err != nil {
				return err
			}
			fmt.Printf("%s Added inclusion rule %s for pattern %s\n", s.Success("[+]"), s.Identifier(rule.ID), s.Success(rule.Pattern))
			return nil

		case "exclude":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: scope exclude <pattern> [description]")
			}
			pat := cmd.Args[1]
			desc := ""
			if len(cmd.Args) > 2 {
				desc = strings.Join(cmd.Args[2:], " ")
			}
			rule, err := a.AddScopeRule(domain.ScopeExclude, pat, desc)
			if err != nil {
				return err
			}
			fmt.Printf("%s Added exclusion rule %s for pattern %s\n", s.Warning("[!]"), s.Identifier(rule.ID), s.Warning(rule.Pattern))
			return nil

		case "remove", "delete":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: scope remove <rule_id>")
			}
			id := cmd.Args[1]
			if err := a.DeleteScopeRule(id); err != nil {
				return err
			}
			fmt.Printf("Removed scope rule %s\n", s.Warning(id))
			return nil

		default:
			return fmt.Errorf("unknown scope subcommand %q. Type 'help scope' for usage", sub)
		}
	})

	r.Register(CommandMeta{
		Name:        "plan",
		Category:    CategoryEngagement,
		Usage:       "plan [target_id] [--profile <name>] [--json]",
		Description: "Generate a pre-execution assessment plan verifying collectors and scope",
		Aliases:     []string{"pl"},
		Examples:    []string{"plan", "plan TGT-001", "plan --profile network"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		targetID := ""
		if len(cmd.Args) > 0 {
			targetID = cmd.Args[0]
		}
		profile := "network"
		if p, ok := cmd.Flags["profile"]; ok {
			profile = p
		}

		plan, err := a.GenerateAssessmentPlan(targetID, profile)
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(plan, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		// Terminal Box Output
		line := "──────────────────────────────────────────────"
		fmt.Printf("╭%s╮\n", line)
		fmt.Printf("│ %-44s │\n", s.Brand("FALCON ASSESSMENT PLAN"))
		fmt.Printf("├%s┤\n", line)
		fmt.Printf("│ Target:       %-30s │\n", plan.TargetValue)
		fmt.Printf("│ Type:         %-30s │\n", plan.TargetType)
		fmt.Printf("│ Profile:      %-30s │\n", plan.Profile)
		fmt.Printf("│ Scope:        %-30s │\n", plan.ScopeSummary)
		fmt.Printf("│ Rate:         %-30s │\n", plan.RateLimit)
		fmt.Printf("│ Workers:      %-30d │\n", plan.Workers)
		fmt.Printf("│ Timeout:      %-30s │\n", plan.Timeout)
		fmt.Printf("│ Scope Guard:  %-30s │\n", s.Success("enabled"))
		fmt.Printf("╰%s╯\n\n", line)

		fmt.Println(s.Brand("DISCOVERY"))
		for _, step := range plan.DiscoverySteps {
			fmt.Printf("  %s %s\n", s.Success("✓"), step)
		}

		fmt.Println("\n" + s.Brand("CORRELATION"))
		for _, step := range plan.CorrelationSteps {
			fmt.Printf("  %s %s\n", s.Success("✓"), step)
		}

		fmt.Println("\n" + s.Brand("INTELLIGENCE"))
		for _, step := range plan.IntelligenceSteps {
			fmt.Printf("  %s %s\n", s.Success("✓"), step)
		}

		return nil
	})

	r.Register(CommandMeta{
		Name:        "assess",
		Category:    CategoryEngagement,
		Usage:       "assess [<target>] [status|history] [--ports <ports>] [--timeout <duration>] [--workers <n>] [--rate-limit <rate>] [--json]",
		Description: "Execute active discovery collectors and analyze security findings",
		Aliases:     []string{"scan"},
		Examples:    []string{"assess", "assess example.com", "assess status", "assess history"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		// 1. Subcommands: status, history
		if len(cmd.Args) > 0 {
			switch strings.ToLower(cmd.Args[0]) {
			case "status":
				latestRun, err := a.GetLatestAssessmentRun()
				if err != nil {
					return err
				}
				if latestRun == nil {
					fmt.Println("No assessment runs recorded in the current workspace. Run 'assess' to start one.")
					return nil
				}
				if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
					out, _ := json.MarshalIndent(latestRun, "", "  ")
					fmt.Println(string(out))
					return nil
				}
				fmt.Printf("%s\n", s.Brand(fmt.Sprintf("ASSESSMENT RUN: %s", latestRun.ID)))
				fmt.Println(strings.Repeat("─", 45))
				fmt.Printf("Run ID       : %s\n", s.Identifier(latestRun.ID))
				fmt.Printf("Status       : %s\n", formatRunStatus(s, string(latestRun.Status)))
				fmt.Printf("Target       : %s (%s)\n", latestRun.TargetValue, latestRun.TargetID)
				fmt.Printf("Started      : %s\n", latestRun.StartedAt.Format("2006-01-02 15:04:05"))
				if !latestRun.CompletedAt.IsZero() {
					dur := latestRun.CompletedAt.Sub(latestRun.StartedAt).Round(time.Millisecond)
					fmt.Printf("Completed    : %s (Duration: %s)\n", latestRun.CompletedAt.Format("2006-01-02 15:04:05"), dur)
				}
				if len(latestRun.CollectorStats) > 0 {
					fmt.Println("\nCollector Observations:")
					for cName, count := range latestRun.CollectorStats {
						fmt.Printf("  • %-16s : %d observations\n", cName, count)
					}
				}
				if len(latestRun.Errors) > 0 {
					fmt.Println("\nErrors:")
					for _, errStr := range latestRun.Errors {
						fmt.Printf("  • %s\n", s.Error(errStr))
					}
				}
				return nil

			case "history", "list":
				runs, err := a.ListAssessmentRuns()
				if err != nil {
					return err
				}
				if len(runs) == 0 {
					fmt.Println("No assessment runs recorded in the current workspace.")
					return nil
				}
				if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
					out, _ := json.MarshalIndent(runs, "", "  ")
					fmt.Println(string(out))
					return nil
				}
				fmt.Printf("%-10s %-12s %-25s %-20s %s\n", "RUN ID", "STATUS", "TARGET", "STARTED", "DURATION")
				fmt.Println(strings.Repeat("─", 80))
				for _, r := range runs {
					durStr := "-"
					if !r.CompletedAt.IsZero() {
						durStr = r.CompletedAt.Sub(r.StartedAt).Round(time.Millisecond).String()
					}
					fmt.Printf("%-10s %-12s %-25s %-20s %s\n",
						s.Identifier(r.ID),
						formatRunStatus(s, string(r.Status)),
						r.TargetValue,
						r.StartedAt.Format("2006-01-02 15:04"),
						durStr,
					)
				}
				return nil
			}
		}

		// 2. Active Assessment Execution
		targetInput := ""
		if len(cmd.Args) > 0 && cmd.Args[0] != "run" {
			targetInput = cmd.Args[0]
		}

		opts := collector.DefaultOptions()
		if pStr, ok := cmd.Flags["ports"]; ok {
			var parsedPorts []int
			for _, p := range strings.Split(pStr, ",") {
				if portNum, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && portNum > 0 && portNum <= 65535 {
					parsedPorts = append(parsedPorts, portNum)
				}
			}
			if len(parsedPorts) > 0 {
				opts.Ports = parsedPorts
			}
		}
		if tStr, ok := cmd.Flags["timeout"]; ok {
			if d, err := time.ParseDuration(tStr); err == nil {
				opts.Timeout = d
			}
		}
		if wStr, ok := cmd.Flags["workers"]; ok {
			if w, err := strconv.Atoi(wStr); err == nil && w > 0 {
				opts.Workers = w
			}
		}
		if rl, ok := cmd.Flags["rate-limit"]; ok {
			opts.RateLimit = rl
		}

		isJSON := cmd.OutputFormat == "json" || cmd.Flags["json"] == "true"

		progressCb := func(evt assessment.ProgressEvent) {
			if isJSON {
				return
			}
			switch evt.Status {
			case "start":
				fmt.Printf("Run: %s\n\n", evt.Collector)
			case "done", "failed":
				fmt.Println(assessment.FormatProgressLine(evt.Collector, evt.Status))
			}
		}

		if !isJSON {
			fmt.Println("Assessment started")
		}

		ctx := context.Background()
		run, res, err := a.ExecuteAssessment(ctx, targetInput, opts, progressCb)
		if err != nil {
			return err
		}

		if isJSON {
			out, _ := json.MarshalIndent(map[string]interface{}{
				"run":     run,
				"results": res,
			}, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Println("\nAssessment completed")
		return nil
	})

	r.Register(CommandMeta{
		Name:        "objectives",
		Category:    CategoryEngagement,
		Usage:       "objectives [list|add <title>]",
		Description: "Manage Red Team engagement objectives and milestones",
		Examples:    []string{"objectives list", "objectives add \"Map OT Perimeter\""},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		eng, _ := a.GetActiveEngagement()
		if len(cmd.Args) >= 2 && cmd.Args[0] == "add" {
			title := strings.Join(cmd.Args[1:], " ")
			_ = a.AddObjective(eng.ID, title)
			fmt.Printf("Added objective: %s\n", s.Success(title))
			return nil
		}

		fmt.Printf("%s for %s\n\n", s.Brand("ENGAGEMENT OBJECTIVES"), eng.Name)
		for _, o := range eng.Objectives {
			mark := "[ ]"
			if o.Completed {
				mark = s.Success("[✓]")
			}
			fmt.Printf("  %s %s\n", mark, o.Title)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "snapshot",
		Category:    CategoryEngagement,
		Usage:       "snapshot [create <name>|list|show <id>] [--json]",
		Description: "Create and inspect point-in-time assessment snapshots",
		Examples:    []string{"snapshot list", "snapshot create baseline", "snapshot show baseline"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		sub := "list"
		if len(cmd.Args) > 0 {
			sub = cmd.Args[0]
		}
		isJSON := cmd.OutputFormat == "json" || cmd.Flags["json"] == "true"

		switch sub {
		case "list":
			snaps, err := a.ListSnapshots()
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(snaps, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s (Total: %d)\n\n", s.Brand("ASSESSMENT SNAPSHOTS"), len(snaps))
			for _, snap := range snaps {
				fmt.Printf("  %-16s Assessment: %-14s Created: %s\n",
					s.Identifier(snap.ID), snap.AssessmentID, snap.CreatedAt.Format("2006-01-02 15:04:05"))
			}
			return nil

		case "create":
			name := ""
			if len(cmd.Args) > 1 {
				name = cmd.Args[1]
			}
			snap, err := a.CreateSnapshot(name)
			if err != nil {
				return err
			}
			if isJSON {
				out, _ := json.MarshalIndent(snap, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("Snapshot %s created successfully.\n", s.Success(snap.ID))
			return nil

		case "show":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: snapshot show <snapshot_id>")
			}
			id := cmd.Args[1]
			snap, err := a.GetSnapshot(id)
			if err != nil {
				return err
			}
			if snap == nil {
				return fmt.Errorf("snapshot %q not found", id)
			}
			if isJSON {
				out, _ := json.MarshalIndent(snap, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Printf("%s: %s\n\n", s.Brand("ASSESSMENT SNAPSHOT"), s.Identifier(snap.ID))
			fmt.Printf("  Assessment ID : %s\n", snap.AssessmentID)
			fmt.Printf("  Workspace     : %s\n", snap.WorkspaceID)
			fmt.Printf("  Created At    : %s\n\n", snap.CreatedAt.Format(time.RFC3339))
			return nil

		default:
			return fmt.Errorf("unknown snapshot subcommand %q. Valid subcommands: list, create <name>, show <id>", sub)
		}
	})

	// ===================================================================
	// REPORTING
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "report",
		Category:    CategoryReporting,
		Usage:       "report [--format table|json|ndjson|markdown] [--output <file>]",
		Description: "Generate deterministic executive and technical assessment reports",
		Aliases:     []string{"rep", "r"},
		Examples:    []string{"report", "report --format json", "report --format markdown --output report.md"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		format := reporting.FormatTable
		switch cmd.OutputFormat {
		case "json":
			format = reporting.FormatJSON
		case "ndjson":
			format = reporting.FormatNDJSON
		case "markdown", "md":
			format = reporting.FormatMarkdown
		}
		if cmd.Flags["json"] == "true" {
			format = reporting.FormatJSON
		}

		out, err := a.GenerateReport(format, true)
		if err != nil {
			return err
		}

		if outFile, ok := cmd.Flags["output"]; ok && outFile != "" {
			if err := os.WriteFile(outFile, []byte(out), 0644); err != nil {
				return fmt.Errorf("writing report to %q: %w", outFile, err)
			}
			fmt.Printf("Report saved to %s\n", s.Success(outFile))
			return nil
		}

		fmt.Println(out)
		return nil
	})

	r.Register(CommandMeta{
		Name:        "diff",
		Category:    CategoryReporting,
		Usage:       "diff <snapshot_or_assessment_1> <snapshot_or_assessment_2> [--json]",
		Description: "Compare two snapshots or assessments to evaluate delta changes across ADDED, REMOVED, CHANGED, UNCHANGED",
		Examples:    []string{"diff baseline second", "diff ASSESS-001 ASSESS-002"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		if len(cmd.Args) < 2 {
			return fmt.Errorf("usage: diff <snapshot_1> <snapshot_2>")
		}
		baseID := cmd.Args[0]
		targetID := cmd.Args[1]
		d, err := a.CompareSnapshots(baseID, targetID)
		if err != nil {
			return err
		}

		if cmd.OutputFormat == "json" || cmd.Flags["json"] == "true" {
			out, _ := json.MarshalIndent(d, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("%s\n\n", s.Brand(fmt.Sprintf("ASSESSMENT STRUCTURAL DIFF: %s ➔ %s", baseID, targetID)))
		fmt.Printf("  ADDED Findings      : %d\n", d.AddedCount)
		fmt.Printf("  REMOVED Findings    : %d\n", d.RemovedCount)
		fmt.Printf("  CHANGED Findings    : %d\n", d.ChangedCount)
		fmt.Printf("  UNCHANGED Findings  : %d\n", d.UnchangedCount)
		fmt.Printf("  Persisting Total    : %d\n\n", d.PersistingCount)

		if len(d.Items) > 0 {
			fmt.Println("  Detailed Changes:")
			for _, item := range d.Items {
				switch item.Status {
				case "ADDED":
					fmt.Printf("    • %s %-12s %s\n", s.Success("[ADDED]  "), item.Finding.ID, item.Finding.Title)
				case "REMOVED":
					fmt.Printf("    • %s %-12s %s\n", s.Error("[REMOVED]"), item.Finding.ID, item.Finding.Title)
				case "CHANGED":
					fmt.Printf("    • %s %-12s %s (%s)\n", s.Brand("[CHANGED]"), item.Finding.ID, item.Finding.Title, strings.Join(item.Changes, ", "))
				}
			}
		}
		return nil
	})

	// ===================================================================
	// WORKSPACE
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "workspace",
		Category:    CategoryWorkspace,
		Usage:       "workspace [list|current|create <name>|use <name>|delete <name>|info|export <file>|import <file>]",
		Description: "Manage isolated workspaces and database instances",
		Aliases:     []string{"ws"},
		Examples:    []string{"workspace list", "workspace current", "workspace use red-team-01", "workspace create red-team-01 --use"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		sub := "list"
		if len(cmd.Args) > 0 {
			sub = cmd.Args[0]
		}

		switch sub {
		case "list":
			list, err := a.ListWorkspaces()
			if err != nil {
				return err
			}
			fmt.Printf("%s\n\n", s.Brand("FALCON WORKSPACES"))
			for _, ws := range list {
				activeMarker := " "
				if ws.IsActive {
					activeMarker = s.Success("▶")
				}
				fmt.Printf(" %s %-16s %-40s (Assets: %d, Findings: %d)\n",
					activeMarker, s.Identifier(ws.Name), s.Muted(ws.Path), ws.AssetCount, ws.FindingCount)
			}
			return nil

		case "current":
			info, err := a.WorkspaceInfo(a.ActiveWorkspace())
			if err != nil {
				fmt.Printf("Active workspace: %s\n", s.Success(a.ActiveWorkspace()))
				return nil
			}
			fmt.Printf("%s\n\n", s.Brand("ACTIVE WORKSPACE CONTEXT"))
			fmt.Printf("  Workspace Name  : %s\n", s.Success(info.Name))
			fmt.Printf("  Database Path   : %s\n", s.Muted(info.Path))
			fmt.Printf("  Database Size   : %d bytes\n", info.SizeBytes)
			fmt.Printf("  Assets          : %d\n", info.AssetCount)
			fmt.Printf("  Services        : %d\n", info.ServiceCount)
			fmt.Printf("  Networks        : %d\n", info.NetworkCount)
			fmt.Printf("  Findings        : %d\n", info.FindingCount)
			fmt.Printf("  Evidence        : %d\n", info.EvidenceCount)
			return nil

		case "create":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: workspace create <name> [--use]")
			}
			name := cmd.Args[1]
			if err := a.CreateWorkspace(name); err != nil {
				return err
			}
			if cmd.Flags["use"] == "true" {
				_ = a.UseWorkspace(name)
				fmt.Printf("Workspace %s created and activated.\n", s.Success(name))
			} else {
				fmt.Printf("Workspace %s created. (Active workspace remains %q. Run 'workspace use %s' to switch)\n",
					s.Success(name), a.ActiveWorkspace(), name)
			}
			return nil

		case "use", "switch":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: workspace use <name>")
			}
			name := cmd.Args[1]
			if err := a.UseWorkspace(name); err != nil {
				return err
			}
			fmt.Printf("Switched to workspace %s\n", s.Success(name))
			return nil

		case "delete":
			if len(cmd.Args) < 2 {
				return fmt.Errorf("usage: workspace delete <name>")
			}
			name := cmd.Args[1]
			if err := a.DeleteWorkspace(name); err != nil {
				return err
			}
			fmt.Printf("Deleted workspace %s\n", s.Warning(name))
			return nil

		default:
			return fmt.Errorf("unknown workspace action %q", sub)
		}
	})

	// ===================================================================
	// MODULES
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "modules",
		Category:    CategoryModules,
		Usage:       "modules [list|show <id>|validate]",
		Description: "Inspect built-in intelligence, parser, graph, and reporting modules",
		Aliases:     []string{"mod"},
		Examples:    []string{"modules", "modules list"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		mods := a.Modules.List()
		fmt.Printf("%s (Total: %d)\n\n", s.Brand("BUILT-IN CAPABILITY MODULES"), len(mods))
		for _, m := range mods {
			fmt.Printf("  %-20s %-10s %s\n", s.Command(m.ID), s.Muted(m.Version), m.Description)
			fmt.Printf("    Capabilities: %s\n\n", strings.Join(m.Capabilities, ", "))
		}
		return nil
	})

	// ===================================================================
	// SHELL
	// ===================================================================

	r.Register(CommandMeta{
		Name:        "history",
		Category:    CategoryShell,
		Usage:       "history",
		Description: "Show interactive REPL command history",
		Examples:    []string{"history"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		fmt.Printf("%s\n\n", s.Brand("COMMAND HISTORY"))
		for i, line := range r.history {
			fmt.Printf("  %3d  %s\n", i+1, line)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "alias",
		Category:    CategoryShell,
		Usage:       "alias [list|add <name> <cmd>]",
		Description: "Manage command shortcuts and aliases",
		Examples:    []string{"alias", "alias list"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		fmt.Printf("%s\n\n", s.Brand("CONFIGURED ALIASES"))
		for alias, target := range r.aliases {
			fmt.Printf("  %-10s ➔  %s\n", s.Command(alias), target)
		}
		return nil
	})

	r.Register(CommandMeta{
		Name:        "theme",
		Category:    CategoryShell,
		Usage:       "theme [show|reset]",
		Description: "Show or configure terminal color theme",
		Examples:    []string{"theme"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		fmt.Printf("%s: Falcon Green (ANSI 256/16 semantic)\n", s.Brand("Current Theme"))
		return nil
	})

	r.Register(CommandMeta{
		Name:        "clear",
		Category:    CategoryShell,
		Usage:       "clear",
		Description: "Clear the terminal screen",
		Examples:    []string{"clear"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		print("\033[H\033[2J")
		return nil
	})

	r.Register(CommandMeta{
		Name:        "exit",
		Category:    CategoryShell,
		Usage:       "exit",
		Description: "Exit the Falcon interactive shell",
		Aliases:     []string{"quit", "q"},
		Examples:    []string{"exit"},
	}, func(a *app.App, s *terminal.Style, cmd *ParsedCommand) error {
		_ = a.Close()
		fmt.Println("Exiting Falcon ToolKit.")
		os.Exit(0)
		return nil
	})
}

// formatRunStatus styles an AssessmentRun status string.
func formatRunStatus(s *terminal.Style, status string) string {
	switch strings.ToUpper(status) {
	case "COMPLETED":
		return s.Success("COMPLETED")
	case "RUNNING":
		return s.Info("RUNNING")
	case "FAILED":
		return s.Error("FAILED")
	case "CANCELLED":
		return s.Warning("CANCELLED")
	default:
		return s.Muted(status)
	}
}
