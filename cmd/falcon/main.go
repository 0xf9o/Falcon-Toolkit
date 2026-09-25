package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"falcon/internal/app"
	"falcon/internal/db"
	"falcon/internal/modules"
	"falcon/internal/ui"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	dbPath         = "falcon_data.db"
	globalStore    *db.Store
	globalMatcher  *modules.SignatureEngine
	portsFlag      string
	workersFlag    int
	timeoutFlag    int
	rateLimitFlag  int
	workspaceFlag  string
	jsonOutputFlag bool
)

var rootCmd = &cobra.Command{
	Use:   "falcon [command]",
	Short: "Falcon v3.0 - High-Performance Network Diagnostics & TUI Framework",
	Long: `⚡ Falcon v3.0 - Cyber Diagnostics & Reconnaissance Framework
Lead Systems Architect: Faisal Al-Harbi (0xF9o)

Falcon v3.0 is a standalone, ultra-fast network diagnostic and reconnaissance framework
featuring a full-screen Cyberpunk Terminal UI (TUI), dual-mode CLI/REPL runner,
YAML-based protocol signature matcher, and embedded topology graph persistence.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open database at %s: %w", dbPath, err)
		}
		globalStore = store

		matcher, err := modules.NewSignatureEngine()
		if err != nil {
			return fmt.Errorf("failed to initialize signature engine: %w", err)
		}
		globalMatcher = matcher

		if workspaceFlag != "" {
			_ = globalStore.SetActiveWorkspace(workspaceFlag)
		}
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if globalStore != nil {
			_ = globalStore.Close()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default action when run without arguments: Launch Cyberpunk Bubbletea TUI
		return app.StartTUI(globalStore, globalMatcher)
	},
}

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch full-screen Cyberpunk Terminal UI (TUI) Dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.StartTUI(globalStore, globalMatcher)
	},
}

var replCmd = &cobra.Command{
	Use:   "repl",
	Short: "Launch interactive readline shell prompt (falcon >)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.StartInteractive(globalStore)
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Perform high-speed TCP socket & HTTP probe with YAML signature identification",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		activeWs, _ := globalStore.GetActiveWorkspace()
		if workspaceFlag != "" {
			activeWs = workspaceFlag
		}

		ports, err := modules.ParsePortList(portsFlag)
		if err != nil {
			return fmt.Errorf("invalid port specification: %w", err)
		}

		if !jsonOutputFlag {
			pterm.DefaultHeader.WithFullWidth().Println("Falcon v3.0 Network Scanner")
			ui.PrintInfo("Target: %s | Ports: %d | Workers: %d | Workspace: %s",
				pterm.Cyan(target), len(ports), workersFlag, pterm.Yellow(activeWs))
			ui.PrintInfo("Signature Matcher: %s loaded", pterm.Green(fmt.Sprintf("%d YAML rules", globalMatcher.Count())))
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		var spinner *pterm.SpinnerPrinter
		if !jsonOutputFlag {
			spinner, _ = pterm.DefaultSpinner.Start(fmt.Sprintf("Scanning %s...", target))
		}

		// Ensure asset node exists in topology
		_ = globalStore.SaveAssetNode(activeWs, db.AssetNode{
			ID:   target,
			Name: target,
			Type: db.AssetIP,
		})

		opts := modules.ScanOptions{
			Target:    target,
			Ports:     ports,
			Workers:   workersFlag,
			TimeoutMs: timeoutFlag,
			RateLimit: rateLimitFlag,
			Workspace: activeWs,
			Store:     globalStore,
			OnOpenFound: func(rec db.PortRecord) {
				// Execute dynamic YAML signature matching
				match := globalMatcher.Identify(rec.Banner, rec.Port)
				if match.Matched {
					rec.Service = match.Service
					_ = globalStore.SavePort(activeWs, rec)
				}

				// Record in topology graph
				_ = globalStore.SaveServiceNode(activeWs, db.ServiceNode{
					ID:        fmt.Sprintf("%s:%d", target, rec.Port),
					AssetID:   target,
					Port:      rec.Port,
					Protocol:  rec.Protocol,
					Service:   rec.Service,
					Product:   match.Product,
					Version:   match.Version,
					Banner:    rec.Banner,
					LatencyMs: rec.LatencyMs,
				})

				if jsonOutputFlag {
					data, _ := json.Marshal(rec)
					fmt.Println(string(data))
				} else if spinner != nil {
					srv := rec.Service
					if match.Product != "" {
						srv = fmt.Sprintf("%s (%s %s)", rec.Service, match.Product, match.Version)
					}
					spinner.UpdateText(fmt.Sprintf("Found open port: %d [%s]", rec.Port, srv))
				}
			},
		}

		results, err := modules.RunPortScan(ctx, opts)
		if spinner != nil {
			spinner.Stop()
		}
		if err != nil {
			return err
		}

		if !jsonOutputFlag {
			if len(results) == 0 {
				ui.PrintWarning("No open ports found on target %s", target)
			} else {
				tableData := pterm.TableData{
					{"TARGET", "PORT", "STATE", "SERVICE", "LATENCY", "BANNER / IDENTIFICATION"},
				}
				for _, r := range results {
					tableData = append(tableData, []string{
						r.Target,
						fmt.Sprintf("%d/tcp", r.Port),
						pterm.Green(r.State),
						r.Service,
						fmt.Sprintf("%dms", r.LatencyMs),
						r.Banner,
					})
				}
				_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
			}
			ui.PrintSuccess("Scan complete. %d open ports recorded in workspace '%s'.", len(results), activeWs)
		}

		return nil
	},
}

var subdomainsCmd = &cobra.Command{
	Use:     "subdomains <domain>",
	Aliases: []string{"subs"},
	Short:   "Passively discover subdomains via Certificate Transparency & DNS",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		activeWs, _ := globalStore.GetActiveWorkspace()
		if workspaceFlag != "" {
			activeWs = workspaceFlag
		}

		if !jsonOutputFlag {
			pterm.DefaultHeader.WithFullWidth().Println("Falcon v3.0 Subdomain Discovery")
			ui.PrintInfo("Target Domain: %s | Workers: %d | Workspace: %s",
				pterm.Cyan(domain), workersFlag, pterm.Yellow(activeWs))
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		var spinner *pterm.SpinnerPrinter
		if !jsonOutputFlag {
			spinner, _ = pterm.DefaultSpinner.Start(fmt.Sprintf("Querying CT logs for %s...", domain))
		}

		// Save root domain asset in topology
		_ = globalStore.SaveAssetNode(activeWs, db.AssetNode{
			ID:   domain,
			Name: domain,
			Type: db.AssetDomain,
		})

		opts := modules.SubdomainOptions{
			Domain:     domain,
			Workers:    workersFlag,
			TimeoutSec: 15,
			Workspace:  activeWs,
			Store:      globalStore,
			OnSubFound: func(rec db.SubdomainRecord) {
				// Record child domain & IPs in topology graph
				_ = globalStore.SaveAssetNode(activeWs, db.AssetNode{
					ID:       rec.Subdomain,
					Name:     rec.Subdomain,
					Type:     db.AssetDomain,
					ParentID: domain,
				})
				for _, ip := range rec.IPs {
					_ = globalStore.SaveAssetNode(activeWs, db.AssetNode{
						ID:       ip,
						Name:     ip,
						Type:     db.AssetIP,
						ParentID: rec.Subdomain,
					})
				}

				if jsonOutputFlag {
					data, _ := json.Marshal(rec)
					fmt.Println(string(data))
				} else if spinner != nil && len(rec.IPs) > 0 {
					spinner.UpdateText(fmt.Sprintf("Resolved: %s -> %s", rec.Subdomain, strings.Join(rec.IPs, ", ")))
				}
			},
		}

		results, err := modules.DiscoverSubdomains(ctx, opts)
		if spinner != nil {
			spinner.Stop()
		}
		if err != nil {
			return err
		}

		if !jsonOutputFlag {
			if len(results) == 0 {
				ui.PrintWarning("No subdomains discovered for %s", domain)
			} else {
				tableData := pterm.TableData{
					{"SUBDOMAIN", "RESOLVED IPS", "SOURCE"},
				}
				for _, r := range results {
					ipStr := pterm.Red("Unresolved")
					if len(r.IPs) > 0 {
						ipStr = pterm.Green(strings.Join(r.IPs, ", "))
					}
					tableData = append(tableData, []string{
						r.Subdomain,
						ipStr,
						r.Source,
					})
				}
				_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
			}
			ui.PrintSuccess("Discovered %d subdomains saved to workspace '%s'.", len(results), activeWs)
		}

		return nil
	},
}

var topologyCmd = &cobra.Command{
	Use:   "topology [view | json]",
	Short: "Render or export the target asset topology graph",
	RunE: func(cmd *cobra.Command, args []string) error {
		activeWs, _ := globalStore.GetActiveWorkspace()
		if workspaceFlag != "" {
			activeWs = workspaceFlag
		}

		graph, err := globalStore.GetTopologyGraph(activeWs)
		if err != nil {
			return err
		}

		if len(args) > 0 && args[0] == "json" {
			data, _ := json.MarshalIndent(graph, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		pterm.DefaultHeader.WithFullWidth().Println("Falcon v3.0 Topology Graph")
		fmt.Println(db.RenderTopologyTree(graph))
		return nil
	},
}

var workspaceCmd = &cobra.Command{
	Use:     "workspace [list | set <name>]",
	Aliases: []string{"ws"},
	Short:   "Manage and inspect workspaces",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || args[0] == "list" {
			list, err := globalStore.ListWorkspaces()
			if err != nil {
				return err
			}
			current, _ := globalStore.GetActiveWorkspace()
			tableData := pterm.TableData{{"WORKSPACE", "STATUS"}}
			for _, w := range list {
				status := "Inactive"
				if w == current {
					status = pterm.Green("Active (*)")
				}
				tableData = append(tableData, []string{w, status})
			}
			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		}

		if args[0] == "set" || args[0] == "new" {
			if len(args) < 2 {
				return fmt.Errorf("workspace name required: falcon workspace set <name>")
			}
			name := args[1]
			if err := globalStore.SetActiveWorkspace(name); err != nil {
				return err
			}
			ui.PrintSuccess("Active workspace set to: %s", pterm.Yellow(name))
			return nil
		}

		return fmt.Errorf("unknown workspace action '%s'", args[0])
	},
}

var showCmd = &cobra.Command{
	Use:   "show <ports | subdomains>",
	Short: "Display recorded findings for the current or specified workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		category := strings.ToLower(args[0])
		activeWs, _ := globalStore.GetActiveWorkspace()
		if workspaceFlag != "" {
			activeWs = workspaceFlag
		}

		switch category {
		case "ports", "port":
			ports, err := globalStore.GetPorts(activeWs)
			if err != nil {
				return err
			}
			if len(ports) == 0 {
				ui.PrintInfo("No ports recorded in workspace '%s'.", activeWs)
				return nil
			}
			tableData := pterm.TableData{
				{"TARGET", "PORT", "STATE", "SERVICE", "BANNER", "DISCOVERED"},
			}
			for _, p := range ports {
				tableData = append(tableData, []string{
					p.Target,
					fmt.Sprintf("%d/tcp", p.Port),
					pterm.Green(p.State),
					p.Service,
					p.Banner,
					p.Timestamp,
				})
			}
			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

		case "subdomains", "subs":
			subs, err := globalStore.GetSubdomains(activeWs)
			if err != nil {
				return err
			}
			if len(subs) == 0 {
				ui.PrintInfo("No subdomains recorded in workspace '%s'.", activeWs)
				return nil
			}
			tableData := pterm.TableData{
				{"DOMAIN", "SUBDOMAIN", "IPS", "SOURCE"},
			}
			for _, s := range subs {
				tableData = append(tableData, []string{
					s.Domain,
					s.Subdomain,
					strings.Join(s.IPs, ", "),
					s.Source,
				})
			}
			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

		default:
			return fmt.Errorf("invalid show argument '%s'. Use 'ports' or 'subdomains'", category)
		}
	},
}

var exportCmd = &cobra.Command{
	Use:   "export <json|csv> [ports|subdomains] <filepath>",
	Short: "Export workspace data to JSON or CSV file",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		activeWs, _ := globalStore.GetActiveWorkspace()
		if workspaceFlag != "" {
			activeWs = workspaceFlag
		}

		format := strings.ToLower(args[0])
		switch format {
		case "json":
			outPath := args[1]
			if err := globalStore.ExportJSON(activeWs, outPath); err != nil {
				return err
			}
			ui.PrintSuccess("Workspace '%s' data exported to: %s", activeWs, outPath)
			return nil

		case "csv":
			if len(args) < 3 {
				return fmt.Errorf("usage: falcon export csv <ports|subdomains> <filepath>")
			}
			category := strings.ToLower(args[1])
			outPath := args[2]
			if err := globalStore.ExportCSV(activeWs, category, outPath); err != nil {
				return err
			}
			ui.PrintSuccess("Exported %s from workspace '%s' to: %s", category, activeWs, outPath)
			return nil

		default:
			return fmt.Errorf("unsupported format '%s'. Use 'json' or 'csv'", format)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "falcon_data.db", "Path to local embedded database")
	rootCmd.PersistentFlags().StringVarP(&workspaceFlag, "workspace", "W", "", "Override active workspace")

	scanCmd.Flags().StringVarP(&portsFlag, "ports", "p", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443", "Ports to probe (e.g. 80,443 or 1-1024)")
	scanCmd.Flags().IntVarP(&workersFlag, "workers", "w", 50, "Number of concurrent worker goroutines")
	scanCmd.Flags().IntVarP(&timeoutFlag, "timeout", "t", 800, "Per-target timeout in milliseconds")
	scanCmd.Flags().IntVarP(&rateLimitFlag, "rate", "r", 0, "Rate limit per second (0 = unlimited)")
	scanCmd.Flags().BoolVar(&jsonOutputFlag, "json", false, "Output results as streaming JSON")

	subdomainsCmd.Flags().IntVarP(&workersFlag, "workers", "w", 25, "Number of concurrent DNS resolver workers")
	subdomainsCmd.Flags().BoolVar(&jsonOutputFlag, "json", false, "Output results as streaming JSON")

	rootCmd.AddCommand(tuiCmd)
	rootCmd.AddCommand(replCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(subdomainsCmd)
	rootCmd.AddCommand(topologyCmd)
	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(exportCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
