package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"falcon/internal/db"
	"falcon/internal/modules"
	"falcon/internal/ui"

	"github.com/chzyer/readline"
	"github.com/pterm/pterm"
)

// Shell encapsulates the interactive REPL state and DB store.
type Shell struct {
	store     *db.Store
	workspace string
	rl        *readline.Instance
}

// StartInteractive initializes the interactive REPL environment.
func StartInteractive(store *db.Store) error {
	ws, err := store.GetActiveWorkspace()
	if err != nil || ws == "" {
		ws = "default"
	}

	historyFile := filepath.Join(os.TempDir(), ".falcon_history")

	completer := readline.NewPrefixCompleter(
		readline.PcItem("scan"),
		readline.PcItem("subdomains"),
		readline.PcItem("workspace",
			readline.PcItem("list"),
			readline.PcItem("set"),
			readline.PcItem("new"),
		),
		readline.PcItem("show",
			readline.PcItem("ports"),
			readline.PcItem("subdomains"),
		),
		readline.PcItem("export",
			readline.PcItem("json"),
			readline.PcItem("csv",
				readline.PcItem("ports"),
				readline.PcItem("subdomains"),
			),
		),
		readline.PcItem("help"),
		readline.PcItem("clear"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          ui.FormatPrompt(ws),
		HistoryFile:     historyFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize readline shell: %w", err)
	}
	defer rl.Close()

	sh := &Shell{
		store:     store,
		workspace: ws,
		rl:        rl,
	}

	ui.PrintBanner()
	ui.PrintInfo("Active Workspace: %s", pterm.Yellow(ws))

	// Listen for termination signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigCh {
			fmt.Println()
			ui.PrintWarning("Use 'exit' or 'quit' to close Falcon Shell.")
			sh.rl.Refresh()
		}
	}()

	for {
		line, err := sh.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				break
			}
			ui.PrintError("Read error: %v", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			ui.PrintInfo("Shutting down Falcon session. Goodbye!")
			break
		}

		sh.executeCommand(line)
	}

	return nil
}

// executeCommand routes input commands to the respective action.
func (sh *Shell) executeCommand(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help":
		sh.showHelp()
	case "clear", "cls":
		print("\033[H\033[2J")
	case "workspace", "ws":
		sh.handleWorkspace(args)
	case "scan":
		sh.handleScan(args)
	case "subdomains", "subs":
		sh.handleSubdomains(args)
	case "show":
		sh.handleShow(args)
	case "export":
		sh.handleExport(args)
	default:
		ui.PrintError("Unknown command '%s'. Type 'help' for available commands.", cmd)
	}
}

// showHelp displays interactive shell commands and usage.
func (sh *Shell) showHelp() {
	tableData := pterm.TableData{
		{"COMMAND", "ARGUMENTS", "DESCRIPTION"},
		{"scan", "<target> [-p 80,443] [-w 50]", "Perform high-speed TCP socket & HTTP probe"},
		{"subdomains", "<domain> [-w 25]", "Passive subdomain discovery via CT logs + DNS"},
		{"workspace", "list | set <name> | new <name>", "Manage and switch active workspaces"},
		{"show", "ports | subdomains", "Display recorded reconnaissance findings for active workspace"},
		{"export", "json <file> | csv <category> <file>", "Export workspace data to JSON or CSV format"},
		{"clear", "", "Clear terminal screen"},
		{"help", "", "Display this help menu"},
		{"exit / quit", "", "Exit interactive Falcon REPL shell"},
	}

	_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}

// handleWorkspace manages workspace switching and listing.
func (sh *Shell) handleWorkspace(args []string) {
	if len(args) == 0 {
		ui.PrintInfo("Active workspace: %s", pterm.Yellow(sh.workspace))
		return
	}

	subCmd := strings.ToLower(args[0])
	switch subCmd {
	case "list":
		list, err := sh.store.ListWorkspaces()
		if err != nil {
			ui.PrintError("Failed to list workspaces: %v", err)
			return
		}
		tableData := pterm.TableData{{"WORKSPACE", "STATUS"}}
		for _, w := range list {
			status := "Inactive"
			if w == sh.workspace {
				status = pterm.Green("Active (*)")
			}
			tableData = append(tableData, []string{w, status})
		}
		_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

	case "set", "use", "new":
		if len(args) < 2 {
			ui.PrintWarning("Usage: workspace %s <name>", subCmd)
			return
		}
		name := args[1]
		if err := sh.store.SetActiveWorkspace(name); err != nil {
			ui.PrintError("Failed to set workspace: %v", err)
			return
		}
		sh.workspace = name
		sh.rl.SetPrompt(ui.FormatPrompt(name))
		ui.PrintSuccess("Workspace switched to: %s", pterm.Yellow(name))

	default:
		ui.PrintWarning("Unknown workspace action '%s'. Use 'list' or 'set <name>'.", subCmd)
	}
}

// handleScan parses scan flags and executes the port scanner.
func (sh *Shell) handleScan(args []string) {
	if len(args) == 0 {
		ui.PrintWarning("Usage: scan <target> [-p ports] [-w workers] [-t timeout_ms] [-r rate_limit]")
		return
	}

	target := args[0]
	portsSpec := "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443"
	workers := 50
	timeoutMs := 800
	rateLimit := 0

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-p", "--ports":
			if i+1 < len(args) {
				portsSpec = args[i+1]
				i++
			}
		case "-w", "--workers":
			if i+1 < len(args) {
				if w, err := strconv.Atoi(args[i+1]); err == nil && w > 0 {
					workers = w
				}
				i++
			}
		case "-t", "--timeout":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil && t > 0 {
					timeoutMs = t
				}
				i++
			}
		case "-r", "--rate":
			if i+1 < len(args) {
				if r, err := strconv.Atoi(args[i+1]); err == nil && r >= 0 {
					rateLimit = r
				}
				i++
			}
		}
	}

	ports, err := modules.ParsePortList(portsSpec)
	if err != nil {
		ui.PrintError("Invalid port specification: %v", err)
		return
	}

	ui.PrintInfo("Probing target: %s (%d ports | %d workers | %dms timeout)",
		pterm.Cyan(target), len(ports), workers, timeoutMs)

	spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Scanning %s...", target))

	var liveFound int
	opts := modules.ScanOptions{
		Target:    target,
		Ports:     ports,
		Workers:   workers,
		TimeoutMs: timeoutMs,
		RateLimit: rateLimit,
		Workspace: sh.workspace,
		Store:     sh.store,
		OnOpenFound: func(rec db.PortRecord) {
			liveFound++
			if spinner != nil {
				spinner.UpdateText(fmt.Sprintf("Discovered open port: %d (%s) - %s", rec.Port, rec.Service, rec.Target))
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := modules.RunPortScan(ctx, opts)
	if spinner != nil {
		spinner.Stop()
	}

	if err != nil {
		ui.PrintError("Port scan failed: %v", err)
		return
	}

	if len(results) == 0 {
		ui.PrintWarning("No open ports found on target %s", target)
		return
	}

	tableData := pterm.TableData{
		{"TARGET", "PORT", "STATE", "SERVICE", "LATENCY", "BANNER"},
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
	ui.PrintSuccess("Scan finished: %d open ports recorded into workspace '%s'", len(results), sh.workspace)
}

// handleSubdomains discovers passive subdomains and DNS records.
func (sh *Shell) handleSubdomains(args []string) {
	if len(args) == 0 {
		ui.PrintWarning("Usage: subdomains <domain> [-w workers]")
		return
	}

	domain := args[0]
	workers := 25

	for i := 1; i < len(args); i++ {
		if (args[i] == "-w" || args[i] == "--workers") && i+1 < len(args) {
			if w, err := strconv.Atoi(args[i+1]); err == nil && w > 0 {
				workers = w
			}
			i++
		}
	}

	ui.PrintInfo("Querying Certificate Transparency & DNS for: %s", pterm.Cyan(domain))
	spinner, _ := pterm.DefaultSpinner.Start("Aggregating subdomains...")

	opts := modules.SubdomainOptions{
		Domain:     domain,
		Workers:    workers,
		TimeoutSec: 15,
		Workspace:  sh.workspace,
		Store:      sh.store,
		OnSubFound: func(rec db.SubdomainRecord) {
			if len(rec.IPs) > 0 && spinner != nil {
				spinner.UpdateText(fmt.Sprintf("Resolved: %s -> %s", rec.Subdomain, strings.Join(rec.IPs, ", ")))
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := modules.DiscoverSubdomains(ctx, opts)
	if spinner != nil {
		spinner.Stop()
	}

	if err != nil {
		ui.PrintError("Subdomain discovery failed: %v", err)
		return
	}

	if len(results) == 0 {
		ui.PrintWarning("No subdomains discovered for %s", domain)
		return
	}

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
	ui.PrintSuccess("Discovered %d subdomains saved to workspace '%s'", len(results), sh.workspace)
}

// handleShow queries and prints stored data from the current workspace.
func (sh *Shell) handleShow(args []string) {
	if len(args) == 0 {
		ui.PrintWarning("Usage: show <ports | subdomains>")
		return
	}

	category := strings.ToLower(args[0])
	switch category {
	case "ports", "port":
		ports, err := sh.store.GetPorts(sh.workspace)
		if err != nil {
			ui.PrintError("Failed to load ports: %v", err)
			return
		}
		if len(ports) == 0 {
			ui.PrintInfo("No ports recorded in workspace '%s'. Run 'scan <target>' first.", sh.workspace)
			return
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
		_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

	case "subdomains", "subs":
		subs, err := sh.store.GetSubdomains(sh.workspace)
		if err != nil {
			ui.PrintError("Failed to load subdomains: %v", err)
			return
		}
		if len(subs) == 0 {
			ui.PrintInfo("No subdomains recorded in workspace '%s'. Run 'subdomains <domain>' first.", sh.workspace)
			return
		}
		tableData := pterm.TableData{
			{"DOMAIN", "SUBDOMAIN", "IPS", "SOURCE"},
		}
		for _, s := range subs {
			ipStr := strings.Join(s.IPs, ", ")
			if ipStr == "" {
				ipStr = "Unresolved"
			}
			tableData = append(tableData, []string{
				s.Domain,
				s.Subdomain,
				ipStr,
				s.Source,
			})
		}
		_ = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

	default:
		ui.PrintWarning("Unknown show target '%s'. Use 'ports' or 'subdomains'.", category)
	}
}

// handleExport writes workspace data to disk in JSON or CSV format.
func (sh *Shell) handleExport(args []string) {
	if len(args) < 2 {
		ui.PrintWarning("Usage: export json <filepath> OR export csv <ports|subdomains> <filepath>")
		return
	}

	format := strings.ToLower(args[0])
	switch format {
	case "json":
		filePath := args[1]
		if err := sh.store.ExportJSON(sh.workspace, filePath); err != nil {
			ui.PrintError("Export to JSON failed: %v", err)
			return
		}
		ui.PrintSuccess("Workspace '%s' data successfully exported to: %s", sh.workspace, filePath)

	case "csv":
		if len(args) < 3 {
			ui.PrintWarning("Usage: export csv <ports|subdomains> <filepath>")
			return
		}
		category := strings.ToLower(args[1])
		filePath := args[2]
		if err := sh.store.ExportCSV(sh.workspace, category, filePath); err != nil {
			ui.PrintError("Export to CSV failed: %v", err)
			return
		}
		ui.PrintSuccess("Exported %s from workspace '%s' to: %s", category, sh.workspace, filePath)

	default:
		ui.PrintWarning("Unsupported format '%s'. Use 'json' or 'csv'.", format)
	}
}
