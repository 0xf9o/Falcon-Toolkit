package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/falcon-toolkit/falcon/internal/core"
	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/engine/active"
	"github.com/falcon-toolkit/falcon/internal/engine/firewall"
	"github.com/falcon-toolkit/falcon/internal/engine/passive"
	"github.com/falcon-toolkit/falcon/internal/engine/recon"
	"github.com/falcon-toolkit/falcon/internal/engine/tunneling"
	"github.com/falcon-toolkit/falcon/internal/exporter"
	"github.com/falcon-toolkit/falcon/internal/graph"
	"github.com/falcon-toolkit/falcon/internal/schema"
	"github.com/olekukonko/tablewriter"
)

// REPL is the interactive shell driver for the Falcon Toolkit.
type REPL struct {
	session *core.Session
	rl      *readline.Instance
	server  *recon.LiveServer
}

// NewREPL initializes the interactive command line environment.
func NewREPL(session *core.Session) (*REPL, error) {
	completer := readline.NewPrefixCompleter(
		readline.PcItem("target",
			readline.PcItem("add"),
			readline.PcItem("list"),
			readline.PcItem("remove"),
			readline.PcItem("clear"),
		),
		readline.PcItem("scope",
			readline.PcItem("add",
				readline.PcItem("include"),
				readline.PcItem("exclude"),
			),
			readline.PcItem("list"),
			readline.PcItem("check"),
		),
		readline.PcItem("workspace",
			readline.PcItem("list"),
			readline.PcItem("use"),
			readline.PcItem("create"),
			readline.PcItem("status"),
		),
		readline.PcItem("graph",
			readline.PcItem("path"),
			readline.PcItem("blast"),
			readline.PcItem("summary"),
		),
		readline.PcItem("analyze"),
		readline.PcItem("serve",
			readline.PcItem("--port"),
		),
		readline.PcItem("evidence",
			readline.PcItem("list"),
			readline.PcItem("add"),
		),
		readline.PcItem("set",
			readline.PcItem("targets"),
			readline.PcItem("profile",
				readline.PcItem("zero-trust-audit"),
				readline.PcItem("active-directory-reachability"),
				readline.PcItem("ot-scada-posture"),
				readline.PcItem("default"),
			),
			readline.PcItem("rate"),
			readline.PcItem("workers"),
		),
		readline.PcItem("run",
			readline.PcItem("audit",
				readline.PcItem("--evasion"),
				readline.PcItem("--passive"),
			),
			readline.PcItem("egress",
				readline.PcItem("--dns"),
				readline.PcItem("--ports"),
			),
			readline.PcItem("firewall",
				readline.PcItem("--host"),
				readline.PcItem("--port"),
			),
		),
		readline.PcItem("show",
			readline.PcItem("matrix"),
			readline.PcItem("posture"),
			readline.PcItem("targets"),
			readline.PcItem("config"),
			readline.PcItem("identities"),
			readline.PcItem("drifts"),
			readline.PcItem("evidence"),
			readline.PcItem("scope"),
		),
		readline.PcItem("simulate",
			readline.PcItem("rule",
				readline.PcItem("--block"),
			),
		),
		readline.PcItem("export",
			readline.PcItem("all",
				readline.PcItem("--format"),
				readline.PcItem("--out-dir"),
			),
		),
		readline.PcItem("clear"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)

	cfg := &readline.Config{
		Prompt:          "falcon [ctx: none] > ",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}

	rl, err := readline.NewEx(cfg)
	if err != nil {
		return nil, fmt.Errorf("initializing readline: %w", err)
	}

	return &REPL{
		session: session,
		rl:      rl,
	}, nil
}

// Run starts the REPL input loop.
func (r *REPL) Run() error {
	defer r.rl.Close()

	for {
		r.updatePrompt()
		line, err := r.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				break
			}
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "exit", "quit":
			fmt.Println("Shutting down Falcon session. Goodbye.")
			return nil

		case "clear":
			readline.ClearScreen(os.Stdout)

		case "help":
			r.printHelp()

		case "target":
			r.handleTarget(parts[1:])

		case "scope":
			r.handleScope(parts[1:])

		case "workspace":
			r.handleWorkspace(parts[1:])

		case "graph":
			r.handleGraph(parts[1:])

		case "analyze":
			r.handleAnalyze(parts[1:])

		case "serve":
			r.handleServe(parts[1:])

		case "evidence":
			r.handleEvidence(parts[1:])

		case "set":
			r.handleSet(parts[1:])

		case "show":
			r.handleShow(parts[1:])

		case "run":
			r.handleRun(parts[1:])

		case "simulate":
			r.handleSimulate(parts[1:])

		case "export":
			r.handleExport(parts[1:])

		default:
			fmt.Printf("Unknown command %q. Type 'help' for command reference.\n", cmd)
		}
	}
	return nil
}

func (r *REPL) updatePrompt() {
	targets := r.session.GetTargets()
	ctxLabel := "none"
	if len(targets) > 0 {
		ctxLabel = targets[0]
		if len(targets) > 1 {
			ctxLabel += fmt.Sprintf(" (+%d)", len(targets)-1)
		}
	}
	ws := r.session.WorkspaceName
	if ws == "" {
		ws = "default"
	}
	r.rl.SetPrompt(fmt.Sprintf("\033[1;32mfalcon\033[0m [\033[1;36mws: %s\033[0m | \033[1;34mctx: %s\033[0m] > ", ws, ctxLabel))
}

func (r *REPL) printHelp() {
	fmt.Print(`
FALCON TOOLKIT — COMMAND REFERENCE
================================================================================
WORKSPACE & SCOPE MANAGEMENT:
  workspace <list|use <name>|create <name>|status>   Manage operational environments
  scope <list|add include|add exclude|check <ip>>     Define and enforce strict scope boundaries
  target <add <val>|list|remove <val>|clear>          Configure and validate assessment targets

CONFIGURATION:
  set targets <cidr/ip/range...>  Define active assessment target scopes
  set profile <name>              Select audit profile (zero-trust, active-directory, ot-scada)
  set rate <pps>                  Configure probe transmission rate (packets/sec)
  set workers <count>             Configure concurrent worker pool size

EXECUTION & AUDIT:
  run audit [--evasion] [--passive] Execute live active L4/L7 discovery & segmentation audit
  run egress [--dns <ip>] [--ports] Test outbound filtering permissiveness and path MTU
  run firewall --host <ip> --port <p> Test for stateful vs stateless ACLs and port 53/88 bypass

INTELLIGENCE & ANALYSIS:
  analyze                         Correlate observations, classify identities, and score attack surface
  serve [--port <p>]              Launch embedded live interactive web topology & HUD dashboard
  graph path <source> <dest>      Trace shortest multi-hop lateral movement trajectory
  graph blast <node/cidr>         Compute blast radius score and dependency impact
  graph summary                   Display topology graph metrics and connectivity density
  evidence <list|add>             Inspect and append empirical intelligence records

INSPECTION:
  show matrix                     Render ASCII reachability matrix & blast radius table
  show posture <cidr>             Display in-depth port observations and TLS certificates
  show targets                    List parsed target scopes in current session
  show identities                 Display fused asset identities (IP, MAC, Hostname, AD Domain)
  show drifts                     Display detected MAC/hostname/IP drift events
  show scope                      Display active scope rules (inclusions and exclusions)
  show evidence                   Display collected empirical evidence
  show config                     Display current session parameters

ANALYSIS & SIMULATION:
  simulate rule --block --port <p> Model hypothetical ACL drops and test blast mitigation

EXPORTERS:
  export all [--format <f>] [--out-dir <d>] Export HTML graph, JSON, Markdown, and firewall ACLs

GENERAL:
  clear                           Clear screen
  help                            Show this help menu
  exit / quit                     Terminate session
`)
}

func (r *REPL) handleTarget(args []string) {
	if len(args) == 0 {
		r.handleShow([]string{"targets"})
		return
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: target add <cidr|ip|range|domain>")
			return
		}
		for _, raw := range args[1:] {
			added, err := r.session.AddTarget(raw)
			if err != nil {
				fmt.Printf("\033[1;31mError adding target %q:\033[0m %v\n", raw, err)
				continue
			}
			// Validate against Scope Guard
			if err := r.session.ValidateTarget(raw); err != nil {
				fmt.Printf("\033[1;33m[!] Warning:\033[0m Target %s added but restricted by Scope Guard: %v\n", raw, err)
			} else {
				fmt.Printf("\033[1;32m✓ Target added:\033[0m %s (Total active targets: %d)\n", raw, len(added))
			}
		}

	case "list", "ls":
		r.handleShow([]string{"targets"})

	case "remove", "rm":
		if len(args) < 2 {
			fmt.Println("Usage: target remove <pattern>")
			return
		}
		target := args[1]
		if r.session.RemoveTarget(target) {
			fmt.Printf("\033[1;32m✓ Target %q removed.\033[0m\n", target)
		} else {
			fmt.Printf("Target %q not found in active targets.\n", target)
		}

	case "clear":
		r.session.ClearTargets()
		fmt.Println("\033[1;32m✓ All targets cleared.\033[0m")

	default:
		// Direct target specification syntax
		r.handleTarget(append([]string{"add"}, args...))
	}
}

func (r *REPL) handleScope(args []string) {
	if len(args) == 0 {
		r.handleShow([]string{"scope"})
		return
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "add":
		if len(args) < 3 {
			fmt.Println("Usage: scope add <include|exclude> <pattern> [description]")
			return
		}
		kind := strings.ToLower(args[1])
		pattern := args[2]
		desc := ""
		if len(args) > 3 {
			desc = strings.Join(args[3:], " ")
		}

		var ruleType domain.ScopeRuleType
		switch kind {
		case "include", "inc":
			ruleType = domain.ScopeInclude
		case "exclude", "exc":
			ruleType = domain.ScopeExclude
		default:
			fmt.Println("Invalid scope rule kind. Use 'include' or 'exclude'.")
			return
		}

		r.session.AddScopeRule(ruleType, pattern, desc)
		fmt.Printf("\033[1;32m✓ Scope rule added:\033[0m %s %s (%s)\n", strings.ToUpper(string(ruleType)), pattern, desc)

	case "list", "ls":
		r.handleShow([]string{"scope"})

	case "check":
		if len(args) < 2 {
			fmt.Println("Usage: scope check <ip|cidr|hostname>")
			return
		}
		target := args[1]
		err := r.session.ValidateTarget(target)
		if err != nil {
			fmt.Printf("\033[1;31m[BLOCKED]\033[0m %s is OUT OF SCOPE: %v\n", target, err)
		} else {
			fmt.Printf("\033[1;32m[PERMITTED]\033[0m %s is strictly IN SCOPE.\n", target)
		}

	default:
		fmt.Printf("Unknown scope command %q. Valid: add, list, check.\n", sub)
	}
}

func (r *REPL) handleWorkspace(args []string) {
	if len(args) == 0 {
		r.handleWorkspace([]string{"status"})
		return
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "list", "ls":
		fmt.Println("\nWORKSPACES:")
		fmt.Printf("  * %s (Active)\n\n", r.session.WorkspaceName)

	case "use":
		if len(args) < 2 {
			fmt.Println("Usage: workspace use <name>")
			return
		}
		name := args[1]
		r.session.WorkspaceID = name
		r.session.WorkspaceName = name
		fmt.Printf("\033[1;32m✓ Switched to workspace:\033[0m %s\n", name)

	case "create":
		if len(args) < 2 {
			fmt.Println("Usage: workspace create <name>")
			return
		}
		name := args[1]
		r.session.WorkspaceID = name
		r.session.WorkspaceName = name
		fmt.Printf("\033[1;32m✓ Created and activated workspace:\033[0m %s\n", name)

	case "status":
		targets := r.session.GetTargets()
		postures := r.session.GetAllPostures()
		identities := r.session.GetIdentities()
		evidence := r.session.GetEvidence()
		rules := r.session.GetScopeRules()

		fmt.Printf("\nWORKSPACE STATUS: %s (ID: %s)\n", r.session.WorkspaceName, r.session.WorkspaceID)
		fmt.Printf("  Active Target Scopes : %d\n", len(targets))
		fmt.Printf("  Scope Guard Rules    : %d\n", len(rules))
		fmt.Printf("  Evaluated Subnets    : %d\n", len(postures))
		fmt.Printf("  Fused Identities     : %d\n", len(identities))
		fmt.Printf("  Evidence Records     : %d\n\n", len(evidence))

	default:
		fmt.Printf("Unknown workspace command %q. Valid: list, use, create, status.\n", sub)
	}
}

func (r *REPL) handleGraph(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: graph <path <source> <dest> | blast <node> | summary>")
		return
	}

	sub := strings.ToLower(args[0])
	postures := r.session.GetAllPostures()
	g := graph.BuildSubnetGraph(postures)

	switch sub {
	case "path":
		if len(args) < 3 {
			fmt.Println("Usage: graph path <source> <dest>")
			return
		}
		src := args[1]
		dst := args[2]

		detailed := g.DetailedPath(src, dst)
		if detailed == nil {
			// Try finding with plain BFS
			p := g.ShortestPath(src, dst)
			if len(p) == 0 {
				fmt.Printf("\033[1;33m[!] No viable attack or reachability path found between %s and %s in the current topology.\033[0m\n", src, dst)
				return
			}
			fmt.Printf("\n\033[1;32m✓ Reachability Path Found (%d hops):\033[0m\n", len(p)-1)
			fmt.Printf("  %s\n\n", strings.Join(p, " ➔ "))
			return
		}

		fmt.Printf("\n\033[1;32m✓ Lateral Movement Path Found (%d hops):\033[0m %s ➔ %s\n", detailed.Hops, src, dst)
		table := tablewriter.NewTable(os.Stdout)
		table.Header("Hop", "From Node", "To Node", "Vector / Edge Type", "Target Classification")

		for i, step := range detailed.Steps {
			toKind := "Host / Service"
			if step.ToNode != nil && step.ToNode.Type != "" {
				toKind = string(step.ToNode.Type)
			}
			_ = table.Append([]any{
				fmt.Sprintf("%d", i+1),
				step.FromNode.ID,
				step.ToNode.ID,
				string(step.EdgeType),
				toKind,
			})
		}
		_ = table.Render()
		fmt.Println()

	case "blast":
		node := ""
		if len(args) > 1 {
			node = args[1]
		}
		if node != "" {
			p, ok := r.session.GetPosture(node)
			if ok {
				fmt.Printf("\nBLAST RADIUS ASSESSMENT: %s\n", node)
				fmt.Printf("  Blast Score     : %.1f / 10.0\n", p.BlastScore)
				fmt.Printf("  Exposed Hosts   : %d\n", len(p.ExposedHosts))
				fmt.Printf("  Total Services  : %d\n", len(p.ProbedServices))
				fmt.Printf("  Compliance      : %s\n\n", p.Compliance)
				return
			}
		}
		r.handleShow([]string{"matrix"})

	case "summary":
		stats := g.Stats()
		fmt.Println("\nTOPOLOGY GRAPH SUMMARY:")
		fmt.Printf("  Total Nodes       : %d\n", stats.TotalNodes)
		fmt.Printf("  Total Edges       : %d\n", stats.TotalEdges)
		fmt.Printf("  Subnet Segments   : %d\n", len(postures))
		fmt.Printf("  Fused Identities  : %d\n\n", len(r.session.GetIdentities()))

	default:
		fmt.Printf("Unknown graph command %q. Valid: path, blast, summary.\n", sub)
	}
}

func (r *REPL) handleAnalyze(args []string) {
	postures := r.session.GetAllPostures()
	identities := r.session.GetIdentities()

	filterScope := ""
	if len(args) > 0 {
		filterScope = strings.ToLower(args[0])
	}

	if len(postures) == 0 && len(identities) == 0 {
		fmt.Println("\033[1;33m[!] No posture evaluations or identities recorded. Run 'run audit' first.\033[0m")
		return
	}

	fmt.Println("\n================================================================================")
	fmt.Println("FALCON TOOLKIT — NETWORK INTELLIGENCE & POSTURE ANALYSIS REPORT")
	fmt.Println("================================================================================")

	var highRiskCount, passCount, failCount int
	var criticalAssets []string

	for cidr, p := range postures {
		if filterScope != "" && !strings.Contains(strings.ToLower(cidr), filterScope) {
			continue
		}
		if p.Compliance == "FAIL" {
			failCount++
		} else {
			passCount++
		}
		if p.BlastScore >= 5.0 {
			highRiskCount++
			criticalAssets = append(criticalAssets, fmt.Sprintf("%s (Score: %.1f)", cidr, p.BlastScore))
		}
	}

	fmt.Printf("  Audited Subnets      : %d\n", len(postures))
	fmt.Printf("  Compliant Segments   : \033[1;32m%d PASS\033[0m\n", passCount)
	fmt.Printf("  Non-Compliant Segments: \033[1;31m%d FAIL\033[0m\n", failCount)
	fmt.Printf("  High Blast Radius Hubs: \033[1;33m%d\033[0m\n", highRiskCount)
	fmt.Printf("  Fused Asset Identities: %d\n\n", len(identities))

	if len(criticalAssets) > 0 {
		fmt.Println("CRITICAL ATTACK-SURFACE HUBS:")
		for _, h := range criticalAssets {
			fmt.Printf("  • %s\n", h)
		}
		fmt.Println()
	}

	drifts := r.session.GetIdentityDrifts()
	if len(drifts) > 0 {
		fmt.Printf("\033[1;33m[!] DETECTED IDENTITY DRIFT EVENTS (%d):\033[0m\n", len(drifts))
		for _, d := range drifts {
			fmt.Printf("  • [%s] %s ➔ %s\n", d.IdentityID, d.Description, d.DetectedAt.Format(time.RFC3339))
		}
		fmt.Println()
	}

	fmt.Println("RECOMMENDATIONS:")
	if highRiskCount > 0 {
		fmt.Println("  1. Apply micro-segmentation ACLs to isolate critical management and AD ports (88, 389, 445).")
		fmt.Println("  2. Restrict lateral connectivity between user subnets and sensitive database/SCADA infrastructure.")
	} else {
		fmt.Println("  1. Current segmentation demonstrates strong isolation across evaluated boundaries.")
	}
	fmt.Println()
}

func (r *REPL) handleEvidence(args []string) {
	if len(args) == 0 {
		r.handleShow([]string{"evidence"})
		return
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "list", "ls":
		r.handleShow([]string{"evidence"})

	case "add":
		if len(args) < 3 {
			fmt.Println("Usage: evidence add <target> <kind> <details...>")
			return
		}
		target := args[1]
		kind := args[2]
		details := strings.Join(args[3:], " ")

		r.session.AddEvidence(domain.Evidence{
			WorkspaceID: r.session.WorkspaceID,
			Address:     target,
			Category:    domain.EvidenceManual,
			Confidence:  domain.ConfidenceHigh,
			Description: details,
			ObservedAt:  time.Now().UTC(),
		})
		fmt.Printf("\033[1;32m✓ Evidence recorded for %s:\033[0m [%s] %s\n", target, kind, details)

	default:
		fmt.Printf("Unknown evidence action %q. Valid: list, add.\n", sub)
	}
}

func (r *REPL) handleSet(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: set <targets|profile|rate|workers> <value>")
		return
	}

	sub := strings.ToLower(args[0])
	val := args[1:]

	switch sub {
	case "targets", "target":
		expanded, err := r.session.SetTargets(val)
		if err != nil {
			fmt.Printf("\033[1;31mError setting targets:\033[0m %v\n", err)
			return
		}
		fmt.Printf("\033[1;32m✓ Targets updated:\033[0m %d scopes configured (%s)\n",
			len(expanded), strings.Join(expanded, ", "))

	case "profile":
		p := strings.ToLower(val[0])
		r.session.SetProfile(p)
		fmt.Printf("\033[1;32m✓ Probing profile set to:\033[0m %s\n", p)

	case "rate":
		rateVal, err := strconv.Atoi(val[0])
		if err != nil || rateVal < 1 {
			fmt.Println("Rate must be a positive integer (packets/sec).")
			return
		}
		r.session.SetRateLimit(rateVal)
		fmt.Printf("\033[1;32m✓ Rate limit set to:\033[0m %d probes/sec\n", rateVal)

	case "workers":
		wVal, err := strconv.Atoi(val[0])
		if err != nil || wVal < 1 {
			fmt.Println("Workers must be a positive integer.")
			return
		}
		r.session.SetWorkers(wVal)
		fmt.Printf("\033[1;32m✓ Worker pool configured with:\033[0m %d concurrent routines\n", wVal)

	default:
		fmt.Printf("Unknown setting %q. Valid: targets, profile, rate, workers.\n", sub)
	}
}

func (r *REPL) handleShow(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: show <matrix|posture <cidr>|targets|identities|drifts|scope|evidence|config>")
		return
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "matrix":
		r.renderMatrixTable()

	case "posture":
		if len(args) < 2 {
			fmt.Println("Usage: show posture <cidr>")
			return
		}
		r.renderPostureDetail(args[1])

	case "targets":
		targets := r.session.GetTargets()
		fmt.Printf("\nActive Target Scopes (%d configured):\n", len(targets))
		for i, t := range targets {
			scopeStatus := "\033[1;32mIN-SCOPE\033[0m"
			if err := r.session.ValidateTarget(t); err != nil {
				scopeStatus = "\033[1;31mRESTRICTED\033[0m"
			}
			fmt.Printf("  %2d. %-24s [%s]\n", i+1, t, scopeStatus)
		}
		fmt.Println()

	case "identities":
		identities := r.session.GetIdentities()
		if len(identities) == 0 {
			fmt.Println("No fused identities recorded yet.")
			return
		}
		table := tablewriter.NewTable(os.Stdout)
		table.Header("Identity ID", "Primary IP", "MAC Address", "Hostname", "AD Domain", "Confidence")
		for _, id := range identities {
			_ = table.Append([]any{
				id.ID,
				id.PrimaryIP,
				id.MACAddress,
				id.Hostname,
				id.ADDomain,
				id.Confidence,
			})
		}
		_ = table.Render()
		fmt.Println()

	case "drifts":
		drifts := r.session.GetIdentityDrifts()
		if len(drifts) == 0 {
			fmt.Println("No identity drift events detected.")
			return
		}
		table := tablewriter.NewTable(os.Stdout)
		table.Header("Identity ID", "Previous IP", "Current IP", "Description", "Detected At")
		for _, d := range drifts {
			_ = table.Append([]any{
				d.IdentityID,
				d.PreviousIP,
				d.NewIP,
				d.Description,
				d.DetectedAt.Format("2006-01-02 15:04:05"),
			})
		}
		_ = table.Render()
		fmt.Println()

	case "scope":
		rules := r.session.GetScopeRules()
		fmt.Printf("\nSCOPE GUARD RULES (%d configured):\n", len(rules))
		if len(rules) == 0 {
			fmt.Println("  (No explicit inclusion/exclusion rules configured; all targets in session are allowed by default)")
			fmt.Println()
			return
		}
		table := tablewriter.NewTable(os.Stdout)
		table.Header("Rule ID", "Action", "Pattern / CIDR / Domain", "Description")
		for _, r := range rules {
			action := "\033[1;32mINCLUDE\033[0m"
			if r.RuleType == domain.ScopeExclude {
				action = "\033[1;31mEXCLUDE\033[0m"
			}
			_ = table.Append([]any{
				r.ID,
				action,
				r.Pattern,
				r.Description,
			})
		}
		_ = table.Render()
		fmt.Println()

	case "evidence":
		evidence := r.session.GetEvidence()
		if len(evidence) == 0 {
			fmt.Println("No empirical evidence records captured yet.")
			return
		}
		table := tablewriter.NewTable(os.Stdout)
		table.Header("Evidence ID", "Address / Host", "Category", "Confidence", "Description", "Observed At")
		for _, ev := range evidence {
			_ = table.Append([]any{
				ev.ID,
				ev.Address,
				string(ev.Category),
				string(ev.Confidence),
				ev.Description,
				ev.ObservedAt.Format("2006-01-02 15:04:05"),
			})
		}
		_ = table.Render()
		fmt.Println()

	case "config":
		fmt.Printf("\nSession Parameters (ID: %s | Workspace: %s):\n", r.session.Env.SessionID, r.session.WorkspaceName)
		fmt.Printf("  Profile      : %s\n", r.session.GetProfile())
		fmt.Printf("  Rate Limit   : %d probes/sec\n", r.session.GetRateLimit())
		fmt.Printf("  Worker Pool  : %d goroutines\n", r.session.GetWorkers())
		fmt.Printf("  Probe Timeout: %v\n\n", r.session.ProbeTimeout)

	default:
		fmt.Printf("Unknown show target %q.\n", sub)
	}
}

func (r *REPL) renderMatrixTable() {
	postures := r.session.GetAllPostures()
	if len(postures) == 0 {
		fmt.Println("No audit postures evaluated yet. Run 'run audit' to evaluate target scopes.")
		return
	}

	table := tablewriter.NewTable(os.Stdout)
	table.Header("Subnet CIDR", "Compliance", "Blast Radius", "Exposed Hosts", "Open Services")

	for cidr, p := range postures {
		var openSvcs []string
		for _, s := range p.ProbedServices {
			if s.State == schema.StateOpen {
				openSvcs = append(openSvcs, fmt.Sprintf("%d/%s", s.Port, s.ServiceName))
			}
		}
		svcSummary := strings.Join(openSvcs, ", ")
		if svcSummary == "" {
			svcSummary = "None (Isolated)"
		}

		_ = table.Append([]any{
			cidr,
			p.Compliance,
			fmt.Sprintf("%.1f / 10.0", p.BlastScore),
			fmt.Sprintf("%d", len(p.ExposedHosts)),
			svcSummary,
		})
	}
	_ = table.Render()
}

func (r *REPL) renderPostureDetail(cidr string) {
	p, ok := r.session.GetPosture(cidr)
	if !ok {
		fmt.Printf("No evaluated posture found for subnet %q.\n", cidr)
		return
	}

	fmt.Printf("\nSUB-SEGMENT POSTURE: %s\n", cidr)
	fmt.Printf("  Compliance Status : %s\n", p.Compliance)
	fmt.Printf("  Blast Radius Score: %.1f / 10.0\n", p.BlastScore)
	fmt.Printf("  Exposed Hosts (%d): %s\n\n", len(p.ExposedHosts), strings.Join(p.ExposedHosts, ", "))

	if len(p.ProbedServices) == 0 {
		fmt.Println("  No service probe records available.")
		return
	}

	table := tablewriter.NewTable(os.Stdout)
	table.Header("Port", "Proto", "Service", "State", "Latency", "Banner / TLS Certificate")

	for _, s := range p.ProbedServices {
		banner := s.Banner
		if banner == "" && len(s.TLSDetails) > 0 {
			banner = fmt.Sprintf("CN: %s (Issuer: %s)", s.TLSDetails["subject_cn"], s.TLSDetails["issuer"])
		}
		if banner == "" {
			banner = "-"
		}
		_ = table.Append([]any{
			fmt.Sprintf("%d", s.Port),
			s.Protocol,
			s.ServiceName,
			string(s.State),
			fmt.Sprintf("%dms", s.LatencyMs),
			banner,
		})
	}
	_ = table.Render()
	fmt.Println()
}

func (r *REPL) handleRun(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: run <audit|egress|firewall> [options]")
		return
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "audit":
		r.executeLiveAudit(args[1:])

	case "egress":
		r.executeEgressCheck(args[1:])

	case "firewall":
		r.executeFirewallAnalysis(args[1:])

	default:
		fmt.Printf("Unknown run action %q.\n", sub)
	}
}

func (r *REPL) executeLiveAudit(args []string) {
	targets := r.session.GetTargets()
	if len(targets) == 0 {
		fmt.Println("\033[1;31mError:\033[0m No target scopes defined. Use 'set targets <CIDR>' first.")
		return
	}

	evasion := false
	passiveSniff := false
	for _, a := range args {
		if a == "--evasion" {
			evasion = true
		}
		if a == "--passive" {
			passiveSniff = true
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if passiveSniff {
		fmt.Println("\033[1;34m[*] Spawning passive listeners (LLMNR / mDNS / NetBIOS)...\033[0m")
		sniffer := passive.NewPassiveSniffer(func(node passive.DiscoveredNode) {
			r.session.AddDiscoveredHost(targets[0], node.IP)
		})
		_ = sniffer.Start(ctx)
	}

	fmt.Printf("\033[1;32m[*] Commencing live audit across %d target scope(s)...\033[0m\n", len(targets))
	ports := r.selectAuditPorts()

	engine := active.NewActiveEngine(r.session.ProbeTimeout, r.session.GetWorkers(), r.session.GetRateLimit(), evasion)

	for _, target := range targets {
		if err := r.session.ValidateTarget(target); err != nil {
			fmt.Printf("  \033[1;31m[!] Scope Guard Block:\033[0m Target %s is outside authorized scope: %v. Skipping.\n", target, err)
			continue
		}

		hosts := resolveTargetHosts(target)
		fmt.Printf("  ▶ Auditing scope %s (%d host addresses, %d ports)...\n", target, len(hosts), len(ports))

		var allServices []schema.ServiceProbeResult
		var activeHosts []string

		for _, host := range hosts {
			res := engine.ProbeHost(ctx, host, ports)
			hasOpen := false
			for _, probe := range res {
				if probe.State == schema.StateOpen {
					hasOpen = true
					allServices = append(allServices, probe)

					// Ingest observation into Identity Fusion Engine
					obs := schema.Observation{
						WorkspaceID: r.session.WorkspaceID,
						TargetIP:    host,
						ObservedAt:  time.Now().UTC(),
						Kind:        "service",
						RawData:     fmt.Sprintf("%d/%s", probe.Port, probe.ServiceName),
					}
					if probe.Banner != "" {
						obs.Kind = "banner"
						obs.RawData = probe.Banner
					}
					if len(probe.TLSDetails) > 0 {
						if cn, ok := probe.TLSDetails["subject_cn"]; ok && cn != "" {
							r.session.IngestTelemetry(schema.Observation{
								WorkspaceID: r.session.WorkspaceID,
								TargetIP:    host,
								ObservedAt:  time.Now().UTC(),
								Kind:        "tls",
								RawData:     cn,
							})
						}
					}
					r.session.IngestTelemetry(obs)

					// Ingest empirical evidence
					r.session.AddEvidence(domain.Evidence{
						WorkspaceID: r.session.WorkspaceID,
						Address:     host,
						Category:    domain.EvidenceDirect,
						Confidence:  domain.ConfidenceHigh,
						Port:        probe.Port,
						Protocol:    probe.Protocol,
						ServiceName: probe.ServiceName,
						Description: fmt.Sprintf("Open port %d/%s (%s, latency %dms)", probe.Port, probe.ServiceName, probe.Protocol, probe.LatencyMs),
						ObservedAt:  time.Now().UTC(),
					})
				}
			}
			if hasOpen {
				activeHosts = append(activeHosts, host)
			}
		}

		posture := schema.SubnetPosture{
			SubnetCIDR:     target,
			ExposedHosts:   activeHosts,
			ProbedServices: allServices,
			Compliance:     "PASS",
		}
		posture.BlastScore = graph.CalculateBlastScore(posture)
		if posture.BlastScore >= 5.0 {
			posture.Compliance = "FAIL"
		}

		r.session.SetPosture(posture)
		fmt.Printf("    └── Scope %s completed. Blast Radius: \033[1;33m%.1f\033[0m | Compliance: %s\n",
			target, posture.BlastScore, posture.Compliance)
	}

	fmt.Println("\n\033[1;32m✓ Audit completed.\033[0m Run 'show matrix' to inspect live reachability.")
}

func (r *REPL) selectAuditPorts() []int {
	profile := r.session.GetProfile()
	switch profile {
	case "active-directory-reachability", "ad":
		return []int{53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269}
	case "ot-scada-posture", "ot":
		return []int{102, 502, 4840, 20000, 44818}
	case "zero-trust-audit", "zero-trust":
		return []int{21, 22, 23, 80, 88, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5985, 8080, 8443}
	default:
		return []int{21, 22, 80, 88, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443}
	}
}

func resolveTargetHosts(target string) []string {
	if strings.Contains(target, "/") {
		_, ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return []string{target}
		}
		var ips []string
		ip := ipNet.IP.Mask(ipNet.Mask)
		for ipNet.Contains(ip) {
			ips = append(ips, ip.String())
			// Increment IP
			for j := len(ip) - 1; j >= 0; j-- {
				ip[j]++
				if ip[j] > 0 {
					break
				}
			}
			if len(ips) > 256 { // Bound live sweep per subnet for interactive execution
				break
			}
		}
		if len(ips) > 2 {
			return ips[1 : len(ips)-1] // Drop network and broadcast
		}
		return ips
	}
	return []string{target}
}

func (r *REPL) executeEgressCheck(args []string) {
	dnsTarget := "1.1.1.1"
	ports := []int{53, 80, 443, 853, 8080, 8443, 22, 587}

	for i := 0; i < len(args); i++ {
		if args[i] == "--dns" && i+1 < len(args) {
			dnsTarget = args[i+1]
			i++
		}
	}

	fmt.Printf("\033[1;34m[*] Verifying egress filtration towards %s...\033[0m\n", dnsTarget)
	ev := tunneling.NewEgressValidator(r.session.ProbeTimeout)
	results := ev.CheckEgressPorts(context.Background(), dnsTarget, ports)

	table := tablewriter.NewTable(os.Stdout)
	table.Header("Egress Port", "Protocol", "Status", "Latency", "Observation")
	for _, res := range results {
		status := "\033[1;32mPERMITTED\033[0m"
		obs := "Direct outbound tunnel path reachable"
		if !res.Open {
			status = "\033[1;31mBLOCKED\033[0m"
			obs = res.FilterMsg
		}
		_ = table.Append([]any{
			fmt.Sprintf("%d", res.Port),
			res.Protocol,
			status,
			fmt.Sprintf("%v", res.Latency.Round(time.Millisecond)),
			obs,
		})
	}
	_ = table.Render()

	mtu, err := ev.DiscoverPathMTU(dnsTarget, 53)
	if err == nil {
		fmt.Printf("\n  Effective Path MTU: \033[1;32m%d bytes\033[0m (Unfragmented Payload Capacity: %d bytes)\n\n",
			mtu, mtu-28)
	}
}

func (r *REPL) executeFirewallAnalysis(args []string) {
	host := ""
	port := 80
	for i := 0; i < len(args); i++ {
		if args[i] == "--host" && i+1 < len(args) {
			host = args[i+1]
			i++
		} else if args[i] == "--port" && i+1 < len(args) {
			p, _ := strconv.Atoi(args[i+1])
			if p > 0 {
				port = p
			}
			i++
		}
	}

	if host == "" {
		fmt.Println("Usage: run firewall --host <ip> --port <p>")
		return
	}

	fmt.Printf("\033[1;34m[*] Testing connection tracking & ACL behavior on %s:%d...\033[0m\n", host, port)
	detector := firewall.NewDetector(r.session.ProbeTimeout)
	assessment := detector.AnalyzePort(context.Background(), host, port)

	fmt.Printf("\nFIREWALL POLICY INFERENCE: %s:%d\n", host, port)
	fmt.Printf("  Filtering Behavior    : %s\n", assessment.Behavior)
	fmt.Printf("  Source Port 53 Bypass : %v\n", assessment.SourcePort53Pass)
	fmt.Printf("  Source Port 88 Bypass : %v\n", assessment.SourcePort88Pass)
	fmt.Printf("  Analysis Note         : %s\n\n", assessment.Details)
}

func (r *REPL) handleSimulate(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: simulate rule --block --port <port>")
		return
	}

	port := 0
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			port, _ = strconv.Atoi(args[i+1])
			i++
		}
	}

	postures := r.session.GetAllPostures()
	if len(postures) == 0 {
		fmt.Println("No active postures loaded to simulate against. Run 'run audit' first.")
		return
	}

	g := graph.BuildSubnetGraph(postures)
	rule := graph.SimulationRule{
		Action: "DENY",
		Port:   port,
	}

	fmt.Printf("\nWHAT-IF POLICY SIMULATION: DENY port %d\n", port)
	for cidr, p := range postures {
		res := g.SimulateBlockRule(rule, p)
		fmt.Printf("  Segment %-18s : Initial Score: %.1f ➔ Mitigated: \033[1;32m%.1f\033[0m (%s)\n",
			cidr, res.InitialScore, res.MitigatedScore, res.MitigationEffect)
	}
	fmt.Println()
}

func (r *REPL) handleExport(args []string) {
	outDir := "exports"
	formats := []string{"html", "json", "markdown", "rules"}

	for i := 0; i < len(args); i++ {
		if args[i] == "--out-dir" && i+1 < len(args) {
			outDir = args[i+1]
			i++
		} else if args[i] == "--format" && i+1 < len(args) {
			formats = strings.Split(args[i+1], ",")
			i++
		}
	}

	generated, err := exporter.ExportAll(r.session.Env, exporter.ExportOptions{
		OutDir:  outDir,
		Formats: formats,
	})
	if err != nil {
		fmt.Printf("\033[1;31mExport failed:\033[0m %v\n", err)
		return
	}

	fmt.Printf("\n\033[1;32m✓ Session artifacts successfully exported to %q:\033[0m\n", outDir)
	for f, path := range generated {
		fmt.Printf("  • %-10s : %s\n", strings.ToUpper(f), path)
	}
	fmt.Println()
}

func (r *REPL) handleServe(args []string) {
	port := 8080
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			p, err := strconv.Atoi(args[i+1])
			if err == nil && p > 0 {
				port = p
			}
			i++
		}
	}

	if r.server == nil {
		r.server = recon.NewLiveServer(r.session.Env, r.session.GetIdentities)
	}

	url, err := r.server.Start(port)
	if err != nil {
		fmt.Printf("\033[1;31mError starting live server:\033[0m %v\n", err)
		return
	}

	fmt.Printf("\n\033[1;32m✓ Falcon Live Web Topology Dashboard active:\033[0m %s\n", url)
	fmt.Println("  (Live visual HUD updates automatically as network probes discover new nodes)")
	fmt.Println()
}
