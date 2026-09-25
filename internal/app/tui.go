package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"falcon/internal/db"
	"falcon/internal/modules"
	"falcon/internal/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tabIndex int

const (
	tabDashboard tabIndex = iota
	tabTopology
	tabPorts
	tabSignatures
	tabWorkspaces
)

var tabNames = []string{
	"1: DASHBOARD",
	"2: TOPOLOGY",
	"3: PORTS & SERVICES",
	"4: SIGNATURES",
	"5: WORKSPACES",
}

// TickMsg triggers periodic interface refresh
type TickMsg time.Time

// ScanDoneMsg notifies that an asynchronous scan has completed
type ScanDoneMsg struct {
	Count int
	Err   error
}

// LogMsg appends a new message to the live activity feed
type LogMsg string

// TUIModel represents the full-screen Bubbletea application state
type TUIModel struct {
	store     *db.Store
	matcher   *modules.SignatureEngine
	workspace string

	// View dimensions & navigation
	width     int
	height    int
	activeTab tabIndex

	// Cached data
	ports      []db.PortRecord
	subdomains []db.SubdomainRecord
	topology   *db.TopologyGraph
	workspaces []string

	// Live status & logs
	logs        []string
	scanRunning bool
	scanStatus  string

	// Interactive Input Mode
	inputMode   bool
	inputAction string // "scan" | "workspace"
	inputPrompt string
	inputBuffer string
}

// NewTUIModel initializes the application model with connected dependencies
func NewTUIModel(store *db.Store, matcher *modules.SignatureEngine) *TUIModel {
	ws, _ := store.GetActiveWorkspace()
	if ws == "" {
		ws = "default"
	}

	m := &TUIModel{
		store:      store,
		matcher:    matcher,
		workspace:  ws,
		activeTab:  tabDashboard,
		logs:       make([]string, 0),
		scanStatus: "Engine Ready",
		width:      120,
		height:     32,
	}

	m.addLog(fmt.Sprintf("Falcon v3.0 initialized — active workspace: %s", ws))
	m.addLog(fmt.Sprintf("Loaded %d compiled YAML protocol signatures.", matcher.Count()))
	m.refreshData()
	return m
}

func (m *TUIModel) addLog(entry string) {
	ts := time.Now().Format("15:04:05")
	m.logs = append(m.logs, fmt.Sprintf("[%s] %s", ts, entry))
	if len(m.logs) > 60 {
		m.logs = m.logs[len(m.logs)-60:]
	}
}

func (m *TUIModel) refreshData() {
	m.ports, _ = m.store.GetPorts(m.workspace)
	m.subdomains, _ = m.store.GetSubdomains(m.workspace)
	m.topology, _ = m.store.GetTopologyGraph(m.workspace)
	m.workspaces, _ = m.store.ListWorkspaces()
}

func (m *TUIModel) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case TickMsg:
		if !m.scanRunning {
			m.refreshData()
		}
		return m, tickCmd()

	case LogMsg:
		m.addLog(string(msg))
		return m, nil

	case ScanDoneMsg:
		m.scanRunning = false
		if msg.Err != nil {
			m.scanStatus = fmt.Sprintf("Scan failed: %v", msg.Err)
			m.addLog(fmt.Sprintf("ERROR: Scan failed: %v", msg.Err))
		} else {
			m.scanStatus = fmt.Sprintf("Scan complete — %d open ports discovered.", msg.Count)
			m.addLog(fmt.Sprintf("SUCCESS: Scan complete. Found %d open ports.", msg.Count))
		}
		m.refreshData()
		return m, nil

	case tea.KeyMsg:
		if m.inputMode {
			switch msg.Type {
			case tea.KeyEsc:
				m.inputMode = false
				m.inputBuffer = ""
			case tea.KeyBackspace:
				if len(m.inputBuffer) > 0 {
					m.inputBuffer = m.inputBuffer[:len(m.inputBuffer)-1]
				}
			case tea.KeyEnter:
				val := strings.TrimSpace(m.inputBuffer)
				action := m.inputAction
				m.inputMode = false
				m.inputBuffer = ""

				if val == "" {
					return m, nil
				}
				if action == "scan" {
					return m, m.startScanCmd(val)
				} else if action == "workspace" {
					_ = m.store.SetActiveWorkspace(val)
					m.workspace = val
					m.addLog(fmt.Sprintf("Switched active workspace to: %s", val))
					m.refreshData()
				}
			case tea.KeyRunes:
				m.inputBuffer += string(msg.Runes)
			case tea.KeySpace:
				m.inputBuffer += " "
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 5
		case "shift+tab":
			if m.activeTab == 0 {
				m.activeTab = 4
			} else {
				m.activeTab--
			}
		case "1":
			m.activeTab = tabDashboard
		case "2":
			m.activeTab = tabTopology
		case "3":
			m.activeTab = tabPorts
		case "4":
			m.activeTab = tabSignatures
		case "5":
			m.activeTab = tabWorkspaces
		case "s", "S":
			m.inputMode = true
			m.inputAction = "scan"
			m.inputPrompt = "Target Host / IP (e.g. 127.0.0.1 or example.com):"
			m.inputBuffer = ""
		case "w", "W":
			m.inputMode = true
			m.inputAction = "workspace"
			m.inputPrompt = "Enter Workspace Name:"
			m.inputBuffer = ""
		case "r", "R":
			m.refreshData()
			m.addLog("Data synchronised with local storage.")
		}
	}

	return m, nil
}

func (m *TUIModel) startScanCmd(target string) tea.Cmd {
	m.scanRunning = true
	m.scanStatus = fmt.Sprintf("Scanning %s...", target)
	m.addLog(fmt.Sprintf("Dispatched high-speed scan: %s", target))

	return func() tea.Msg {
		ports := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		opts := modules.ScanOptions{
			Target:    target,
			Ports:     ports,
			Workers:   50,
			TimeoutMs: 600,
			Workspace: m.workspace,
			Store:     m.store,
			OnOpenFound: func(rec db.PortRecord) {
				match := m.matcher.Identify(rec.Banner, rec.Port)
				if match.Matched {
					rec.Service = match.Service
					_ = m.store.SavePort(m.workspace, rec)
				}
				_ = m.store.SaveAssetNode(m.workspace, db.AssetNode{
					ID:   target,
					Name: target,
					Type: db.AssetIP,
				})
				_ = m.store.SaveServiceNode(m.workspace, db.ServiceNode{
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
			},
		}

		res, err := modules.RunPortScan(ctx, opts)
		return ScanDoneMsg{Count: len(res), Err: err}
	}
}

// =============================================================================
// View
// =============================================================================

func (m *TUIModel) View() string {
	w := m.width
	if w < 90 {
		w = 90
	}

	// 1. Header HUD
	header := ui.RenderCyberpunkHeader(m.workspace, w)

	// 2. Tab bar
	var tabs []string
	for i, name := range tabNames {
		if tabIndex(i) == m.activeTab {
			tabs = append(tabs, ui.StyleTabActive.Render(name))
		} else {
			tabs = append(tabs, ui.StyleTabInactive.Render(name))
		}
	}
	// Join tabs with a subtle separator
	sep := lipgloss.NewStyle().Foreground(ui.ColorBorderDim).Render("│")
	tabsRow := strings.Join(tabs, sep)

	// 3. Body
	bodyH := m.height - 9
	if bodyH < 12 {
		bodyH = 12
	}

	var body string
	switch m.activeTab {
	case tabDashboard:
		body = m.renderDashboard(w, bodyH)
	case tabTopology:
		body = m.renderTopology(w, bodyH)
	case tabPorts:
		body = m.renderPorts(w, bodyH)
	case tabSignatures:
		body = m.renderSignatures(w, bodyH)
	case tabWorkspaces:
		body = m.renderWorkspaces(w, bodyH)
	}

	// 4. Input modal overlay
	if m.inputMode {
		promptStyle := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary)
		hintStyle   := lipgloss.NewStyle().Foreground(ui.ColorMuted)
		cursorStyle := lipgloss.NewStyle().Foreground(ui.ColorAccent).Bold(true)

		inputBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ui.ColorPrimary).
			Background(ui.ColorCard).
			Padding(1, 2).
			Width(w - 12).
			Render(fmt.Sprintf("%s\n\n%s %s%s\n\n%s",
				promptStyle.Render(m.inputPrompt),
				lipgloss.NewStyle().Foreground(ui.ColorAccent).Render("›"),
				m.inputBuffer,
				cursorStyle.Render("█"),
				hintStyle.Render("[Enter] Confirm   [Esc] Cancel"),
			))

		body = lipgloss.JoinVertical(lipgloss.Center, body, "\n", inputBox)
	}

	// 5. Footer
	footer := ui.RenderFooterKeymap(w)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		tabsRow,
		"",
		body,
		"",
		footer,
	)
}

// =============================================================================
// Tab: Dashboard
// =============================================================================

func (m *TUIModel) renderDashboard(width, height int) string {
	cardW := (width - 10) / 4
	if cardW < 20 {
		cardW = 20
	}

	// Metric cards row — each with a badge label
	c1 := ui.RenderMetricCard("Active Workspace",
		ui.BadgeActive.Render(m.workspace), lipgloss.NewStyle(), cardW)

	c2 := ui.RenderMetricCard("Discovered Ports",
		ui.BadgeOpen.Render(fmt.Sprintf("%d Open", len(m.ports))), lipgloss.NewStyle(), cardW)

	c3 := ui.RenderMetricCard("Topology Assets",
		ui.BadgeWarn.Render(fmt.Sprintf("%d Nodes", len(m.topology.Assets))), lipgloss.NewStyle(), cardW)

	c4 := ui.RenderMetricCard("YAML Signatures",
		ui.BadgeEngine.Render(fmt.Sprintf("%d Rules", m.matcher.Count())), lipgloss.NewStyle(), cardW)

	metricsRow := lipgloss.JoinHorizontal(lipgloss.Top, c1, " ", c2, " ", c3, " ", c4)

	panelH := height - 7
	if panelH < 8 {
		panelH = 8
	}
	colW := (width - 6) / 2

	// Left: Recent services table
	svcHeader := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary).
		Render("RECENT OPEN SERVICES")

	var svcLines []string
	if len(m.ports) == 0 {
		svcLines = append(svcLines,
			lipgloss.NewStyle().Foreground(ui.ColorMuted).
				Render("  No open ports yet. Press [S] to scan a target."))
	} else {
		colsDef := []ui.TableColumn{
			{Header: "TARGET", Width: 16},
			{Header: "PORT", Width: 7},
			{Header: "SERVICE", Width: 12},
			{Header: "MS", Width: 6},
			{Header: "BANNER", Width: colW - 48},
		}
		var rows []ui.TableRow
		for i, p := range m.ports {
			if i >= 10 {
				break
			}
			banner := p.Banner
			maxB := colW - 50
			if maxB < 5 {
				maxB = 5
			}
			if len(banner) > maxB {
				banner = banner[:maxB-3] + "..."
			}
			rows = append(rows, ui.TableRow{
				p.Target,
				fmt.Sprintf("%d/tcp", p.Port),
				p.Service,
				fmt.Sprintf("%d", p.LatencyMs),
				banner,
			})
		}
		svcTable := ui.RenderTable(colsDef, rows, colW)
		svcLines = append(svcLines, svcTable)
	}

	leftContent := lipgloss.JoinVertical(lipgloss.Left,
		svcHeader, "", strings.Join(svcLines, "\n"))
	leftPanel := ui.StylePanelActive.Width(colW).Height(panelH).Render(leftContent)

	// Right: Live activity log
	logHeader := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorHot).
		Render("LIVE ENGINE LOG")

	logStart := 0
	if len(m.logs) > 10 {
		logStart = len(m.logs) - 10
	}

	tsStyle  := lipgloss.NewStyle().Foreground(ui.ColorBorderDim)
	msgStyle := lipgloss.NewStyle().Foreground(ui.ColorText)

	var logLines []string
	for _, l := range m.logs[logStart:] {
		// Split [HH:MM:SS] from message
		if len(l) > 10 && l[0] == '[' {
			ts  := tsStyle.Render(l[:10])  // "[HH:MM:SS]"
			msg := msgStyle.Render(l[11:])
			logLines = append(logLines, ts+" "+msg)
		} else {
			logLines = append(logLines, msgStyle.Render(l))
		}
	}

	logContent := lipgloss.JoinVertical(lipgloss.Left,
		logHeader, "", strings.Join(logLines, "\n"))
	rightPanel := ui.StylePanel.Width(colW).Height(panelH).Render(logContent)

	bottomRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, "  ", rightPanel)

	// Status line
	statusLabel := ui.BadgeEngine.Render("STATUS")
	var statusText string
	if m.scanRunning {
		statusText = lipgloss.NewStyle().Foreground(ui.ColorAmber).Bold(true).Render(m.scanStatus)
	} else {
		statusText = lipgloss.NewStyle().Foreground(ui.ColorText).Render(m.scanStatus)
	}
	statusLine := statusLabel + "  " + statusText

	return lipgloss.JoinVertical(lipgloss.Left, metricsRow, "", bottomRow, "", statusLine)
}

// =============================================================================
// Tab: Topology
// =============================================================================

func (m *TUIModel) renderTopology(width, height int) string {
	headerLabel := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary).
		Render("NETWORK TOPOLOGY ASSET GRAPH")

	nodeCount := ui.BadgeOpen.Render(fmt.Sprintf("%d assets", len(m.topology.Assets)))
	edgeCount  := ui.BadgeNeutral.Render(fmt.Sprintf("%d edges", len(m.topology.Edges)))

	statsLine := lipgloss.JoinHorizontal(lipgloss.Center,
		headerLabel, "  ", nodeCount, " ", edgeCount)

	tree := db.RenderTopologyTree(m.topology)

	// Style tree lines
	styledTree := styleTopologyTree(tree)

	content := lipgloss.JoinVertical(lipgloss.Left, statsLine, "", styledTree)

	return ui.StylePanelActive.Width(width - 4).Height(height).Render(content)
}

// styleTopologyTree applies neon colours to ASCII tree nodes.
func styleTopologyTree(raw string) string {
	lines := strings.Split(raw, "\n")
	var out []string

	domainStyle  := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary)
	ipStyle      := lipgloss.NewStyle().Foreground(ui.ColorAccent)
	serviceStyle := lipgloss.NewStyle().Foreground(ui.ColorAmber)
	treeStyle    := lipgloss.NewStyle().Foreground(ui.ColorBorderDim)

	for _, l := range lines {
		if l == "" {
			out = append(out, "")
			continue
		}
		switch {
		case strings.Contains(l, "[DOMAIN]"):
			out = append(out, treeStyle.Render("├── ")+domainStyle.Render(strings.TrimPrefix(l, "├── ")))
		case strings.Contains(l, "[IP]"):
			out = append(out, treeStyle.Render("│   ├── ↳ ")+ipStyle.Render(strings.TrimPrefix(strings.TrimPrefix(l, "│   ├── ↳ "), "│   ")))
		case strings.Contains(l, "->"):
			out = append(out, treeStyle.Render("│   │   └── ")+serviceStyle.Render(strings.TrimLeft(l, "│   └─")))
		default:
			out = append(out, lipgloss.NewStyle().Foreground(ui.ColorMuted).Render(l))
		}
	}

	return strings.Join(out, "\n")
}

// =============================================================================
// Tab: Ports & Services
// =============================================================================

func (m *TUIModel) renderPorts(width, height int) string {
	header := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary).
		Render("AUDITED PORTS & PROTOCOL IDENTIFICATION")

	countBadge := ui.BadgeOpen.Render(fmt.Sprintf("%d records", len(m.ports)))

	if len(m.ports) == 0 {
		empty := lipgloss.NewStyle().Foreground(ui.ColorMuted).
			Render("  No ports recorded in this workspace. Press [S] to initiate a probe.")
		return ui.StylePanel.Width(width - 4).Height(height).
			Render(lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.JoinHorizontal(lipgloss.Center, header, "  ", countBadge), "", empty))
	}

	usableW := width - 12
	cols := []ui.TableColumn{
		{Header: "Target", Width: 18},
		{Header: "Port", Width: 10},
		{Header: "State", Width: 8},
		{Header: "Service", Width: 14},
		{Header: "Latency", Width: 9},
		{Header: "Banner / Identification", Width: max(usableW-63, 20)},
	}

	var rows []ui.TableRow
	for _, p := range m.ports {
		banner := p.Banner
		maxB := max(usableW-65, 15)
		if len(banner) > maxB {
			banner = banner[:maxB-3] + "..."
		}
		stateStr := ui.BadgeOpen.Render(p.State)
		if p.State != "open" {
			stateStr = ui.BadgeNeutral.Render(p.State)
		}
		rows = append(rows, ui.TableRow{
			p.Target,
			fmt.Sprintf("%d/tcp", p.Port),
			stateStr,
			p.Service,
			fmt.Sprintf("%dms", p.LatencyMs),
			banner,
		})
	}

	table := ui.RenderTable(cols, rows, width-4)

	titleRow := lipgloss.JoinHorizontal(lipgloss.Center, header, "  ", countBadge)
	content  := lipgloss.JoinVertical(lipgloss.Left, titleRow, "", table)

	return ui.StylePanel.Width(width - 4).Height(height).Render(content)
}

// =============================================================================
// Tab: YAML Signatures
// =============================================================================

func (m *TUIModel) renderSignatures(width, height int) string {
	header := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary).
		Render("COMPILED YAML PROTOCOL & SERVICE SIGNATURES")

	countBadge := ui.BadgeEngine.Render(fmt.Sprintf("%d rules loaded", m.matcher.Count()))

	cols := []ui.TableColumn{
		{Header: "Signature ID", Width: 20},
		{Header: "Name", Width: 24},
		{Header: "Protocol", Width: 10},
		{Header: "Ports", Width: 16},
		{Header: "Pattern Regex", Width: max((width-12)-76, 20)},
	}

	var rows []ui.TableRow
	for _, sig := range m.matcher.Signatures() {
		pattern := ""
		if len(sig.Matches) > 0 {
			pattern = sig.Matches[0].Regex
		}
		maxP := max((width-12)-78, 10)
		if len(pattern) > maxP {
			pattern = pattern[:maxP-3] + "..."
		}

		var portStrs []string
		for _, p := range sig.Ports {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		portsStr := strings.Join(portStrs, ",")
		if portsStr == "" {
			portsStr = "any"
		}

		protoBadge := protoToBadge(sig.Protocol)

		rows = append(rows, ui.TableRow{
			sig.ID,
			sig.Name,
			protoBadge,
			portsStr,
			lipgloss.NewStyle().Foreground(ui.ColorAmber).Render(pattern),
		})
	}

	table := ui.RenderTable(cols, rows, width-4)
	titleRow := lipgloss.JoinHorizontal(lipgloss.Center, header, "  ", countBadge)
	content  := lipgloss.JoinVertical(lipgloss.Left, titleRow, "", table)

	return ui.StylePanel.Width(width - 4).Height(height).Render(content)
}

// protoToBadge returns a styled badge for a protocol string.
func protoToBadge(proto string) string {
	switch strings.ToLower(proto) {
	case "http":
		return ui.BadgeActive.Render("HTTP")
	case "tcp":
		return ui.BadgeOpen.Render("TCP")
	case "udp":
		return ui.BadgeWarn.Render("UDP")
	default:
		return ui.BadgeNeutral.Render(strings.ToUpper(proto))
	}
}

// =============================================================================
// Tab: Workspaces
// =============================================================================

func (m *TUIModel) renderWorkspaces(width, height int) string {
	header := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorPrimary).
		Render("LOCAL WORKSPACE MANAGEMENT")

	cols := []ui.TableColumn{
		{Header: "Workspace Name", Width: 28},
		{Header: "Status", Width: 16},
		{Header: "Actions", Width: 30},
	}

	var rows []ui.TableRow
	for _, w := range m.workspaces {
		var status, actions string
		if w == m.workspace {
			status  = ui.BadgeActive.Render("● ACTIVE")
			actions = lipgloss.NewStyle().Foreground(ui.ColorMuted).Render("Press [S] to scan • [R] refresh")
		} else {
			status  = ui.BadgeNeutral.Render("○ Inactive")
			actions = lipgloss.NewStyle().Foreground(ui.ColorMuted).Render("Press [W] to switch")
		}
		rows = append(rows, ui.TableRow{w, status, actions})
	}

	table := ui.RenderTable(cols, rows, width-4)

	hint := lipgloss.NewStyle().Foreground(ui.ColorMuted).
		Render("  Press [W] to switch workspace or create a new one.")

	content := lipgloss.JoinVertical(lipgloss.Left, header, "", table, "", hint)

	return ui.StylePanel.Width(width - 4).Height(height).Render(content)
}

// max returns the larger of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// StartTUI launches the Bubbletea full-screen application
func StartTUI(store *db.Store, matcher *modules.SignatureEngine) error {
	p := tea.NewProgram(NewTUIModel(store, matcher), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
