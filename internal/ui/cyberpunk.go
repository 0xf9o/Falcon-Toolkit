package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// Falcon v3.0 — Cyberpunk Neon Theme
// Primary:  Neon Cyan  #00E5FF
// Accent:   Neon Green #00FF87
// =============================================================================

// Color Palette
var (
	// Primary neon cyan — borders, active elements, titles
	ColorPrimary = lipgloss.Color("#00E5FF")
	// Accent neon green — success, open ports, active badges
	ColorAccent = lipgloss.Color("#00FF87")
	// Hot pink — author badge, danger, alerts
	ColorHot = lipgloss.Color("#FF2D78")
	// Electric purple — version badge, tags
	ColorPurple = lipgloss.Color("#BD00FF")
	// Amber — warning, engine badge, status
	ColorAmber = lipgloss.Color("#FFB800")
	// Dim border — inactive panels
	ColorBorderDim = lipgloss.Color("#1E2A3A")
	// Panel background — dark base
	ColorBg = lipgloss.Color("#080D14")
	// Card background — slightly lifted
	ColorCard = lipgloss.Color("#0D1520")
	// Row alt background — subtle contrast
	ColorRowAlt = lipgloss.Color("#111C2B")
	// Muted text — secondary info
	ColorMuted = lipgloss.Color("#4A6375")
	// Light text — primary readable content
	ColorText = lipgloss.Color("#C9D8E8")
	// Bright white — for emphasis
	ColorBright = lipgloss.Color("#EEF4FC")

	// Legacy aliases kept for backward compatibility
	ColorCyan         = ColorPrimary
	ColorPink         = ColorHot
	ColorGreen        = ColorAccent
	ColorYellow       = ColorAmber
	ColorBgDark       = ColorBg
	ColorPanelBg      = ColorCard
	ColorBorder       = ColorBorderDim
	ColorBorderActive = ColorPrimary
	ColorTextMuted    = ColorMuted
	ColorTextLight    = ColorText
)

// =============================================================================
// Badge Styles — Solid-background highlighted status labels
// =============================================================================

var (
	// BadgeAuthor — hot pink solid background for AUTHOR label
	BadgeAuthor = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#080D14")).
			Background(ColorHot).
			Padding(0, 1).
			MarginRight(1)

	// BadgeVersion — electric purple solid background for VERSION label
	BadgeVersion = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#EEF4FC")).
			Background(ColorPurple).
			Padding(0, 1).
			MarginRight(1)

	// BadgeEngine — amber solid background for ENGINE label
	BadgeEngine = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#080D14")).
			Background(ColorAmber).
			Padding(0, 1).
			MarginRight(1)

	// BadgeOpen — neon green solid background for OPEN state
	BadgeOpen = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#080D14")).
			Background(ColorAccent).
			Padding(0, 1)

	// BadgeActive — neon cyan solid background for ACTIVE state
	BadgeActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#080D14")).
			Background(ColorPrimary).
			Padding(0, 1)

	// BadgeWarn — amber solid background for warnings
	BadgeWarn = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#080D14")).
			Background(ColorAmber).
			Padding(0, 1)

	// BadgeDanger — hot pink solid background for errors / danger
	BadgeDanger = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#EEF4FC")).
			Background(ColorHot).
			Padding(0, 1)

	// BadgeNeutral — muted solid background for inactive labels
	BadgeNeutral = lipgloss.NewStyle().
			Foreground(ColorText).
			Background(ColorBorderDim).
			Padding(0, 1)
)

// =============================================================================
// Panel Styles — Rounded borders, neon accents
// =============================================================================

var (
	// StylePanel — standard rounded panel with dim border
	StylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorderDim).
			Background(ColorCard).
			Padding(0, 1)

	// StylePanelActive — rounded panel with neon cyan glow border
	StylePanelActive = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorPrimary).
				Background(ColorCard).
				Padding(0, 1)

	// StylePanelAccent — rounded panel with neon green accent border
	StylePanelAccent = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorAccent).
				Background(ColorCard).
				Padding(0, 1)
)

// =============================================================================
// Navigation Tab Styles
// =============================================================================

var (
	// StyleTabActive — solid primary background for the selected tab
	StyleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorBg).
			Background(ColorPrimary).
			Padding(0, 2)

	// StyleTabInactive — dim muted appearance for unselected tabs
	StyleTabInactive = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Background(ColorCard).
				Padding(0, 2)
)

// =============================================================================
// Text & Metric Styles (legacy-compatible names kept)
// =============================================================================

var (
	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Background(ColorBg).
			Padding(0, 1)

	StyleAuthor = lipgloss.NewStyle().
			Foreground(ColorHot).
			Italic(true)

	StyleVersion = lipgloss.NewStyle().
			Foreground(ColorAmber).
			Bold(true)

	StyleBadge = BadgeNeutral

	StyleBadgeSuccess = BadgeOpen

	StyleBadgeWarning = BadgeWarn

	StyleBadgeDanger = BadgeDanger

	StyleKey = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true)

	StyleKeyDesc = lipgloss.NewStyle().
			Foreground(ColorMuted)
)

// =============================================================================
// Table Rendering — Explicit column padding, header styling, alt-row contrast
// =============================================================================

// TableColumn defines a single column specification.
type TableColumn struct {
	Header string
	Width  int
}

// TableRow is a slice of cell strings, one per column.
type TableRow []string

// RenderTable renders a styled table with:
//   - neon cyan bold header row with solid background
//   - alternating row background for contrast
//   - explicit column widths with right-padding
//   - rounded outer border via StylePanel
func RenderTable(cols []TableColumn, rows []TableRow, panelWidth int) string {
	var sb strings.Builder

	// ── Header row ──────────────────────────────────────────────────────────
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorBg).
		Background(ColorPrimary).
		Padding(0, 0)

	sepStyle := lipgloss.NewStyle().
		Foreground(ColorBorderDim)

	var headerCells []string
	for _, col := range cols {
		cell := padRight(strings.ToUpper(col.Header), col.Width)
		headerCells = append(headerCells, headerStyle.Render(cell))
	}
	sb.WriteString(strings.Join(headerCells, sepStyle.Render("  ")))
	sb.WriteString("\n")

	// Header underline — neon cyan dashes
	divStyle := lipgloss.NewStyle().Foreground(ColorPrimary)
	totalW := 0
	for i, col := range cols {
		totalW += col.Width
		if i < len(cols)-1 {
			totalW += 2 // separator gap
		}
	}
	sb.WriteString(divStyle.Render(strings.Repeat("─", totalW)))
	sb.WriteString("\n")

	// ── Data rows ────────────────────────────────────────────────────────────
	evenRowBg := ColorCard
	oddRowBg  := ColorRowAlt

	for i, row := range rows {
		bg := evenRowBg
		if i%2 != 0 {
			bg = oddRowBg
		}

		cellStyle := lipgloss.NewStyle().
			Foreground(ColorText).
			Background(bg)

		var cells []string
		for j, col := range cols {
			val := ""
			if j < len(row) {
				val = row[j]
			}
			// Preserve ANSI in cells — just pad the plain text
			plain := lipgloss.NewStyle().Render(val) // strip existing styles for width calc
			padded := padRight(stripANSI(plain), col.Width)
			// Re-render with row background, then overlay original value
			cell := cellStyle.Render(padded)
			// If the original value had badge styling, overlay it
			if val != plain && val != padded {
				cell = val + cellStyle.Render(strings.Repeat(" ", max(0, col.Width-lipgloss.Width(val))))
			}
			cells = append(cells, cell)
		}
		sb.WriteString(strings.Join(cells, "  "))
		sb.WriteString("\n")
	}

	return StylePanel.Width(panelWidth - 2).Render(sb.String())
}

// =============================================================================
// Header HUD
// =============================================================================

// RenderCyberpunkHeader renders the top status bar with badge labels.
func RenderCyberpunkHeader(workspace string, width int) string {
	// Left: title + AUTHOR badge + author name
	titleText := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		Render("⚡ FALCON")

	verText := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorAmber).
		Render("v3.0")

	engineLabel := BadgeEngine.Render("ENGINE")
	engineVal := lipgloss.NewStyle().Foreground(ColorText).Render("Go Worker Pool")

	authorLabel := BadgeAuthor.Render("AUTHOR")
	authorVal   := lipgloss.NewStyle().Foreground(ColorHot).Italic(true).Render("Faisal Al-Harbi (0xF9o)")

	versionLabel := BadgeVersion.Render("VERSION")

	left := lipgloss.JoinHorizontal(lipgloss.Center,
		titleText, " ", verText, "  ",
		versionLabel, "  ",
		engineLabel, engineVal, "  ",
		authorLabel, authorVal,
	)

	// Right: workspace badge
	wsText := fmt.Sprintf("[ %s ]", strings.ToUpper(workspace))
	right := BadgeActive.Render(wsText)

	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, left, strings.Repeat(" ", gap), right)

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorderDim).
		Background(ColorBg).
		Width(width - 2).
		Padding(0, 1).
		Render(row)
}

// =============================================================================
// Metric Cards
// =============================================================================

// RenderMetricCard renders an illuminated stat card with a rounded border.
func RenderMetricCard(label, value string, style lipgloss.Style, width int) string {
	lbl := lipgloss.NewStyle().
		Foreground(ColorMuted).
		Render(strings.ToUpper(label))

	val := style.Render(value)

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorPrimary).
		Background(ColorCard).
		Width(width).
		Padding(0, 1).
		Render(fmt.Sprintf("%s\n%s", lbl, val))
}

// =============================================================================
// Footer Keymap Bar
// =============================================================================

// RenderFooterKeymap renders the bottom keyboard reference toolbar.
func RenderFooterKeymap(width int) string {
	keys := []struct{ k, d string }{
		{"Tab", "Next Tab"},
		{"1-5", "Jump View"},
		{"S", "Quick Scan"},
		{"W", "Workspace"},
		{"R", "Refresh"},
		{"Q / Ctrl+C", "Quit"},
	}

	var parts []string
	for _, kv := range keys {
		k := lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Render("[" + kv.k + "]")
		d := lipgloss.NewStyle().Foreground(ColorMuted).Render(kv.d)
		parts = append(parts, k+" "+d)
	}

	bar := strings.Join(parts, lipgloss.NewStyle().Foreground(ColorBorderDim).Render("  │  "))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorderDim).
		Background(ColorBg).
		Width(width - 2).
		Padding(0, 1).
		Render(bar)
}

// =============================================================================
// Internal helpers
// =============================================================================

// padRight pads s to exactly width runes using spaces.
func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		if w > width && width > 3 {
			return s[:width-3] + "..."
		}
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// stripANSI removes lipgloss ANSI escape sequences to get the printable length.
// We use lipgloss.Width on a plain copy to normalise.
func stripANSI(s string) string {
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
