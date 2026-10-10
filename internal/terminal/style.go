// Package terminal provides centralized terminal styling, color management,
// and output formatting for Falcon ToolKit. All ANSI escape codes are
// contained within this package — no other package should emit raw ANSI.
//
// Respects NO_COLOR and TERM=dumb conventions.
package terminal

import (
	"fmt"
	"os"
	"strings"
)

// -------------------------------------------------------------------
// Color codes
// -------------------------------------------------------------------

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	italic = "\033[3m"

	fgBlack   = "\033[30m"
	fgRed     = "\033[31m"
	fgGreen   = "\033[32m"
	fgYellow  = "\033[33m"
	fgBlue    = "\033[34m"
	fgMagenta = "\033[35m"
	fgCyan    = "\033[36m"
	fgWhite   = "\033[37m"
	fgGray    = "\033[90m"

	fgBrightGreen = "\033[92m"
	fgBrightCyan  = "\033[96m"
	fgBrightWhite = "\033[97m"
)

// -------------------------------------------------------------------
// Theme
// -------------------------------------------------------------------

// Theme holds the color scheme used throughout the application.
type Theme struct {
	Brand    string
	Command  string
	Category string
	Success  string
	Info     string
	Warning  string
	Error    string
	ID       string
	Muted    string
	Bold     string
	Reset    string
}

// DefaultTheme returns the Falcon green-based theme.
func DefaultTheme() *Theme {
	return &Theme{
		Brand:    fgBrightGreen + bold,
		Command:  fgGreen,
		Category: fgCyan,
		Success:  fgGreen,
		Info:     fgCyan,
		Warning:  fgYellow,
		Error:    fgRed + bold,
		ID:       fgBrightWhite,
		Muted:    fgGray,
		Bold:     bold,
		Reset:    reset,
	}
}

// NoColorTheme returns a theme with no ANSI codes (for NO_COLOR / machine output).
func NoColorTheme() *Theme {
	return &Theme{}
}

// -------------------------------------------------------------------
// Styler / Style
// -------------------------------------------------------------------

// Style is an alias for Styler.
type Style = Styler

// Styler provides themed text formatting for terminal output.
type Styler struct {
	theme   *Theme
	enabled bool
}

// NewStyler creates a Styler. It automatically detects NO_COLOR and TERM=dumb.
func NewStyler() *Styler {
	enabled := isColorEnabled()
	s := &Styler{enabled: enabled}
	if enabled {
		s.theme = DefaultTheme()
	} else {
		s.theme = NoColorTheme()
	}
	return s
}

// NewStyle creates a new Style honoring the noColor flag.
func NewStyle(noColor bool) *Styler {
	if noColor {
		return NewStylerDisabled()
	}
	return NewStyler()
}

// NewStylerDisabled creates a Styler with colors explicitly disabled.
func NewStylerDisabled() *Styler {
	return &Styler{
		theme:   NoColorTheme(),
		enabled: false,
	}
}

// IsColorEnabled returns whether colors are currently active.
func (s *Styler) IsColorEnabled() bool {
	return s.enabled
}

// Theme returns the current theme.
func (s *Styler) Theme() *Theme {
	return s.theme
}

func isColorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return true
}

// -------------------------------------------------------------------
// Formatting helpers
// -------------------------------------------------------------------

// Brand formats text with the brand color.
func (s *Styler) Brand(text string) string {
	return s.wrap(s.theme.Brand, text)
}

// Command formats text with the command color.
func (s *Styler) Command(text string) string {
	return s.wrap(s.theme.Command, text)
}

// Category formats text with the category color.
func (s *Styler) Category(text string) string {
	return s.wrap(s.theme.Category, text)
}

// Success formats text with the success color.
func (s *Styler) Success(text string) string {
	return s.wrap(s.theme.Success, text)
}

// Info formats text with the info color.
func (s *Styler) Info(text string) string {
	return s.wrap(s.theme.Info, text)
}

// Warning formats text with the warning color.
func (s *Styler) Warning(text string) string {
	return s.wrap(s.theme.Warning, text)
}

// Error formats text with the error color.
func (s *Styler) Error(text string) string {
	return s.wrap(s.theme.Error, text)
}

// Identifier formats text with the identifier color.
func (s *Styler) Identifier(text string) string {
	return s.wrap(s.theme.ID, text)
}

// Muted formats text with the muted color.
func (s *Styler) Muted(text string) string {
	return s.wrap(s.theme.Muted, text)
}

// BoldText formats text as bold.
func (s *Styler) BoldText(text string) string {
	return s.wrap(s.theme.Bold, text)
}

// SuccessIcon returns a colored check mark.
func (s *Styler) SuccessIcon() string {
	return s.Success("✓")
}

// ErrorIcon returns a colored X mark.
func (s *Styler) ErrorIcon() string {
	return s.Error("✗")
}

// WarningIcon returns a colored warning symbol.
func (s *Styler) WarningIcon() string {
	return s.Warning("!")
}

func (s *Styler) wrap(style, text string) string {
	if !s.enabled || style == "" {
		return text
	}
	return style + text + reset
}

// -------------------------------------------------------------------
// Table rendering
// -------------------------------------------------------------------

// Table renders a formatted table to a string.
type Table struct {
	Headers []string
	Rows    [][]string
	Styler  *Styler
}

// Render produces the formatted table string.
func (t *Table) Render() string {
	if len(t.Headers) == 0 {
		return ""
	}

	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder

	for i, h := range t.Headers {
		if i > 0 {
			sb.WriteString("  ")
		}
		if t.Styler != nil {
			sb.WriteString(t.Styler.BoldText(padRight(h, widths[i])))
		} else {
			sb.WriteString(padRight(h, widths[i]))
		}
	}
	sb.WriteString("\n")

	for i, w := range widths {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(strings.Repeat("─", w))
	}
	sb.WriteString("\n")

	for _, row := range t.Rows {
		for i := 0; i < len(t.Headers); i++ {
			if i > 0 {
				sb.WriteString("  ")
			}
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			sb.WriteString(padRight(cell, widths[i]))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// -------------------------------------------------------------------
// Section rendering
// -------------------------------------------------------------------

// Section prints a section header with a horizontal rule.
func Section(title string) string {
	return fmt.Sprintf("%s\n%s\n", title, strings.Repeat("─", 40))
}

// SectionStyled prints a styled section header.
func (s *Styler) Section(title string) string {
	return fmt.Sprintf("%s\n%s\n", s.BoldText(title), s.Muted(strings.Repeat("─", 40)))
}

// KeyValue formats a key-value pair with alignment.
func KeyValue(key string, value string, keyWidth int) string {
	return fmt.Sprintf("  %-*s  %s\n", keyWidth, key+":", value)
}
