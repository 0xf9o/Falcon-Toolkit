package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/terminal"
)

// CommandCategory groups related commands for help display.
type CommandCategory string

const (
	CategoryCore          CommandCategory = "CORE"
	CategoryReconData     CommandCategory = "RECON / DATA"
	CategoryAssets        CommandCategory = "ASSETS"
	CategoryAttackSurface CommandCategory = "ATTACK SURFACE"
	CategoryOT            CommandCategory = "OT / ICS"
	CategoryIntelligence  CommandCategory = "INTELLIGENCE"
	CategoryEngagement    CommandCategory = "ENGAGEMENT"
	CategoryReporting     CommandCategory = "REPORTING"
	CategoryWorkspace     CommandCategory = "WORKSPACE"
	CategoryModules       CommandCategory = "MODULES"
	CategoryShell         CommandCategory = "SHELL"
)

// CommandMeta stores documentation and usage metadata for a command.
type CommandMeta struct {
	Name        string
	Category    CommandCategory
	Usage       string
	Description string
	Aliases     []string
	Examples    []string
	Subcommands []SubcommandMeta
}

// SubcommandMeta stores documentation for a subcommand.
type SubcommandMeta struct {
	Name        string
	Usage       string
	Description string
}

// HelpRenderer renders categorized help and command-specific help screens.
type HelpRenderer struct {
	style *terminal.Style
}

// NewHelpRenderer creates a new HelpRenderer.
func NewHelpRenderer(style *terminal.Style) *HelpRenderer {
	return &HelpRenderer{style: style}
}

// RenderCategorizedHelp formats the top-level categorized help menu.
func (h *HelpRenderer) RenderCategorizedHelp(commands map[string]CommandMeta) string {
	var sb strings.Builder

	sb.WriteString("╭────────────────────────────────────────────────────────────────────────────╮\n")
	sb.WriteString("│                         ")
	sb.WriteString(h.style.Brand("FALCON TOOLKIT v4.0.0"))
	sb.WriteString("                              │\n")
	sb.WriteString("│                    ")
	sb.WriteString(h.style.Info("RED TEAM INTELLIGENCE CLI"))
	sb.WriteString("                               │\n")
	sb.WriteString("╰────────────────────────────────────────────────────────────────────────────╯\n\n")

	categories := []CommandCategory{
		CategoryCore,
		CategoryReconData,
		CategoryAssets,
		CategoryAttackSurface,
		CategoryOT,
		CategoryIntelligence,
		CategoryEngagement,
		CategoryReporting,
		CategoryWorkspace,
		CategoryModules,
		CategoryShell,
	}

	byCat := make(map[CommandCategory][]CommandMeta)
	for _, cmd := range commands {
		byCat[cmd.Category] = append(byCat[cmd.Category], cmd)
	}

	for _, cat := range categories {
		cmds, exists := byCat[cat]
		if !exists || len(cmds) == 0 {
			continue
		}

		sort.Slice(cmds, func(i, j int) bool {
			return cmds[i].Name < cmds[j].Name
		})

		sb.WriteString(h.style.Category(string(cat)))
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("─", 78))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("%-20s %s\n", "COMMAND", "DESCRIPTION"))
		for _, cmd := range cmds {
			aliasStr := ""
			if len(cmd.Aliases) > 0 {
				aliasStr = h.style.Muted(fmt.Sprintf(" (%s)", strings.Join(cmd.Aliases, ", ")))
			}
			cmdName := h.style.Command(fmt.Sprintf("%-20s", cmd.Name))
			sb.WriteString(fmt.Sprintf("%s%s%s\n", cmdName, cmd.Description, aliasStr))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Type:\n")
	sb.WriteString("  help <command>\n\n")
	sb.WriteString("for detailed command information.\n")

	return sb.String()
}

// RenderCommandHelp formats detailed help for an individual command.
func (h *HelpRenderer) RenderCommandHelp(meta CommandMeta) string {
	var sb strings.Builder

	sb.WriteString(h.style.Brand(strings.ToUpper(meta.Name)))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 60))
	sb.WriteString("\n\n")

	sb.WriteString(h.style.Category("Purpose\n"))
	sb.WriteString(fmt.Sprintf("  %s\n\n", meta.Description))

	sb.WriteString(h.style.Category("Usage\n"))
	for _, line := range strings.Split(meta.Usage, "\n") {
		sb.WriteString(fmt.Sprintf("  %s\n", line))
	}
	sb.WriteString("\n")

	if len(meta.Aliases) > 0 {
		sb.WriteString(h.style.Category("Aliases\n"))
		sb.WriteString(fmt.Sprintf("  %s\n\n", strings.Join(meta.Aliases, ", ")))
	}

	if len(meta.Subcommands) > 0 {
		sb.WriteString(h.style.Category("Subcommands\n"))
		for _, sub := range meta.Subcommands {
			sb.WriteString(fmt.Sprintf("  %-20s %s\n", h.style.Command(sub.Name), sub.Description))
		}
		sb.WriteString("\n")
	}

	if len(meta.Examples) > 0 {
		sb.WriteString(h.style.Category("Examples\n"))
		for _, ex := range meta.Examples {
			sb.WriteString(fmt.Sprintf("  %s\n", h.style.Info(ex)))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
