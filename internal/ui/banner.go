package ui

import (
	"fmt"
	"strings"

	"github.com/pterm/pterm"
)

const Version = "v3.0.0-PRO"

// PrintBanner outputs the high-tech ASCII logo and version banner.
func PrintBanner() {
	banner := `
  ______      _                     ____   ___  
 |  ____/\   | |                   |___ \ / _ \ 
 | |__ /  \  | |     ___ ___  _ __   __) | | | |
 |  __/ /\ \ | |    / __/ _ \| '_ \ |__ <| | | |
 | | / ____ \| |___| (_| (_) | | | |___) | |_| |
 |_|/_/    \_\______\___\___/|_| |_|____/ \___/ 
`
	fmt.Println(pterm.Cyan(banner))
	fmt.Printf("%s %s - %s\n",
		pterm.Bold.Sprint(pterm.Cyan("▶ Falcon")),
		pterm.LightMagenta(Version),
		pterm.Gray("Unified High-Speed Reconnaissance & Network Diagnostic Engine"),
	)
	pterm.Println(pterm.Gray("  Engineered in Go | Multi-threaded Worker Pools | Embedded Persistence"))
	pterm.Println(pterm.Gray("  Type 'help' for available commands, Tab for autocomplete, 'exit' to quit.\n"))
}

// FormatPrompt generates the dynamic shell prompt with workspace context.
func FormatPrompt(workspace string) string {
	if workspace == "" {
		workspace = "default"
	}
	return fmt.Sprintf("\033[1;36mfalcon\033[0m (\033[1;33m%s\033[0m) > ", workspace)
}

// PrintSuccess outputs a success badge message.
func PrintSuccess(format string, a ...interface{}) {
	pterm.Success.Printf(format+"\n", a...)
}

// PrintInfo outputs an info badge message.
func PrintInfo(format string, a ...interface{}) {
	pterm.Info.Printf(format+"\n", a...)
}

// PrintWarning outputs a warning badge message.
func PrintWarning(format string, a ...interface{}) {
	pterm.Warning.Printf(format+"\n", a...)
}

// PrintError outputs an error badge message.
func PrintError(format string, a ...interface{}) {
	pterm.Error.Printf(format+"\n", a...)
}

// Truncate safely cuts a string with an ellipsis if it exceeds maxLen.
func Truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
