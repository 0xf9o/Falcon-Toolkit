package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/app"
	"github.com/falcon-toolkit/falcon/internal/cli"
	"github.com/falcon-toolkit/falcon/internal/config"
	"github.com/falcon-toolkit/falcon/internal/shell"
	"github.com/falcon-toolkit/falcon/internal/terminal"
)

func main() {
	cfg := config.Load()
	style := terminal.NewStyle(cfg.NoColor)

	appInstance := app.New(cfg)
	defer appInstance.Close()

	// Direct CLI invocation mode
	if len(os.Args) > 1 {
		rawInput := strings.Join(os.Args[1:], " ")
		registry := cli.NewCommandRegistry(style)
		if err := registry.Execute(appInstance, rawInput); err != nil {
			fmt.Fprintf(os.Stderr, "%s %s\n", style.Error("Error:"), err.Error())
			os.Exit(1)
		}
		return
	}

	// Interactive REPL mode
	if !cfg.NoBanner {
		banner := terminal.RenderBanner(style)
		fmt.Println(banner)
	}

	repl := shell.New(appInstance, style)
	if err := repl.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Shell error: %v\n", err)
		os.Exit(1)
	}
}
