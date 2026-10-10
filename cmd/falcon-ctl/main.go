package main

import (
	"fmt"
	"os"

	"github.com/falcon-toolkit/falcon/internal/cli"
	"github.com/falcon-toolkit/falcon/internal/config"
	"github.com/falcon-toolkit/falcon/internal/core"
	"github.com/falcon-toolkit/falcon/internal/terminal"
)

func main() {
	cfg := config.Load()
	style := terminal.NewStyle(cfg.NoColor)

	if !cfg.NoBanner {
		banner := terminal.RenderBanner(style)
		fmt.Println(banner)
	}

	session := core.NewSession()

	repl, err := cli.NewREPL(session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal initializing REPL: %v\n", err)
		os.Exit(1)
	}

	if err := repl.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Session error: %v\n", err)
		os.Exit(1)
	}
}
