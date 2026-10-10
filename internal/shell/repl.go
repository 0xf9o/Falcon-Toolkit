// Package shell provides the interactive REPL (Read-Eval-Print Loop) environment for Falcon ToolKit.
package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/app"
	"github.com/falcon-toolkit/falcon/internal/cli"
	"github.com/falcon-toolkit/falcon/internal/terminal"
)

// REPL runs the interactive command shell.
type REPL struct {
	app      *app.App
	registry *cli.CommandRegistry
	style    *terminal.Style
	reader   *bufio.Reader
}

// New creates a new REPL instance.
func New(appInstance *app.App, style *terminal.Style) *REPL {
	return &REPL{
		app:      appInstance,
		registry: cli.NewCommandRegistry(style),
		style:    style,
		reader:   bufio.NewReader(os.Stdin),
	}
}

// Run starts the REPL loop until exit or EOF.
func (r *REPL) Run() error {
	for {
		prompt := "falcon > "
		if r.style != nil && r.style.IsColorEnabled() {
			prompt = r.style.Brand("falcon") + " > "
		}

		fmt.Print(prompt)

		line, err := r.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("\nExiting Falcon ToolKit.")
				return nil
			}
			return fmt.Errorf("reading input: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Execute command through registry
		if err := r.registry.Execute(r.app, line); err != nil {
			fmt.Printf("%s\n\n", err.Error())
		} else {
			fmt.Println()
		}
	}
}
