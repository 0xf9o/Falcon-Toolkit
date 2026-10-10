// Package cli provides command parsing, routing, help display, and command implementations.
package cli

import (
	"strings"
	"unicode"
)

// ParsedCommand represents the structured result of tokenizing and parsing CLI input.
type ParsedCommand struct {
	RawInput        string
	Name            string
	Subcommands     []string
	Args            []string
	Flags           map[string]string
	OutputFormat    string
	IsHelpRequested bool
}

// Tokenize splits a command line string into tokens while preserving quoted substrings.
func Tokenize(input string) []string {
	var tokens []string
	var current strings.Builder
	var inQuote rune
	var escaped bool

	for _, r := range input {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			continue
		}

		if inQuote != 0 {
			if r == inQuote {
				inQuote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}

		if r == '"' || r == '\'' {
			inQuote = r
			continue
		}

		if unicode.IsSpace(r) {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// Parse parses a raw command string or token slice into a ParsedCommand.
func Parse(input string) *ParsedCommand {
	tokens := Tokenize(strings.TrimSpace(input))
	return ParseTokens(tokens, input)
}

// ParseTokens parses a tokenized command list.
func ParseTokens(tokens []string, rawInput string) *ParsedCommand {
	cmd := &ParsedCommand{
		RawInput: rawInput,
		Flags:    make(map[string]string),
	}

	if len(tokens) == 0 {
		return cmd
	}

	cmd.Name = strings.ToLower(tokens[0])

	var positional []string
	i := 1

	for i < len(tokens) {
		t := tokens[i]

		// Long flag: --flag or --flag=value
		if strings.HasPrefix(t, "--") {
			flagPart := strings.TrimPrefix(t, "--")
			if strings.Contains(flagPart, "=") {
				parts := strings.SplitN(flagPart, "=", 2)
				cmd.Flags[parts[0]] = parts[1]
			} else {
				// Check if next token is a value or another flag
				if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") {
					cmd.Flags[flagPart] = tokens[i+1]
					i++
				} else {
					cmd.Flags[flagPart] = "true"
				}
			}
			// Short flag: -f or -o json
		} else if strings.HasPrefix(t, "-") && len(t) > 1 {
			flagPart := strings.TrimPrefix(t, "-")
			if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") {
				cmd.Flags[flagPart] = tokens[i+1]
				i++
			} else {
				cmd.Flags[flagPart] = "true"
			}
		} else {
			positional = append(positional, t)
		}
		i++
	}

	// Check for help flag
	if cmd.Flags["help"] == "true" || cmd.Flags["h"] == "true" {
		cmd.IsHelpRequested = true
	}

	// Check output format flag
	if val, ok := cmd.Flags["output"]; ok {
		cmd.OutputFormat = strings.ToLower(val)
	} else if val, ok := cmd.Flags["o"]; ok {
		cmd.OutputFormat = strings.ToLower(val)
	} else if val, ok := cmd.Flags["format"]; ok {
		cmd.OutputFormat = strings.ToLower(val)
	}

	cmd.Args = positional
	return cmd
}
