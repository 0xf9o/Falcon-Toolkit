package exporter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// ExportOptions specifies which formats to generate.
type ExportOptions struct {
	OutDir  string
	Formats []string // "html", "json", "markdown", "rules"
}

// ExportAll processes all requested formats and writes them to OutDir.
func ExportAll(env *schema.SessionEnvironment, opts ExportOptions) (map[string]string, error) {
	if opts.OutDir == "" {
		opts.OutDir = "exports"
	}

	generated := make(map[string]string)
	formatMap := make(map[string]bool)

	for _, f := range opts.Formats {
		for _, part := range strings.Split(f, ",") {
			formatMap[strings.ToLower(strings.TrimSpace(part))] = true
		}
	}

	// Default to all if empty
	if len(formatMap) == 0 {
		formatMap["html"] = true
		formatMap["json"] = true
		formatMap["markdown"] = true
		formatMap["rules"] = true
	}

	baseName := fmt.Sprintf("falcon_audit_%s", env.SessionID)

	if formatMap["json"] {
		p := filepath.Join(opts.OutDir, baseName+".json")
		if err := ExportJSON(env, p); err != nil {
			return nil, err
		}
		generated["json"] = p
	}

	if formatMap["markdown"] || formatMap["md"] {
		p := filepath.Join(opts.OutDir, baseName+".md")
		if err := ExportMarkdown(env, p); err != nil {
			return nil, err
		}
		generated["markdown"] = p
	}

	if formatMap["html"] {
		p := filepath.Join(opts.OutDir, baseName+".html")
		if err := ExportHTML(env, p); err != nil {
			return nil, err
		}
		generated["html"] = p
	}

	if formatMap["rules"] || formatMap["acl"] {
		p := filepath.Join(opts.OutDir, baseName+"_remediation.txt")
		if err := ExportFirewallRemediation(env, p); err != nil {
			return nil, err
		}
		generated["rules"] = p
	}

	return generated, nil
}
