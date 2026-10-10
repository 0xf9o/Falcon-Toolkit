package exporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// ExportJSON writes the full SessionEnvironment to an indented JSON file.
func ExportJSON(env *schema.SessionEnvironment, outputPath string) error {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing session environment: %w", err)
	}

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("writing JSON output to %q: %w", outputPath, err)
	}
	return nil
}
