// Package config manages Falcon ToolKit configuration from environment
// variables and defaults. No secrets are stored.
package config

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	// Version is the current Falcon ToolKit version.
	Version = "4.0.0"

	// ProductName is the full product name.
	ProductName = "Falcon ToolKit"

	// ProductFull is the full product description.
	ProductFull = "Falcon ToolKit v4.0.0 — Red Team Network Intelligence CLI"

	// ShortDescription is the short product description.
	ShortDescription = "Network Intelligence & Assessment"

	// RulesetVersion is the current assessment ruleset version.
	RulesetVersion = "1.0.0"

	// SchemaVersionLatest is the latest database schema version.
	SchemaVersionLatest = 3

	// DefaultWorkspace is the name of the default workspace.
	DefaultWorkspace = "default"
)

// Config holds the runtime configuration.
type Config struct {
	Home          string
	Workspace     string
	WorkspaceName string
	Debug         bool
	ReadOnly      bool
	ColorEnabled  bool
	NoColor       bool
	NoBanner      bool
	Quiet         bool
	Verbose       bool
	Timing        bool
	OutputFormat  string
	ShowWorkspace bool // Show workspace name in prompt
}

// Load reads configuration from environment variables and applies defaults.
func Load() *Config {
	cfg := &Config{
		Home:          defaultHome(),
		Workspace:     DefaultWorkspace,
		WorkspaceName: DefaultWorkspace,
		ColorEnabled:  true,
		NoColor:       false,
		OutputFormat:  "table",
	}

	if v := os.Getenv("FALCON_HOME"); v != "" {
		cfg.Home = v
	}
	if v := os.Getenv("FALCON_WORKSPACE"); v != "" {
		cfg.Workspace = v
		cfg.WorkspaceName = v
	}
	if os.Getenv("FALCON_DEBUG") == "1" {
		cfg.Debug = true
	}
	if os.Getenv("FALCON_READ_ONLY") == "1" {
		cfg.ReadOnly = true
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		cfg.ColorEnabled = false
		cfg.NoColor = true
	}
	if os.Getenv("TERM") == "dumb" {
		cfg.ColorEnabled = false
		cfg.NoColor = true
	}

	return cfg
}

// WorkspacesDir returns the path to the workspaces directory.
func (c *Config) WorkspacesDir() string {
	if c.Home == "" {
		c.Home = defaultHome()
	}
	return filepath.Join(c.Home, "workspaces")
}

// WorkspaceDir returns the path to a specific workspace directory.
func (c *Config) WorkspaceDir(name string) string {
	return filepath.Join(c.WorkspacesDir(), name)
}

// DatabasePath returns the path to the SQLite database for a workspace.
func (c *Config) DatabasePath(name string) string {
	return filepath.Join(c.WorkspaceDir(name), "falcon.db")
}

// WorkspaceDBPath is an alias for DatabasePath.
func (c *Config) WorkspaceDBPath(name string) string {
	return c.DatabasePath(name)
}

// CurrentDatabasePath returns the database path for the active workspace.
func (c *Config) CurrentDatabasePath() string {
	ws := c.Workspace
	if ws == "" {
		ws = c.WorkspaceName
	}
	if ws == "" {
		ws = DefaultWorkspace
	}
	return c.DatabasePath(ws)
}

// HistoryFile returns the path to the REPL history file.
func (c *Config) HistoryFile() string {
	return filepath.Join(c.Home, "history")
}

// ConfigFile returns the path to the configuration file.
func (c *Config) ConfigFile() string {
	return filepath.Join(c.Home, "config.json")
}

func defaultHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		if runtime.GOOS == "windows" {
			home = os.Getenv("USERPROFILE")
		} else {
			home = os.Getenv("HOME")
		}
	}
	return filepath.Join(home, ".falcon")
}

// BuildInfo holds build-time metadata injected via ldflags.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
	OS        string
	Arch      string
}

// GetBuildInfo returns current build information.
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

var (
	commit    = "dev"
	buildDate = "unknown"
)
