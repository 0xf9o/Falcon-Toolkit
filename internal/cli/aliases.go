package cli

// DefaultAliases returns the canonical map of Falcon short aliases to full commands.
func DefaultAliases() map[string]string {
	return map[string]string{
		"a":     "assets",
		"svc":   "services",
		"if":    "interfaces",
		"net":   "networks",
		"ws":    "workspace",
		"f":     "findings",
		"ev":    "evidence",
		"g":     "graph",
		"q":     "quit",
		"exit":  "quit",
		"h":     "help",
		"?":     "help",
		"rep":   "report",
		"mod":   "modules",
		"imp":   "import",
		"audit": "audit",
		"tgt":   "target",
		"sc":    "scope",
		"pl":    "plan",
	}
}

// ResolveAlias checks if a given command name is an alias and returns the canonical name.
func ResolveAlias(name string) string {
	aliases := DefaultAliases()
	if canonical, ok := aliases[name]; ok {
		return canonical
	}
	return name
}
