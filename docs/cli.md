# Falcon ToolKit CLI Reference

## Invocation Modes

Falcon ToolKit supports two modes of execution:

### 1. Interactive REPL Mode
Running `falcon` with no arguments starts the interactive shell:
```bash
falcon
```

Features:
- Prompt indicating active workspace: `falcon [default] ❯ `
- Command completion and fuzzy suggestion on misspelled commands
- Single-letter shortcuts and aliases (`a`, `svc`, `if`, `net`, `ws`, `f`, `ev`, `g`, `q`)
- Help per command (`help <command>` or `<command> --help`)

### 2. Direct CLI Mode
Executing `falcon <command> [args]` runs a single command and returns to the host shell:
```bash
falcon version
falcon assets --output json
falcon assess --output json
```

## Global Flags

- `--output`, `-o`, `--format`: Format output as `table`, `json`, `ndjson`, or `markdown`.
- `--no-color`: Disable ANSI color escapes (can also set `NO_COLOR=1` environment variable).
- `--help`, `-h`: Show usage information for the specified command.
