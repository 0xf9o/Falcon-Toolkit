# ⚡ Falcon v3.0 — High-Performance Network Diagnostics & TUI Framework

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Build](https://img.shields.io/badge/Build-Passing-39FF14?style=flat)](#installation)
[![Tests](https://img.shields.io/badge/Tests-29%20Passing-39FF14?style=flat)](#testing)
[![Persistence](https://img.shields.io/badge/Storage-BoltDB%20Embedded-FF007F?style=flat)](#persistence)
[![TUI](https://img.shields.io/badge/TUI-Bubbletea%20%2B%20Lipgloss-9D00FF?style=flat)](#tui-mode)
[![License](https://img.shields.io/badge/License-MIT-00F5FF?style=flat)](#license)

> **Lead Architect:** Faisal Al-Harbi (0xF9o)  
> **Stack:** Pure Go · BubbleTea TUI · BoltDB · Cobra CLI · Goroutine Worker Pools · Token Bucket Rate Limiter · YAML Signature Engine

---

Falcon v3.0 is a **standalone, single-binary** network auditing and diagnostic framework compiled from pure Go. It operates with **three execution modes**:

| Mode | Trigger | Description |
| :--- | :--- | :--- |
| **Full-Screen TUI** | `falcon` (no args) or `falcon tui` | Cyberpunk Bubbletea dashboard — keyboard-driven |
| **Interactive Shell** | `falcon repl` | Readline REPL with Tab autocomplete & history |
| **Direct CLI** | `falcon scan <target>` | One-off commands, Unix pipe-friendly `--json` mode |

---

## Architecture

```text
falcon/
├── cmd/
│   └── falcon/
│       └── main.go              # Entry point — tri-mode dispatch (TUI / REPL / CLI)
├── internal/
│   ├── app/
│   │   ├── tui.go               # Bubbletea full-screen TUI (5-tab cyberpunk dashboard)
│   │   └── shell.go             # Interactive readline REPL shell
│   ├── engine/
│   │   ├── pool.go              # Generic Worker Pool — Pool[T, R] with context cancellation
│   │   ├── pool_test.go         # Unit tests: concurrency, timeouts, panic safety, rate limiting
│   │   └── limiter.go           # Token-Bucket Rate Limiter (RateLimiter interface)
│   ├── modules/
│   │   ├── port.go              # TCP port scanner — socket health, banner grab, HTTP header probe
│   │   ├── subdomain.go         # Passive subdomain discovery via crt.sh CT logs + DNS resolver
│   │   ├── matcher.go           # YAML Signature Engine — regex-based protocol identification
│   │   └── matcher_test.go      # Tests: all built-in sigs, port filtering, YAML load, ParsePortList
│   ├── probe/
│   │   ├── tcp.go               # Low-level TCP probe, TLS fingerprinter, HTTP metadata extractor
│   │   └── probe_test.go        # Tests: open/closed/cancelled TCP, HTTP title/redirect, TLS naming
│   ├── db/
│   │   ├── store.go             # BoltDB persistence: ports, subdomains, workspaces, CSV/JSON export
│   │   ├── store_test.go        # Tests: full CRUD, upsert, topology graph, export
│   │   └── topology.go          # Topology graph: AssetNode, ServiceNode, TopologyEdge, ASCII tree
│   └── ui/
│       ├── cyberpunk.go         # Lipgloss cyberpunk theme: color palette, styles, header, footer
│       └── banner.go            # pterm ASCII banner, shell prompt, Print{Success,Info,Warning,Error}
├── signatures/                  # External YAML signature rule sets (hot-loadable at runtime)
│   ├── http-servers.yaml        # IIS, Lighttpd, Gunicorn, Tomcat, Jetty, Express, PHP
│   ├── databases.yaml           # MongoDB, MSSQL, Oracle, Memcached, Elasticsearch, Cassandra
│   └── infrastructure.yaml     # Telnet, RDP, VNC, IMAP, POP3, SIP, Docker API, Kubernetes API
├── bin/
│   └── falcon.exe               # Compiled standalone binary
├── go.mod
└── README.md
```

---

## Key Engineering Features

### 1. Generic Worker Pool (`internal/engine/pool.go`)
```go
// Type-safe, generic — no interface{} boxing
pool, _ := engine.NewPool[int, *db.PortRecord](ctx, cfg, taskFn)
pool.Submit(ctx, 443)
for res := range pool.Results() { ... }
pool.Stop()
```
- **Two-level context cancellation**: pool-level + per-task timeout
- **Panic isolation**: each worker wraps execution in `recover()` — one faulty task never crashes the pool
- **Graceful shutdown**: `Stop()` drains the queue before closing; `Cancel()` aborts immediately
- **Thread-safe `Stats()`**: atomic counters for submitted/completed/failed/active tasks

### 2. Token-Bucket Rate Limiter (`internal/engine/limiter.go`)
- Pre-fills burst capacity; replenishes at `ratePerSec` intervals
- Fully context-aware — `Wait(ctx)` returns immediately on cancellation
- Pluggable via `RateLimiter` interface — swap implementations without touching pool code

### 3. YAML Signature Engine (`internal/modules/matcher.go`)
```yaml
- id: ssh-openssh
  name: OpenSSH Server
  protocol: tcp
  ports: [22, 2222]
  matches:
    - regex: "^SSH-[0-9.]+-OpenSSH_([0-9a-zA-Z.]+)"
      service: SSH
      product: OpenSSH
      version_group: 1
```
- **Port-scoped matching**: signatures specify allowed ports, preventing false positives
- **Version extraction**: capture group `version_group` pulls semantic versions from banners
- **Hot-loadable**: `engine.LoadDirectory("signatures/")` appends external `.yaml` rule packs at runtime
- **9 built-in signatures** covering SSH, Nginx, Apache, Caddy, Redis, MySQL, PostgreSQL, FTP, SMTP

### 4. Advanced Probe Package (`internal/probe/tcp.go`)
| Function | Description |
| :--- | :--- |
| `TCPProbe(ctx, target)` | TCP connectivity + banner grab (300ms deadline) |
| `TLSProbe(ctx, target)` | Full TLS handshake → version, cipher suite, CN, SANs, expiry |
| `HTTPProbe(ctx, target)` | GET request → status, server header, page `<title>`, redirect |

### 5. Embedded BoltDB Topology Graph (`internal/db/topology.go`)
```
Target Asset Graph [target_corp]
├── [DOMAIN] example.com
│   ├── ↳ [IP] 93.184.216.34
│   │   └── :443/tcp -> HTTPS (Nginx 1.24.0) [12ms]
│   │   └── :22/tcp  -> SSH (OpenSSH 8.9p1) [3ms]
```
- Structured `Domain → IP → Service` hierarchy stored in BoltDB buckets
- `RenderTopologyTree()` generates live ASCII tree in TUI and CLI `topology view` output

---

## Installation & Compilation

```bash
# Requires Go 1.21+
git clone https://github.com/falcon-toolkit/falcon.git
cd falcon

# Windows
go build -ldflags="-s -w" -o bin/falcon.exe ./cmd/falcon

# Linux / macOS
go build -ldflags="-s -w" -o bin/falcon ./cmd/falcon
```

---

## Usage Reference

### TUI Mode
```bash
./bin/falcon          # Launches full-screen Cyberpunk TUI
./bin/falcon tui
```

**Keyboard shortcuts:**

| Key | Action |
| :--- | :--- |
| `Tab` / `Shift+Tab` | Cycle through tabs |
| `1` – `5` | Jump to tab directly |
| `S` | Open Quick Scan prompt |
| `W` | Switch / create workspace |
| `R` | Refresh data from DB |
| `Q` / `Ctrl+C` | Quit |

**Tabs:** `DASHBOARD` · `TOPOLOGY GRAPH` · `PORTS & SERVICES` · `YAML SIGNATURES` · `WORKSPACES`

---

### Interactive Shell (REPL) Mode
```bash
./bin/falcon repl
```

```
  ______      _                     ____   ___
 |  ____/\   | |                   |___ \ / _ \
 | |__ /  \  | |     ___ ___  _ __   __) | | | |
 |  __/ /\ \ | |    / __/ _ \| '_ \ |__ <| | | |
 | | / ____ \| |___| (_| (_) | | | |___) | |_| |
 |_|/_/    \_\______\___\___/|_| |_|____/ \___/

▶ Falcon v3.0.0-PRO
falcon (default) >
```

| Command | Example | Description |
| :--- | :--- | :--- |
| `scan` | `scan 192.168.1.1 -p 80,443,22 -w 100 -t 500` | High-speed TCP + HTTP scan |
| `subdomains` | `subdomains example.com -w 30` | Passive CT log + DNS discovery |
| `workspace` | `workspace set target_corp` | Create/switch workspace |
| `show` | `show ports` / `show subdomains` | Display saved findings |
| `export` | `export json report.json` | Export JSON/CSV reports |
| `help` | `help` | Command reference |

---

### Direct CLI Mode

#### Port Scanning
```bash
# Scan common ports with 100 workers, 500ms timeout
./bin/falcon scan 192.168.1.1 -p 22,80,443,3306,5432 -w 100 -t 500

# Scan full port range
./bin/falcon scan 10.0.0.5 -p 1-65535 -w 200 -t 300 -r 500

# Stream results as NDJSON for piping
./bin/falcon scan 10.0.0.1 -p 80,443,8080 --json | jq '.port'
```

#### Subdomain Discovery
```bash
./bin/falcon subdomains example.com -w 50
./bin/falcon subdomains example.com --json | jq '.subdomain'
```

#### Topology & Workspace
```bash
./bin/falcon topology view          # ASCII tree render
./bin/falcon topology json          # Raw JSON graph export

./bin/falcon workspace list         # List all workspaces
./bin/falcon workspace set corp-q4  # Switch workspace
./bin/falcon scan 10.0.0.1 -W corp-q4   # Scan into specific workspace
```

#### Historical Data & Export
```bash
./bin/falcon show ports -W corp-q4
./bin/falcon show subdomains

./bin/falcon export json report.json
./bin/falcon export csv ports    ports.csv
./bin/falcon export csv subdomains subs.csv
```

#### Loading Custom YAML Signatures
Custom signatures are auto-loaded from the `signatures/` directory at startup if the binary is run from the project root. To extend, add any `.yaml` file following the signature format:

```yaml
- id: my-custom-service
  name: My Custom Service
  protocol: tcp
  ports: [12345]
  matches:
    - regex: "^HELLO_([A-Z]+)_CUSTOM"
      service: MyService
      product: CustomProduct
      version_group: 1
```

---

## Testing

```bash
# Run all tests
go test -v ./...

# Run specific packages
go test -v ./internal/engine/...    # Worker pool & rate limiter (6 tests)
go test -v ./internal/modules/...   # Signature engine & scanner (12 tests)
go test -v ./internal/db/...        # BoltDB persistence (10 tests)
go test -v ./internal/probe/...     # TCP/HTTP/TLS probes (7 tests)

# Race condition detection
go test -race ./...
```

**Test Coverage Summary:**

| Package | Tests | Covers |
| :--- | :---: | :--- |
| `engine` | 6 | Concurrency, context cancel, panic recovery, rate limiting, graceful stop |
| `modules` | 12 | All built-in sigs, port filtering, custom YAML load, invalid regex, ParsePortList |
| `db` | 10 | Workspace CRUD, port/subdomain upsert, topology graph, JSON/CSV export |
| `probe` | 7 | TCP open/closed/cancelled, HTTP title/redirect, banner sanitise, TLS naming |
| **Total** | **35** | |

---

## Concurrency Architecture

```
RunPortScan(ctx, opts)
│
├── engine.NewPool[int, *PortRecord](ctx, cfg, probePort)
│   ├── Worker × N goroutines  ←─── taskCh (buffered)
│   │   └── probePort(taskCtx, port)
│   │       ├── net.DialContext  (TCP connect + latency)
│   │       ├── inspectBanner    (300ms read deadline)
│   │       └── probeHTTP        (GET + Server header + <title>)
│   └── resultCh (buffered) ──► Consumer goroutine
│
├── Producer goroutine
│   └── pool.Submit(ctx, port) × len(ports)
│       └── pool.Stop() on completion
│
└── Rate Limiter (optional)
    └── TokenBucketLimiter.Wait(poolCtx) before each task
```

---

## License

MIT License — Copyright (c) 2026 Faisal Al-Harbi (0xF9o)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.
