<div align="center">
  <h1>Falcon ToolKit</h1>
  <p>Evidence-first network discovery, protocol interrogation, and attack-path assessment platform.</p>
  <p>
    <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.22+" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square" alt="Apache 2.0 License" /></a>
    <a href="#"><img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-22272e?style=flat-square" alt="Platform Support" /></a>
    <a href="#"><img src="https://img.shields.io/badge/Storage-Authoritative_SQLite-38bdf8?style=flat-square" alt="Authoritative SQLite" /></a>
    <a href="#"><img src="https://img.shields.io/badge/Engine-Concurrent_Worker_Pool-6366f1?style=flat-square" alt="Worker Pool Engine" /></a>
  </p>
</div>

---

## Overview

Falcon ToolKit is a high-performance network intelligence and security assessment framework written in Go. It enables authorized security operators, system administrators, and infrastructure engineers to perform deterministic host discovery, deep protocol interrogation, scope-bounded port audits, identity fusion, and graph-based attack path modeling without external runtime dependencies.

---

## How to Use

### Method 1 - Interactive Controller (Recommended)

The interactive REPL controller (`falcon-ctl`) provides live autocompletion, real-time command evaluation, scope validation, and embedded analytics listeners.

1. Launch the interactive session:
   ```bash
   falcon-ctl
   ```

2. Establish operational scope and target lists:
   ```text
   falcon> scope add 10.10.0.0/16
   falcon> scope add 192.168.1.0/24
   falcon> target add 10.10.10.5
   falcon> target list
   ```

3. Execute audits and inspect graph relationships:
   ```text
   falcon> run audit --workers 64
   falcon> show matrix
   falcon> show graph --target 10.10.10.5
   falcon> serve --port 8080
   ```

---

### Method 2 - Direct CLI Automation

The standalone CLI binary (`falcon`) provides non-interactive command execution for automated assessment pipelines and CI/CD integration.

1. Initialize a dedicated workspace:
   ```bash
   falcon workspace create internal-audit
   falcon scope add --cidr 10.10.0.0/16
   ```

2. Import third-party reconnaissance outputs or seed targets:
   ```bash
   falcon import --format nmap --file network-scan.xml
   ```

3. Run targeted assessment and export structured evidence:
   ```bash
   falcon assess --targets 10.10.0.0/24 --rate 500 --output evidence.json
   falcon report --format html --out assessment-report.html
   ```

---

### Method 3 - Headless Daemon & REST API

Run the embedded HTTP daemon to power remote orchestration, continuous monitoring, and web-based reporting interfaces.

1. Start the HTTP listener:
   ```bash
   falcon serve --bind 127.0.0.1:8080 --db ./falcon.db
   ```

2. Query live target state and reachability matrices:
   ```bash
   curl -s http://127.0.0.1:8080/api/v1/targets | jq .
   curl -s http://127.0.0.1:8080/api/v1/matrix  | jq .
   ```

---

## Core Capabilities

| Capability | Description | Status |
| :--- | :--- | :--- |
| **Scope Guard Engine** | Hard boundary enforcement preventing out-of-scope packet transmission | Active |
| **Worker Pool Engine** | Deterministic concurrency scheduler with configurable rate-limiting | Active |
| **Protocol Handshakers** | Native protocol interrogation (SMB2 NTLM, SNMP, OT/ICS, TLS, SSH) | Active |
| **Reachability Matrix** | Bi-directional visibility and ACL validation across enterprise subnets | Active |
| **Attack Graph Engine** | Shortest-path exposure analysis using Dijkstra algorithm | Active |
| **Identity Fusion** | Multi-attribute host correlation across MAC, NetBIOS, DNS, and IP drift | Active |
| **Authoritative Storage** | Self-contained SQLite persistence with zero external service dependencies | Active |
| **Multi-Format Export** | HTML, JSON, Markdown, and CSV structured reporting | Active |

---

## Protocol Engine Coverage

Falcon ToolKit implements handshakes natively to extract banners, negotiate security levels, and identify configuration weaknesses without relying on external system utilities:

- **Active Directory & SMB:** Native SMB2/3 negotiation, NTLM challenge inspection (domain, OS build, NetBIOS name), and signing policy detection.
- **SNMP Management:** Community string querying across SNMP v1, v2c, and v3 contexts.
- **Industrial Control Systems (OT/ICS):** Modbus TCP unit ID inspection, Siemens S7 communication handshakes, BACnet device identification, and EtherNet/IP interrogation.
- **Infrastructure Services:** TLS certificate chain verification, SSH banner and key exchange identification, and HTTP/S header auditing.

---

## OpSec & Safety Controls

- **Pre-Execution Scope Bounds:** Every destination IP address is evaluated against the configured CIDR scope prior to socket allocation. Out-of-scope targets are dropped at the engine layer.
- **Deterministic Rate Limiting:** Global token-bucket pacing prevents network saturation, link congestion, and IDS/IPS alarm storms during active assessments.
- **Bounded Worker Pool:** Fixed thread allocation avoids operating system socket exhaustion and resource starvation.

---

## Installation & Building from Source

### Prerequisites

- Go 1.22 or higher
- GCC or compatible C compiler (for SQLite driver)

### Build Commands

```bash
# Clone the repository
git clone https://github.com/0xf9o/Falcon-Toolkit.git
cd Falcon-Toolkit

# Download dependencies
go mod download

# Build both binaries
go build -o bin/falcon ./cmd/falcon
go build -o bin/falcon-ctl ./cmd/falcon-ctl
```

On Windows:
```powershell
go build -o bin\falcon.exe .\cmd\falcon
go build -o bin\falcon-ctl.exe .\cmd\falcon-ctl
```

---

## Troubleshooting & Verification

- **Verify Database Schema:**
  ```bash
  falcon db verify
  ```
- **Check Scope Rules:**
  ```bash
  falcon scope list
  ```
- **Test Ingestion Parser:**
  ```bash
  falcon import --test --file fixtures/nmap-sample.xml
  ```

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
