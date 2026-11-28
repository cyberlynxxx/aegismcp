<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cyberlynxxx/aegismcp/main/assets/banner-dark.svg">
  <img alt="AegisMCP - Active MCP Security Engine & Runtime Firewall" src="https://raw.githubusercontent.com/cyberlynxxx/aegismcp/main/assets/banner-light.svg" width="520">
</picture>

<p align="center">
  <strong>An Active MCP Security Engine & Runtime Firewall — live introspection, runtime proxy, cross-server rules, executive reporting.</strong>
</p>

<p align="center">
  <a href="https://github.com/cyberlynxxx/aegismcp/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/cyberlynxxx/aegismcp/actions/workflows/ci.yml/badge.svg">
  </a>
  <a href="https://github.com/cyberlynxxx/aegismcp/releases/latest">
    <img alt="Latest Release" src="https://img.shields.io/github/v/release/cyberlynxxx/aegismcp">
  </a>
  <a href="https://pypi.org/project/aegismcp-security/">
    <img alt="PyPI" src="https://img.shields.io/pypi/v/aegismcp-security">
  </a>
  <a href="LICENSE">
    <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg">
  </a>
  <a href="https://www.python.org/downloads/">
    <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#live-introspection-inspect">Live Inspect</a> ·
  <a href="#runtime-proxy-firewall-proxy">Runtime Proxy</a> ·
  <a href="#html-reports">HTML Reports</a> ·
  <a href="#benchmarks">Benchmarks</a> ·
  <a href="https://github.com/cyberlynxxx/aegismcp/releases">Releases</a>
</p>

---

## What It Detects

### Built-in Rules (MCP Config Files)

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `AMCP001` | CRITICAL | Direct shell execution (`bash`, `sh`, `cmd`, `powershell`) |
| `AMCP002` | MEDIUM | Unpinned `npx` packages (supply-chain risk) |
| `AMCP003` | HIGH | Overly broad or sensitive filesystem paths (`/`, `.ssh`, `.env`) |
| `AMCP004` | CRITICAL | Hardcoded API keys and tokens in `env` |
| `AMCP005` | CRITICAL | Tool poisoning & indirect prompt injection patterns |
| `AMCP006` | MEDIUM | Abnormally long tool descriptions used to hide payloads |
| `AMCP007` | CRITICAL | Invisible Unicode character smuggling (zero-width, bidi, tags) |
| `AMCP008` | HIGH | High-entropy unknown secrets detected via Shannon entropy |

### AST Rules (Python MCP Server Source)

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `AMCP101` | HIGH / CRITICAL | Command injection (`subprocess`, `os.system`, `os.popen`) |
| `AMCP102` | CRITICAL | Dynamic code execution (`eval`, `exec`) |
| `AMCP103` | HIGH | SSRF — dynamic URLs in HTTP calls (`requests`, `httpx`, etc.) |
| `AMCP104` | HIGH | Path traversal — user-controlled file paths |
| `AMCP105` | CRITICAL | Insecure deserialization (`pickle.loads`, `yaml.load` without SafeLoader) |

### Cross-Server Rules (Multi-Server Analysis)

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `AMCP201` | HIGH | Tool shadowing — duplicate tool names across servers |
| `AMCP202` | MEDIUM | Schema drift — tool signatures changed between lockfile and live |
| `AMCP203` | MEDIUM | Over-permissive tool input schemas (unconstrained dangerous params) |

### Runtime Proxy Rules (Active Firewall)

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `AMCP301` | CRITICAL | Prompt injection in tool call arguments |
| `AMCP302` | HIGH | Command injection patterns in arguments |
| `AMCP303` | HIGH | Path traversal in arguments |
| `AMCP304` | HIGH | SSRF patterns in URL arguments |
| `AMCP305` | MEDIUM | Rate limit exceeded |
| `AMCP306` | MEDIUM | Suspicious argument patterns (entropy, encoding) |
| `AMCP307` | LOW | Tool call audit logging |
| `AMCP308` | CRITICAL | Fail-closed: blocked by default unless explicitly allowed |
| `AMCP309` | CRITICAL | Server-to-client response inspection (indirect prompt injection, secret leakage, invisible Unicode) |

---

## Features

### Live MCP Server Introspection (`inspect`)
**New in v3.0.0** — Connect to running MCP servers via stdio or HTTP/SSE and run real-time security checks:

```bash
# Connect via stdio (spawn server)
aegismcp inspect --command "python server.py" --sarif live.sarif --fail-on HIGH

# Connect via HTTP/SSE
aegismcp inspect --url http://localhost:8000/mcp --html live-report.html

# Connect using platform config (Claude Desktop, Cursor, etc.)
aegismcp inspect --config-file ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Create lockfile from live server tools
aegismcp inspect --command "python server.py" --lock-output live.lock.json
```

**Real-time checks performed:**
- `AMCP005` Tool poisoning in live tool descriptions
- `AMCP006` Abnormally long descriptions hiding payloads
- `AMCP007` Invisible Unicode characters
- `AMCP201` Tool shadowing (duplicate names)
- `AMCP203` Over-permissive input schemas

### Runtime MCP Security Proxy (`proxy`)
**New in v3.0.0** — A transparent MCP proxy/firewall that sits between clients and servers, enforcing security policies in real-time with bidirectional protection:

```bash
# Run proxy between client and server (stdio)
aegismcp proxy --command "python server.py" --policy proxy-policy.yaml

# Run proxy with HTTP upstream
aegismcp proxy --url http://upstream:8000/mcp --port 8080

# Enable audit logging
aegismcp proxy --command "python server.py" --audit-log audit.log --fail-closed
```

**Proxy capabilities:**
- **Prompt injection detection** (AMCP301/AMCP309) — Blocks hidden LLM directives in arguments and responses
- **Anti-evasion normalizer** — Multi-stage URL/Base64/Hex decoding, Unicode NFKC normalization
- **Weighted scoring engine** — STRICT/BALANCED modes with configurable thresholds via policy
- **Command injection prevention** (AMCP302) — Detects shell metacharacters, command substitution
- **Path traversal blocking** (AMCP303) — Stops `../`, absolute paths, directory traversal
- **SSRF protection** (AMCP304) — Blocks private/internal IPs, localhost, metadata endpoints, alternative formats
- **Rate limiting** (AMCP305) — Configurable requests/second per client
- **Audit logging** (AMCP307) — JSONL structured logs for SIEM integration
- **Fail-closed defaults** (AMCP308) — Blocks unknown tools unless explicitly allowed
- **Server-to-client response inspection** (AMCP309) — Detects indirect prompt injection, secret leakage, invisible Unicode in tool results

### Rug-Pull Protection (`lock` / `verify`) — Enhanced
Lockfiles store SHA-256 hashes of server configs **and live tool definitions**.

```bash
# Create lockfile from static config (v2.x compatible)
aegismcp lock samples/vulnerable_mcp.json -o aegismcp.lock.json

# Create lockfile from LIVE server (NEW v3.0.0)
aegismcp lock --live --command "python server.py" -o aegismcp.lock.json
aegismcp lock --live --url http://localhost:8000/mcp -o aegismcp.lock.json

# Verify static config against lockfile
aegismcp verify samples/vulnerable_mcp.json -l aegismcp.lock.json

# Verify LIVE server against lockfile (NEW v3.0.0) — catches runtime rug-pulls!
aegismcp verify --live --command "python server.py" -l aegismcp.lock.json
aegismcp verify --live --url http://localhost:8000/mcp -l aegismcp.lock.json
```

### Python AST Scanning (`ast-scan`)
Static analysis of Python MCP server source code for runtime vulnerabilities:

```bash
# Excludes test files by default (tests/, test_*.py, *_test.py)
aegismcp ast-scan path/to/server.py --sarif ast-report.sarif --fail-on HIGH

# Include test files explicitly
aegismcp ast-scan path/to/server.py --include-tests --fail-on HIGH

# Export HTML report
aegismcp ast-scan path/to/server.py --html ast-report.html
```

### Cross-Server Analysis
Scan multiple MCP configs together to detect cross-server risks:

```bash
# Scan directory of configs for shadowing and drift
aegismcp scan configs/ --cross-server --sarif cross.sarif
```

### SARIF Export & CI/CD
All scan commands support SARIF 2.1.0 output:

```bash
aegismcp scan samples/vulnerable_mcp.json --sarif report.sarif --fail-on HIGH
aegismcp ast-scan server.py --sarif ast.sarif --fail-on CRITICAL
aegismcp inspect --command "python server.py" --sarif live.sarif
aegismcp verify --live --command "python server.py" -l lock.json --sarif verify.sarif
```

Use `--fail-on LEVEL` (LOW, MEDIUM, HIGH, CRITICAL) to gate CI pipelines.

### HTML Executive Reports
**New in v3.0.0** — Beautiful, interactive HTML reports with dark/light themes:

```bash
aegismcp scan samples/vulnerable_mcp.json --html report.html
aegismcp ast-scan server.py --html ast-report.html
aegismcp inspect --command "python server.py" --html live-report.html
```

Features: severity filters, searchable findings, collapsible details, print-optimized CSS, copy-to-clipboard SARIF/JSON.

### Extensible RuleRegistry
Built-in rules + custom regex rules loaded from config. No code changes needed for new patterns.

### Windows Compatible
All CLI output uses `[OK]`/`[FAIL]` markers (no Unicode symbols), colored output works in modern terminals.

---

## Quick Start

```bash
# Install from PyPI
pip install aegismcp-security

# Install from GitHub (for bleeding edge)
pip install git+https://github.com/cyberlynxxx/aegismcp.git

# Or from source (editable)
git clone https://github.com/cyberlynxxx/aegismcp
cd aegismcp
pip install -e .

# With dev dependencies (for testing)
pip install -e ".[dev]"
```

### Scan your MCP configs
```bash
# Auto-discover platform configs (Claude Desktop, Cursor, Windsurf, VS Code)
aegismcp scan --auto

# Scan a specific config file
aegismcp scan samples/vulnerable_mcp.json

# Export SARIF for GitHub Code Scanning
aegismcp scan samples/vulnerable_mcp.json --sarif report.sarif --fail-on HIGH

# Cross-server analysis
aegismcp scan configs/ --cross-server --html cross-report.html
```

### Live introspection (v3.0.0)
```bash
# Inspect a running server via stdio
aegismcp inspect --command "python server.py" --fail-on HIGH --html live.html

# Inspect via HTTP/SSE
aegismcp inspect --url http://localhost:8000/mcp --sarif live.sarif

# Create lockfile from live server
aegismcp inspect --command "python server.py" --lock-output live.lock.json
```

### Runtime proxy (v3.0.0)
```bash
# Proxy stdio server with security enforcement
aegismcp proxy --command "python server.py" --policy proxy-policy.yaml --audit-log audit.log

# Proxy HTTP upstream
aegismcp proxy --url http://upstream:8000/mcp --port 8080 --fail-closed
```

### Lock & verify (rug-pull protection)
```bash
# Create lockfile from static config
aegismcp lock samples/vulnerable_mcp.json -o aegismcp.lock.json

# Create lockfile from LIVE server (catches runtime tool definitions)
aegismcp lock --live --command "python server.py" -o aegismcp.lock.json

# Verify static config
aegismcp verify samples/vulnerable_mcp.json -l aegismcp.lock.json

# Verify LIVE server (detects runtime rug-pulls!)
aegismcp verify --live --command "python server.py" -l aegismcp.lock.json
```

### Scan Python MCP server source
```bash
# Scan for command injection, SSRF, path traversal, insecure deserialization
aegismcp ast-scan path/to/server.py --fail-on HIGH --html ast-report.html

# Include test files if needed
aegismcp ast-scan path/to/server.py --include-tests --fail-on HIGH
```

---

## GitHub Action

Use AegisMCP Security Scanner in your GitHub Actions workflows:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AegisMCP Scan
        uses: cyberlynxxx/aegismcp@v4.0.0
        with:
          target: .
          format: sarif
          fail-on: HIGH

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aegismcp-results.sarif
          category: aegismcp
```

---

## CLI Reference

```bash
aegismcp [--config CONFIG] [--no-color] <COMMAND>
```

| Command | Description |
| :--- | :--- |
| `scan` | Scan MCP config file(s) or directory |
| `inspect` | **v3.0.0** Live MCP server introspection via stdio/HTTP |
| `proxy` | **v3.0.0** Runtime MCP security proxy/firewall |
| `lock` | Create lockfile from MCP config or live server |
| `verify` | Verify MCP config or live server against lockfile |
| `ast-scan` | Scan Python MCP server source code for vulnerabilities |
| `--version` | Show version number |

### `scan`
```bash
aegismcp scan [TARGET] [--auto] [--cross-server] [--sarif FILE] [--html FILE] [--fail-on LEVEL] [--no-auto-discover]
```

| Option | Description |
| :--- | :--- |
| `TARGET` | Path to MCP config file or directory (optional if `--auto` or `auto_discover: true` in config) |
| `--auto` | Auto-discover platform MCP configs |
| `--cross-server` | Enable cross-server analysis (shadowing, drift) |
| `--sarif FILE` | Export SARIF report |
| `--html FILE` | Export HTML executive report |
| `--fail-on LEVEL` | Exit with error if findings ≥ LEVEL (LOW/MEDIUM/HIGH/CRITICAL) |
| `--no-auto-discover` | Disable platform auto-discovery |

### `inspect` (v3.0.0)
```bash
aegismcp inspect [--command CMD] [--url URL] [--config-file FILE] [--sarif FILE] [--html FILE] [--lock-output FILE] [--fail-on LEVEL] [--timeout SEC]
```

| Option | Description |
| :--- | :--- |
| `--command CMD` | Command to spawn MCP server (stdio) |
| `--url URL` | HTTP/SSE endpoint for MCP server |
| `--config-file FILE` | Path to platform MCP config file (Claude Desktop, Cursor, etc.) |
| `--sarif FILE` | Export SARIF report |
| `--html FILE` | Export HTML executive report |
| `--lock-output FILE` | Create lockfile from live server tools |
| `--fail-on LEVEL` | Exit with error if findings ≥ LEVEL |
| `--timeout SEC` | Connection timeout (default: 10s) |

### `proxy` (v3.0.0)
```bash
aegismcp proxy [--command CMD] [--url URL] [--port PORT] [--policy FILE] [--audit-log FILE] [--fail-closed] [--rate-limit RPS]
```

| Option | Description |
| :--- | :--- |
| `--command CMD` | Command to spawn upstream MCP server (stdio) |
| `--url URL` | HTTP/SSE upstream MCP server |
| `--port PORT` | Local port for HTTP proxy mode (default: 8080) |
| `--policy FILE` | Path to proxy policy YAML file |
| `--audit-log FILE` | Path to audit log (JSONL format) |
| `--fail-closed` | Block unknown tools by default |
| `--rate-limit RPS` | Requests per second limit (default: 100) |

#### Proxy Policy Options (proxy-policy.yaml)

| Setting | Description |
| :--- | :--- |
| `prompt_injection_mode` | `balanced` (default) or `strict` - weighted scoring threshold |
| `blocked_response_patterns` | List of regex patterns that trigger response blocking |
| `max_decode_depth` | Maximum iterations for normalization decoding (default: 5) |

### `lock`
```bash
aegismcp lock <CONFIG_FILE> [-o OUTPUT] [--live] [--command CMD] [--url URL]
```

| Option | Description |
| :--- | :--- |
| `CONFIG_FILE` | Path to MCP config file (not needed with `--live`) |
| `-o, --output` | Output lockfile path (default: `./aegismcp.lock.json`) |
| `--live` | Create lockfile from live server instead of static config |
| `--command CMD` | Spawn server command for live mode |
| `--url URL` | HTTP/SSE URL for live mode |

### `verify`
```bash
aegismcp verify <CONFIG_FILE> [-l LOCKFILE] [--live] [--command CMD] [--url URL] [--sarif FILE]
```

| Option | Description |
| :--- | :--- |
| `CONFIG_FILE` | Path to MCP config file (not needed with `--live`) |
| `-l, --lockfile` | Path to lockfile (default: `./aegismcp.lock.json`) |
| `--live` | Verify live server instead of static config |
| `--command CMD` | Spawn server command for live mode |
| `--url URL` | HTTP/SSE URL for live mode |
| `--sarif FILE` | Export SARIF report |

### `ast-scan`
```bash
aegismcp ast-scan <TARGET> [--sarif FILE] [--html FILE] [--fail-on LEVEL] [--include-tests]
```

| Option | Description |
| :--- | :--- |
| `TARGET` | Path to Python file or directory |
| `--sarif FILE` | Export SARIF report |
| `--html FILE` | Export HTML executive report |
| `--fail-on LEVEL` | Exit with error if findings ≥ LEVEL (default: HIGH) |
| `--include-tests` | Include test files/directories (`tests/`, `test_*.py`, `*_test.py`) |

---

## Proxy Policy Configuration

Create a `proxy-policy.yaml` to customize runtime enforcement:

```yaml
# proxy-policy.yaml
fail_closed: true                    # Block unknown tools by default
prompt_injection_mode: "balanced"    # STRICT or BALANCED - weighted scoring mode
allowed_tools:                       # Explicitly allowlisted tools
  - "safe_read"
  - "safe_write"
rate_limit: 50                       # Requests per second per client
block_patterns:                      # Custom block patterns
  - pattern: "internal\\.api\\.com"
    message: "Internal API access blocked"
audit_log: "audit.log"               # JSONL audit log path
log_level: "INFO"                    # DEBUG, INFO, WARNING, ERROR
```

---

## Example Output

```
[CRITICAL] AMCP001 - Direct Shell Execution Allowed
  Location: samples/vulnerable_mcp.json:mcpServers.unsafe-shell
  Detail:   Server 'unsafe-shell' invokes shell 'bash' directly.
  Fix:      Replace shell wrappers with a dedicated, scoped MCP server binary.

[HIGH] AMCP103 - Potential SSRF (Server-Side Request Forgery)
  File:     server.py:33:15
  Detail:   HTTP request with dynamic URL detected (requests.get)
  Fix:      Validate URLs against allowlist, block private/internal IPs

[CRITICAL] AMCP301 - Prompt Injection Detected (Runtime Proxy)
  Tool:     dangerous_tool
  Argument: command="rm -rf / ; ignore previous instructions"
  Action:   BLOCKED

Summary: 9 findings (6 CRITICAL, 2 HIGH, 1 MEDIUM) in 1 file(s)
```

---

## Benchmarks

AegisMCP v3.1.0 includes a comprehensive benchmarking suite (`scripts/benchmark.py`) measuring True Positive Rate (TPR), False Positive Rate (FPR), and latency.

| Component | Metric | Result | Notes |
| :--- | :--- | :--- | :--- |
| **AST Scanner (Python)** | TPR | 100% (54/54) | All injected vulnerabilities detected |
| | FPR | 0% (0/38) | Zero false positives on clean code |
| **Runtime Proxy** | Latency P99 | 3ms | 500 calls, stdio transport |
| | Throughput | ~300 req/s | Single-threaded, no rate limiting |
| **Cross-Server Analysis** | Tool Shadowing | 100% detection | Duplicate names across 1000 tools |
| | Permissive Schemas | 100% detection | Unconstrained dangerous params |
| **Config Scanner** | TPR (balanced) | ~30% | Rules target tool descriptions/env, not raw payloads |
| | TPR (strict) | ~30% | Same limitation by design |

> **Note**: Config scanner TPR appears lower because rules (AMCP005-AMCP008) are designed to analyze *tool descriptions* and *environment variables* in MCP config files, not arbitrary payload strings. The benchmark test feeds raw attack payloads directly, which is not the intended threat model.

### Running Benchmarks

```bash
# Run full benchmark suite
python scripts/benchmark.py

# Run specific benchmarks
python -m pytest tests/test_stress_v3.py -v -k "benchmark"
```

---

## Project Structure

```
aegismcp/
├── LICENSE                    # MIT License
├── aegismcp.yaml              # Example policy config
├── proxy-policy.yaml          # Example proxy policy
├── assets/
│   ├── banner-dark.svg        # Dark mode banner
│   └── banner-light.svg       # Light mode banner
├── samples/
│   ├── vulnerable_mcp.json    # Test config with all rule triggers
│   └── test_server.py         # Test Python server with AST vulnerabilities
├── tests/                     # Pytest test suite
│   ├── conftest.py
│   ├── test_scan.py
│   ├── test_lock_verify.py
│   ├── test_ast_scanner.py
│   ├── test_inspector.py
│   ├── test_proxy.py
│   ├── test_reporter.py
│   └── test_stress_v3.py      # v3.0.0 stress/e2e tests
├── .github/workflows/
│   └── ci.yml                 # GitHub Actions CI (Linux + Windows, Python 3.10/3.12)
├── src/aegismcp/
│   ├── __main__.py            # CLI entry point
│   ├── cli.py                 # Command implementations
│   ├── config.py              # aegismcp.yaml loader
│   ├── discovery.py           # Cross-platform auto-discovery
│   ├── lockfile.py            # SHA-256 lockfile (rug-pull protection)
│   ├── ast_scanner.py         # AST visitor for Python vulnerabilities
│   ├── scanner.py             # Main scanner engine
│   ├── sarif.py               # SARIF 2.1.0 exporter
│   ├── rules_core.py          # Finding dataclass
│   ├── inspector.py           # Live MCP introspection (JSON-RPC 2.0)
│   ├── proxy.py               # Runtime MCP security proxy
│   ├── reporter.py            # HTML/SARIF/Console reporters
│   ├── cross_server.py        # Cross-server analysis (shadowing, drift)
│   ├── html_report.py         # HTML report generator
│   └── rules/
│       ├── __init__.py        # Auto-registers built-in rules
│       ├── registry.py        # RuleRegistry class
│       └── builtins/
│           └── __init__.py    # AMCP001-AMCP008, AMCP101-AMCP105, AMCP201-AMCP203, AMCP301-AMCP308
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Issues and PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.