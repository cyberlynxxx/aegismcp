<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
  <img alt="AegisMCP — Security Scanner for MCP & AI Agents" src="assets/banner-light.svg" width="520">
</picture>

<p align="center">
  <strong>A lightweight, open-source Python security scanner and CI/CD linter for <strong>Model Context Protocol (MCP)</strong> configurations and AI agent tool definitions.</strong>
</p>

<p align="center">
  <a href="https://github.com/cyberlynxxx/aegismcp/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/cyberlynxxx/aegismcp/actions/workflows/ci.yml/badge.svg">
  </a>
  <a href="https://github.com/cyberlynxxx/aegismcp/releases/latest">
    <img alt="Latest Release" src="https://img.shields.io/github/v/release/cyberlynxxx/aegismcp?color=brightgreen">
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
  <a href="#-python-ast-scanning-ast-scan">AST Scan</a> · 
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

---

## Features

### 🔍 Auto-Discovery (`--auto`)
Automatically finds MCP configuration files across platforms:
- **Claude Desktop** (`claude_desktop_config.json`)
- **Cursor** (`mcp.json`)
- **Windsurf** (`mcp.json`)
- **VS Code** (`mcp.json`)

Works on **Windows**, **macOS**, and **Linux**.

```bash
aegismcp scan --auto
```

### ⚙️ Custom Policy Config (`aegismcp.yaml`)
Place `aegismcp.yaml` in your project root to customize:

```yaml
rules:
  AMCP002:
    enabled: false          # disable unpinned npx check
  AMCP003:
    severity: CRITICAL      # escalate path exposure

custom_rules:
  - id: "CUSTOM001"
    title: "Internal Domain Exposure"
    pattern: "internal\\.company\\.com"
    severity: "HIGH"
    target: "servers.env"
    message: "Server '{server}' env var '{key}' references internal domain"
    remediation: "Use environment variables instead"

ignore_paths:
  - "node_modules/**"
  - ".git/**"
  - "*.lock.json"

fail_on: "HIGH"             # CI exit code
auto_discover: true
```

```bash
aegismcp scan --config aegismcp.yaml samples/vulnerable_mcp.json
```

### 🔒 Rug-Pull Protection (`lock` / `verify`)
Lockfiles store SHA-256 hashes of server configs and tool definitions.

```bash
# Create lockfile from trusted config
aegismcp lock samples/vulnerable_mcp.json -o aegismcp.lock.json

# Verify current config matches lockfile (CI-friendly)
aegismcp verify samples/vulnerable_mcp.json -l aegismcp.lock.json
```

### 🐍 Python AST Scanning (`ast-scan`)
Static analysis of Python MCP server source code for runtime vulnerabilities:

```bash
# Excludes test files by default (tests/, test_*.py, *_test.py)
aegismcp ast-scan path/to/server.py --sarif ast-report.sarif --fail-on HIGH

# Include test files explicitly
aegismcp ast-scan path/to/server.py --include-tests --fail-on HIGH
```

### 📦 SARIF Export & CI/CD
All scan commands support SARIF 2.1.0 output:

```bash
aegismcp scan samples/vulnerable_mcp.json --sarif report.sarif --fail-on HIGH
aegismcp ast-scan server.py --sarif ast.sarif --fail-on CRITICAL
```

Use `--fail-on LEVEL` (LOW, MEDIUM, HIGH, CRITICAL) to gate CI pipelines.

### 🔌 Extensible RuleRegistry
Built-in rules + custom regex rules loaded from config. No code changes needed for new patterns.

### 🪟 Windows Compatible
All CLI output uses `[OK]`/`[FAIL]` markers (no Unicode symbols), colored output works in modern terminals.

---

## Quick Start

```bash
# Install from GitHub
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
```

### Lock & verify (rug-pull protection)
```bash
# Create lockfile from trusted config
aegismcp lock samples/vulnerable_mcp.json -o aegismcp.lock.json

# Verify in CI that config hasn't been tampered with
aegismcp verify samples/vulnerable_mcp.json -l aegismcp.lock.json
```

### Scan Python MCP server source
```bash
# Scan for command injection, SSRF, path traversal, insecure deserialization
aegismcp ast-scan path/to/server.py --fail-on HIGH

# Include test files if needed
aegismcp ast-scan path/to/server.py --include-tests --fail-on HIGH
```

---

## CLI Reference

```bash
aegismcp [--config CONFIG] [--no-color] <COMMAND>
```

| Command | Description |
| :--- | :--- |
| `scan` | Scan MCP config file(s) or directory |
| `lock` | Create lockfile from MCP config (rug-pull protection) |
| `verify` | Verify MCP config against lockfile |
| `ast-scan` | Scan Python MCP server source code for vulnerabilities |

### `scan`
```bash
aegismcp scan [TARGET] [--auto] [--sarif FILE] [--fail-on LEVEL] [--no-auto-discover]
```

| Option | Description |
| :--- | :--- |
| `TARGET` | Path to MCP config file or directory (optional if `--auto` or `auto_discover: true` in config) |
| `--auto` | Auto-discover platform MCP configs |
| `--sarif FILE` | Export SARIF report |
| `--fail-on LEVEL` | Exit with error if findings ≥ LEVEL (LOW/MEDIUM/HIGH/CRITICAL) |
| `--no-auto-discover` | Disable platform auto-discovery |

### `lock`
```bash
aegismcp lock <CONFIG_FILE> [-o OUTPUT]
```

| Option | Description |
| :--- | :--- |
| `CONFIG_FILE` | Path to MCP config file |
| `-o, --output` | Output lockfile path (default: `./aegismcp.lock.json`) |

### `verify`
```bash
aegismcp verify <CONFIG_FILE> [-l LOCKFILE]
```

| Option | Description |
| :--- | :--- |
| `CONFIG_FILE` | Path to MCP config file |
| `-l, --lockfile` | Path to lockfile (default: `./aegismcp.lock.json`) |

### `ast-scan`
```bash
aegismcp ast-scan <TARGET> [--sarif FILE] [--fail-on LEVEL] [--include-tests]
```

| Option | Description |
| :--- | :--- |
| `TARGET` | Path to Python file or directory |
| `--sarif FILE` | Export SARIF report |
| `--fail-on LEVEL` | Exit with error if findings ≥ LEVEL (default: HIGH) |
| `--include-tests` | Include test files/directories (`tests/`, `test_*.py`, `*_test.py`) |

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

Summary: 9 findings (6 CRITICAL, 2 HIGH, 1 MEDIUM) in 1 file(s)
```

---

## Project Structure

```
aegismcp/
├── LICENSE                    # MIT License
├── aegismcp.yaml              # Example policy config
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
│   └── test_ast_scanner.py
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
│   └── rules/
│       ├── __init__.py        # Auto-registers built-in rules
│       ├── registry.py        # RuleRegistry class
│       └── builtins/
│           └── __init__.py    # AMCP001-AMCP008 implementations
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Issues and PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.