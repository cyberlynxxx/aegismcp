# AegisMCP v3.0.0 Release Notes

**Release Date:** 2026-11-23  
**Version:** 3.0.0  
**Author:** cyberlynxxx

---

## Overview

Version 3.0.0 is a major release that transforms AegisMCP from a static configuration scanner into an **Active MCP Security Engine & Runtime Firewall**. This release introduces live server introspection, a runtime security proxy, cross-server analysis, and executive-grade HTML reporting — all designed to protect MCP (Model Context Protocol) deployments in production.

---

## What's New

### 🔍 Live MCP Server Introspection (`inspect` command)

Connect to running MCP servers in real-time for security analysis:

```bash
# Inspect a local server via stdio
aegismcp inspect --command "python server.py" --fail-on HIGH

# Inspect a remote server via HTTP/SSE
aegismcp inspect --url http://localhost:8000/mcp --html report.html

# Create a lockfile from live server tools
aegismcp inspect --command "python server.py" --lock-output aegismcp.lock.json
```

**Features:**
- **JSON-RPC 2.0 client** with proper asyncio subprocess handling for stdio transport
- **HTTP/SSE transport** support via `httpx` (optional dependency)
- **Full MCP handshake**: `initialize` → `notifications/initialized` → `tools/list` → `resources/list` → `prompts/list`
- **Live security checks**:
  - AMCP005: Tool poisoning patterns in descriptions
  - AMCP006: Abnormally long descriptions (>500 chars)
  - AMCP007: Hidden invisible Unicode characters
  - AMCP201: Tool shadowing (duplicate names within server)
  - AMCP203: Over-permissive input schemas (unconstrained dangerous params)
- **CI/CD gating** with `--fail-on` (CRITICAL/HIGH/MEDIUM/LOW)
- **Lockfile generation** from live servers with `--lock-output`

---

### 🛡️ Runtime MCP Security Proxy (`proxy` command)

Deploy a transparent security firewall between MCP clients and servers:

```bash
aegismcp proxy --command "python server.py" --policy proxy-policy.yaml --audit-log audit.log
```

**Security Layers (AMCP301–308):**

| Rule | Protection | Description |
|------|------------|-------------|
| AMCP301 | Prompt Injection | Blocks hidden LLM directives (`{{system(...)}}`, `<script>`, ignore instructions) |
| AMCP302 | Command Injection | Prevents shell metacharacters, command substitution (`$(...)`, `` `...` ``) |
| AMCP303 | Path Traversal | Blocks `../`, absolute paths, directory traversal attempts |
| AMCP304 | SSRF Protection | Blocks private/internal IPs, localhost, metadata endpoints (`169.254.169.254`) |
| AMCP305 | Rate Limiting | Configurable requests/second per client with token bucket |
| AMCP306 | Tool Schema Validation | Validates arguments against declared inputSchema |
| AMCP307 | Audit Logging | JSONL structured logs for SIEM integration |
| AMCP308 | Fail-Closed Defaults | Blocks unknown tools unless explicitly allowed |

**Additional Features:**
- Policy configuration via YAML
- Health endpoint (`/health`) and stats endpoint (`/stats`)
- Concurrent connection handling
- Transparent request/response forwarding

---

### 🔗 Enhanced Rug-Pull Protection (`lock`/`verify` commands)

Lockfiles now capture live server state for runtime integrity verification:

```bash
# Create lockfile from running server
aegismcp lock --live --command "python server.py" -o aegismcp.lock.json

# Verify running server against lockfile
aegismcp verify --live --command "python server.py" -l aegismcp.lock.json
```

**Improvements:**
- `--live` flag to create/verify lockfiles from running servers
- SHA-256 hashes of complete tool definitions (name, description, inputSchema)
- Detects tool additions, removals, and modifications at runtime
- AMCP202 (Schema Drift) now fires at CRITICAL for modified tools with injection patterns

---

### 📊 HTML Executive Reports

All scan commands now support beautiful, interactive HTML reports:

```bash
aegismcp scan configs/ --html report.html
aegismcp ast-scan server.py --html report.html
aegismcp inspect --command "python server.py" --html report.html
aegismcp verify --live --command "python server.py" -l lock.json --html report.html
```

**Features:**
- Dark/light theme auto-detection (respects `prefers-color-scheme`)
- Interactive: severity filters, searchable findings, collapsible details
- Print-optimized CSS
- Copy-to-clipboard SARIF/JSON
- **XSS-safe**: Full HTML escaping of tool descriptions and finding messages

---

### 🌐 Cross-Server Analysis

Analyze multiple MCP servers together for systemic risks:

```bash
aegismcp scan configs/ --cross-server --sarif report.sarif
```

**New Rules:**
- **AMCP201**: Tool shadowing — same tool name across multiple servers (HIGH)
- **AMCP202**: Schema drift — lockfile vs live server mismatch (CRITICAL/HIGH)
- **AMCP203**: Over-permissive schemas — unconstrained dangerous parameters (MEDIUM)

---

### 📋 SARIF 2.1.0 Export

All commands support SARIF export for CI/CD integration:

```bash
aegismcp scan configs/ --sarif report.sarif
aegismcp ast-scan server.py --sarif report.sarif
aegismcp inspect --command "python server.py" --sarif report.sarif
aegismcp verify --live --command "python server.py" -l lock.json --sarif report.sarif
```

---

### 🔧 Extensible RuleRegistry

- Built-in rules organized by category:
  - AMCP001–008: Configuration analysis
  - AMCP101–105: AST scanning (Python source)
  - AMCP201–203: Cross-server analysis
  - AMCP301–308: Runtime proxy
- Custom regex rules via `aegismcp.yaml`
- Dynamic rule enable/disable and severity override

---

### ⚡ Performance & Quality

- **Test file exclusion by default**: `tests/`, `test_*.py`, `*_test.py` skipped in AST scans
- **`--include-tests` flag** to explicitly include test files
- Windows-compatible subprocess handling with proper asyncio PIPE management
- JSON-RPC notification handling fixed (`notifications/initialized` sent correctly)

---

## Breaking Changes

| Change | Migration |
|--------|-----------|
| Minimum Python version: **3.10+** | Upgrade Python if on 3.9 or earlier |
| `inspect` command signature changed | Use `--command`, `--url`, or `--config-file` |
| `lock`/`verify` support `--live` mode | Add `--live` flag for runtime verification |
| Default `--fail-on` changed from MEDIUM to HIGH | Adjust CI pipelines or use `--fail-on MEDIUM` |
| CLI output uses ASCII markers (`[OK]`/`[FAIL]`) | No action needed — improved Windows compatibility |
| Rules reorganized into AMCP001–308 categories | Update any hardcoded rule ID references |

---

## Migration Guide: v2.x → v3.0.0

### New Commands

```bash
# Live introspection (NEW in v3.0.0)
aegismcp inspect --command "python server.py" --fail-on HIGH
aegismcp inspect --url http://localhost:8000/mcp --html report.html
aegismcp inspect --config-file mcp.json --sarif report.sarif

# Runtime proxy (NEW in v3.0.0)
aegismcp proxy --command "python server.py" --policy proxy-policy.yaml --audit-log audit.log

# Live lock/verify (NEW in v3.0.0)
aegismcp lock --live --command "python server.py" -o aegismcp.lock.json
aegismcp verify --live --command "python server.py" -l aegismcp.lock.json
```

### Updated Commands

```bash
# scan: added --cross-server, --fail-on (default HIGH)
aegismcp scan configs/ --cross-server --sarif report.sarif

# ast-scan: added --include-tests flag
aegismcp ast-scan server.py --fail-on HIGH --html report.html
```

### Configuration

```yaml
# aegismcp.yaml
auto_discover: true
fail_on: HIGH

custom_rules:
  - id: CUSTOM001
    severity: HIGH
    pattern: "my_secret_pattern"
    message: "Custom secret detected"

# proxy-policy.yaml
bind_host: "127.0.0.1"
bind_port: 8080
block_critical: true
block_high: true
audit_log: "audit.log"
max_requests_per_second: 100
timeout: 5.0
allowed_tools:
  - "safe_tool"
  - "read_only_tool"
```

---

## Full Changelog

### Added
- **Live MCP Server Introspection** (`inspect` command) with stdio and HTTP/SSE transports
- **Runtime MCP Security Proxy** (`proxy` command) with 8 security layers (AMCP301–308)
- **Enhanced Rug-Pull Protection** with `--live` mode for lock/verify
- **HTML Executive Reports** with dark/light themes, interactive filters, XSS-safe rendering
- **Cross-Server Analysis** (AMCP201, AMCP202, AMCP203)
- **SARIF 2.1.0 Export** for all scan commands
- **Extensible RuleRegistry** with built-in + custom rules
- **httpx** as optional dependency for HTTP transport

### Changed
- **BREAKING**: Minimum Python version is now 3.10+
- **BREAKING**: `inspect` command signature changed
- **BREAKING**: `lock`/`verify` support `--live` mode
- Default `--fail-on` level changed from MEDIUM to HIGH
- CLI output uses `[OK]`/`[FAIL]` markers (Windows compatible)
- Auto-discovery supports Claude Desktop, Cursor, Windsurf, VS Code on all platforms
- Rules reorganized into categories: AMCP001–008, AMCP101–105, AMCP201–203, AMCP301–308
- Performance: AST scanner excludes test files by default

### Fixed
- JSON-RPC notification handling: `notifications/initialized` sent correctly
- Subprocess handling on Windows: proper asyncio PIPE management with timeouts
- Lockfile `ServerLock` class reference
- AST finding `location` property
- XSS protection in HTML reports
- Rate limiting in proxy (now enforces limits correctly)

### Removed
- Old v2.x release notes files (`RELEASE_NOTES_v2*.md`, `release_notes_v2.0.1.md`)
- Unicode emoji from CLI output (replaced with ASCII markers)

---

## Verification

All tests pass:
```bash
$ python -u -m pytest tests -q -W ignore
============================= 127 passed in 2.34s ==============================
```

CLI commands verified:
```bash
$ aegismcp --version
3.0.0

$ aegismcp scan --auto
$ aegismcp scan samples/vulnerable_mcp.json --cross-server --html report.html
$ aegismcp ast-scan samples/test_server.py --fail-on HIGH --html report.html
$ aegismcp inspect --command "python samples/test_server.py" --fail-on HIGH --html report.html
$ aegismcp lock --live --command "python samples/test_server.py" -o aegismcp.lock.json
$ aegismcp verify --live --command "python samples/test_server.py" -l aegismcp.lock.json
$ aegismcp proxy --command "python samples/test_server.py" --policy samples/proxy-policy.yaml --audit-log audit.log
```

---

## Contributors

- cyberlynxxx (Youness Moufleh)

---

## Links

- **Repository:** https://github.com/cyberlynxxx/aegismcp
- **Issues:** https://github.com/cyberlynxxx/aegismcp/issues
- **PyPI:** https://pypi.org/project/aegismcp