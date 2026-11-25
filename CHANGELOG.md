# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.1] - 2026-11-25

### Added
- **Version Command Support**: Added `--version`/`-V` flag to CLI for package version reporting
- **GitHub Action Example**: Added comprehensive GitHub Action example to README.md
- **PyPI Package Name Consistency**: Updated all documentation to reference PyPI package name `aegismcp-security` consistently

### Changed
- Version bump to 3.1.1 across all package files (pyproject.toml, src/aegismcp/__init__.py)
- Updated action.yml to use `aegismcp-security==3.1.1` for installation
- Updated README.md to include PyPI badge and proper installation instructions

### Fixed
- html_report.py: Finding.column attribute access guarded with hasattr() (line 888)
- inspector.py: JSONRPCClient process type annotation, None checks for stdin/stdout/client
- scanner.py: Type annotation for findings list
- proxy.py: RateLimiter.tokens type annotation, loop variable naming collision with InjectionPattern class, optional import type ignores

## [3.0.1] - 2026-11-24

### Added
- **Phase 1 Hardening: Bidirectional Anti-Evasion Runtime Proxy (AMCP309)**
  - Server-to-client response inspection for indirect prompt injection, secret leakage, invisible Unicode
  - Multi-stage anti-evasion normalizer (Unicode NFKC, iterative URL/Base64/Hex decoding, enhanced SSRF for alternative IP formats)
  - Weighted prompt injection scoring engine with strict/balanced modes configurable via proxy-policy.yaml
  - Protocol-safe async blocking with JSON-RPC 2.0 error objects (code: -32001)
- AMCP309 server-to-client response inspection module
- PromptInjectionScorer with ScoringMode enum (STRICT/BALANCED) and InjectionPattern dataclass
- Normalizer class with multi-stage decoding pipeline (NFKC, URL, Base64, Hex)
- is_suspicious_ip() enhanced SSRF detection for IPv4/IPv6/decimal/hex/octal formats
- create_scorer_from_config() for policy file integration
- RESPONSE_INJECTION_PATTERNS, RESPONSE_SECRET_PATTERNS, RESPONSE_INVISIBLE_UNICODE_PATTERNS in rules_core.py
- `prompt_injection_mode` setting in proxy-policy.yaml (strict/balanced)

### Fixed
- Three regex fixes in rules_core.py enabling all 32 tests to pass
- Version bump to 3.0.1 across all package files

## [3.0.0] - 2026-11-23

### Added
- **Live MCP Server Introspection (`inspect` command)**: Connect to running MCP servers via stdio or HTTP/SSE for real-time security checks
  - JSON-RPC 2.0 client with proper asyncio subprocess handling
  - Supports `tools/list`, `resources/list`, `prompts/list` introspection
  - Live checks: AMCP005 (tool poisoning), AMCP006 (long descriptions), AMCP007 (invisible Unicode), AMCP201 (shadowing), AMCP203 (permissive schemas)
  - `--lock-output` to create lockfiles from live server tools
  - `--fail-on` to gate CI pipelines
- **Runtime MCP Security Proxy (`proxy` command)**: Transparent firewall between clients and servers
  - Prompt injection detection (AMCP301) — blocks hidden LLM directives
  - Command injection prevention (AMCP302) — shell metacharacters, command substitution
  - Path traversal blocking (AMCP303) — `../`, absolute paths, directory traversal
  - SSRF protection (AMCP304) — private/internal IPs, localhost, metadata endpoints
  - Rate limiting (AMCP305) — configurable requests/second per client
  - Audit logging (AMCP307) — JSONL structured logs for SIEM integration
  - Fail-closed defaults (AMCP308) — blocks unknown tools unless explicitly allowed
  - Policy configuration via YAML
- **Enhanced Rug-Pull Protection (`lock`/`verify` commands)**
  - `--live` flag to create/verify lockfiles from running servers
  - Lockfiles now store SHA-256 hashes of live tool definitions
  - Runtime verification catches tool additions/removals/modifications
- **HTML Executive Reports** (all scan commands)
  - Dark/light theme auto-detection
  - Interactive: severity filters, searchable findings, collapsible details
  - Print-optimized CSS, copy-to-clipboard SARIF/JSON
  - XSS-safe with full HTML escaping
- **Cross-Server Analysis**
  - AMCP201: Tool shadowing (duplicate names across servers)
  - AMCP202: Schema drift detection (lockfile vs live)
  - AMCP203: Over-permissive input schemas
- **SARIF 2.1.0 Export** for all scan commands (scan, ast-scan, inspect, verify)
- **Extensible RuleRegistry**: Built-in rules + custom regex rules from config
- **httpx** as optional dependency for HTTP/SSE transport

### Changed
- **BREAKING**: Minimum Python version is now 3.10+
- **BREAKING**: `aegismcp inspect` command signature changed (new `--command`, `--url`, `--config-file` options)
- **BREAKING**: `aegismcp lock`/`verify` now support `--live` mode
- Default `--fail-on` level changed from MEDIUM to HIGH for stricter CI gating
- CLI output uses `[OK]`/`[FAIL]` markers for Windows compatibility (no Unicode symbols)
- Auto-discovery now supports Claude Desktop, Cursor, Windsurf, VS Code on Windows/macOS/Linux
- Rules reorganized into categories: AMCP001-008 (config), AMCP101-105 (AST), AMCP201-203 (cross-server), AMCP301-308 (runtime proxy)
- Performance: AST scanner excludes test files by default (`tests/`, `test_*.py`, `*_test.py`)

### Fixed
- JSON-RPC notification handling: `notifications/initialized` now sent as notification (no response expected)
- Subprocess handling on Windows: proper asyncio PIPE management with timeouts
- Mock server f-string escaping in tests
- Lockfile `ServerLock` class reference (was incorrectly nested)
- AST finding `location` property missing
- XSS protection in HTML reports (proper escaping of tool descriptions and finding messages)
- Rate limiting in proxy (was not enforcing limits correctly)

### Removed
- Old v2.x release notes files (`RELEASE_NOTES_v2*.md`)
- Unicode emoji from CLI output (replaced with ASCII markers)

## [2.0.1] - 2026-11-20

### Fixed
- CLI installation in CI workflow (entry point now properly registered)
- SVG banner rendering on GitHub (fixed XML namespace issues)
- pytest test collection scope (limited to `tests/` directory)

## [2.0.0] - 2026-11-18

### Added
- Initial release of AegisMCP as static MCP config scanner
- Rules AMCP001-AMCP008 for config file analysis
- SARIF export for CI/CD integration
- Lockfile-based integrity verification
- Cross-platform config auto-discovery
- Python AST scanning (AMCP101-AMCP105)
- Custom rule support via YAML config

---

## Migration Guide: v2.x → v3.0.0

### New Commands
```bash
# Live introspection (NEW)
aegismcp inspect --command "python server.py" --fail-on HIGH
aegismcp inspect --url http://localhost:8000/mcp --html report.html

# Runtime proxy (NEW)
aegismcp proxy --command "python server.py" --policy proxy-policy.yaml --audit-log audit.log

# Live lock/verify (NEW)
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
- `aegismcp.yaml` now supports `auto_discover: true` and custom rules
- `proxy-policy.yaml` for runtime proxy configuration