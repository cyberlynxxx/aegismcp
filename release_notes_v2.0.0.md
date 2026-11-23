# AegisMCP v2.0.0 — Phase 1 Release

**Release Date:** 2026-11-22

---

## 🎉 What's New in v2.0.0

This release completes **Phase 1** of the AegisMCP roadmap, adding four major capabilities:

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
Place `aegismcp.yaml` in your project root to customize rule behavior:

```yaml
rules:
  AMCP002:
    enabled: false          # disable unpinned npx check
  AMCP003:
    severity: CRITICAL      # escalate path exposure

custom_rules:
  - id: "CUSTOM001"
    title: "Internal Domain Exposure"
    pattern: "internal\.company\.com"
    severity: "HIGH"
    target: "servers.env"

ignore_paths:
  - "node_modules/**"
  - "*.lock.json"

fail_on: "HIGH"
auto_discover: true
```

### 🔒 Rug-Pull Protection (`lock` / `verify`)
SHA-256 lockfiles ensure config integrity across deployments:

```bash
# Create lockfile from trusted config
aegismcp lock mcp.json -o aegismcp.lock.json

# Verify in CI/CD pipeline
aegismcp verify mcp.json -l aegismcp.lock.json
```

### 🐍 Python AST Scanning (`ast-scan`)
Static analysis of Python MCP server source code:

| Rule | Severity | Detects |
|------|----------|---------|
| AMCP101 | CRITICAL | Command injection (`subprocess`, `os.system`, `eval`, `exec`) |
| AMCP102 | CRITICAL | Dynamic code execution |
| AMCP103 | HIGH | SSRF (dynamic URLs in HTTP calls) |
| AMCP104 | HIGH | Path traversal (user-controlled paths) |
| AMCP105 | CRITICAL | Insecure deserialization (`pickle`, `yaml` unsafe) |

```bash
aegismcp ast-scan server.py --sarif ast-report.sarif --fail-on HIGH
```

### 📦 SARIF Export & CI/CD Gates
All commands support `--sarif` (SARIF 2.1.0) and `--fail-on LEVEL`:

```bash
aegismcp scan mcp.json --sarif report.sarif --fail-on HIGH
aegismcp ast-scan server.py --sarif ast.sarif --fail-on CRITICAL
```

---

## 📋 Full Changelog

### Added
- **Auto-discovery** across 4 platforms on 3 OSes
- **Policy config** (`aegismcp.yaml`) with rule overrides, custom regex rules, ignore paths
- **Lock/verify** commands with SHA-256 integrity verification
- **AST scanner** for Python source (5 new rules: AMCP101–AMCP105)
- **RuleRegistry** for extensible built-in + custom rules
- **SARIF 2.1.0** export for all scan types
- **Windows-compatible** CLI output (`[OK]`/`[FAIL]`)

### Changed
- Refactored all 8 original rules (AMCP001–AMCP008) into registry pattern
- Renamed `rules.py` → `rules_core.py` to avoid package conflict
- Updated package version to `2.0.0`

### Fixed
- Unicode encoding issues on Windows terminals
- Custom rule loading from config files
- Lockfile deduplication and path handling

---

## 📦 Installation

```bash
pip install aegismcp
# or from source
git clone https://github.com/cyberlynxxx/aegismcp
cd aegismcp
pip install -e .
```

---

## 📚 Documentation

- [README.md](README.md) — Full CLI reference and examples
- [aegismcp.yaml](aegismcp.yaml) — Example policy configuration
- [samples/vulnerable_mcp.json](samples/vulnerable_mcp.json) — Test config triggering all rules
- [samples/test_server.py](samples/test_server.py) — Python server with AST vulnerabilities

---

## 🔮 Roadmap

- **Phase 2:** Dynamic inspection (`inspect`), auto-fix (`fix`), supply-chain reputation
- **Phase 3:** Runtime proxy (`proxy`) with real-time DLP, human-in-the-loop, audit logging
- **Phase 4:** PyPI publishing, GitHub Action, VS Code extension, test suite

---

## 👥 Contributors

- @youness-mouflah (author)
- Generated with [Claude Code](https://claude.com/claude-code)

---

**Full commit history:** [fdec587...10c56d0](https://github.com/cyberlynxxx/aegismcp/compare/fdec587...10c56d0)
