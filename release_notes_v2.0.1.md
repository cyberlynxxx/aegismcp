# AegisMCP v2.0.1 Release Notes

**Release Date:** 2025-11-23  
**Version:** 2.0.1  
**Author:** cyberlynxxx

---

## Overview

Version 2.0.1 is a maintenance and polish release that addresses several key issues from v2.0.0:
- Fixes the `scan --auto` command to work without a required target argument
- Significantly reduces AST scanner false positives with test file exclusion
- Refines AMCP104 (Path Traversal) to only flag truly user-controlled paths
- Adds comprehensive automated test coverage and GitHub Actions CI pipeline
- Updates documentation, samples, and PyPI metadata

---

## What's New

### 🔧 CLI Fixes

**`scan` command now accepts optional target when using `--auto`**
- The `target` argument is now optional (`nargs="?"`)
- When `--auto` is used without a target, it auto-discovers platform MCP configs (Claude Desktop, Cursor, Windsurf, VS Code)
- Without `--auto` and without `auto_discover: true` in config, the command fails cleanly with exit code 2 and a helpful error message

**New summary output for all scan commands**
- All scan commands (`scan`, `ast-scan`) now print a one-line summary: `Summary: N findings (X CRITICAL, Y HIGH, Z MEDIUM) in M file(s)`
- Clean output when no issues found: `[OK] No security issues found.`

### 🐍 AST Scanner Improvements

**Test file exclusion by default (reduces false positives)**
- Files matching `test_*.py`, `*_test.py` are now excluded by default
- Directories named `tests/` or `test/` are excluded by default
- New `--include-tests` flag to explicitly include test files when needed

**Refined AMCP104 (Path Traversal) — only flags dynamic/user-controlled paths**
- Safe literals like `"config.json"`, `Path("safe.txt")`, `pathlib.Path("data/file.json")` are NO longer flagged
- Only flags paths built from:
  - f-strings: `f"{user_input}/file.txt"`
  - String concatenation: `"base/" + user_input`
  - Variables/parameters: `open(user_path)`
  - Function calls: `open(get_user_path())`
- This dramatically reduces false positives while catching genuine path traversal vulnerabilities

### ✅ Automated Tests & CI

**Complete pytest test suite (31 tests)**
- `tests/test_scan.py` — 10 tests covering scan command, custom rules, auto-discovery, CLI behavior
- `tests/test_lock_verify.py` — 5 tests for lock/verify functionality
- `tests/test_ast_scanner.py` — 16 tests for AST scanner rules (AMCP101–105), test exclusion, SARIF export

**GitHub Actions CI pipeline**
- Matrix strategy: Ubuntu + Windows × Python 3.10, 3.11, 3.12
- Installs dev dependencies and runs full test suite
- Tests all CLI commands (`scan`, `lock`, `verify`, `ast-scan`)
- SARIF upload integration ready for GitHub Advanced Security

### 📚 Documentation & Polish

- **LICENSE**: Added MIT License (copyright cyberlynxxx)
- **Updated samples**: `samples/vulnerable_mcp.json` now triggers AMCP006 (long description)
- **Version bump**: All version references updated to 2.0.1
- **PyPI metadata**: Fixed TOML syntax, added keywords, classifiers, project URLs, optional dev dependencies
- **README.md**: Complete rewrite with v2.0.1 features, corrected AMCP101/102 severity docs, `--include-tests` docs, updated project structure

---

## Breaking Changes

None. This is a patch release with only backward-compatible changes.

---

## Migration Guide

### From v2.0.0

No migration needed. All existing workflows continue to work.

**New optional features you can adopt:**
1. Use `aegismcp scan --auto` without a target argument
2. Use `aegismcp ast-scan . --include-tests` to scan test files
3. Add `aegismcp.yaml` with `auto_discover: true` for automatic config discovery

---

## Full Changelog

### Fixed
- `scan --auto` now works without explicit target argument (#1)
- AMCP104 false positives on safe literal paths (e.g., `"config.json"`, `Path("safe.txt")`)
- AST scanner now excludes test files by default (`tests/`, `test_*.py`, `*_test.py`)
- PyProject.toml TOML syntax error (inline table → standard table format)
- Custom rule target `servers.command` now implemented

### Added
- `--include-tests` flag for `ast-scan` command
- Summary output line for all scan commands
- Comprehensive test suite (31 tests)
- GitHub Actions CI pipeline (Linux + Windows, Python 3.10–3.12)
- MIT LICENSE file
- Release notes for v2.0.1

### Changed
- AMCP104 logic rewritten: only flags f-strings, concatenation, variables, function calls
- `scan` target argument is now optional (`nargs="?"`)
- README completely rewritten for v2.0.1
- Project structure updated in docs

---

## Verification

All tests pass:
```bash
$ pytest -v
============================= 31 passed in 0.64s ==============================
```

CLI commands verified:
```bash
$ aegismcp scan --auto
$ aegismcp scan samples/vulnerable_mcp.json
$ aegismcp ast-scan samples/test_server.py
$ aegismcp ast-scan samples/test_server.py --include-tests
$ aegismcp lock samples/vulnerable_mcp.json -o aegismcp.lock.json
$ aegismcp verify samples/vulnerable_mcp.json -l aegismcp.lock.json
```

---

## Contributors

- cyberlynxxx

---

## Links

- **Repository:** https://github.com/cyberlynxxx/aegismcp
- **Issues:** https://github.com/cyberlynxxx/aegismcp/issues
- **PyPI:** https://pypi.org/project/aegismcp