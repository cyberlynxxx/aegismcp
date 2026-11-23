"""Command-line interface for AegisMCP."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .config import Config
from .scanner import scan_file, scan_directory
from .sarif import export_sarif
from .discovery import discover_mcp_files
from .lockfile import (
    Lockfile,
    create_lock_from_config,
    verify_lockfile,
)
from .ast_scanner import scan_python_file, scan_python_directory, ASTFinding
from .rules_core import Finding


COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[96m",    # Cyan
    "LOW": "\033[90m",       # Gray
    "RESET": "\033[0m",
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def print_findings(findings: list, show_color: bool = True) -> None:
    """Print findings in a formatted way."""
    for finding in findings:
        severity = getattr(finding, "severity", "MEDIUM")
        rule_id = getattr(finding, "rule_id", "UNKNOWN")
        title = getattr(finding, "title", "Unknown Issue")
        location = getattr(finding, "location", "Unknown Location")
        message = getattr(finding, "message", "")
        remediation = getattr(finding, "remediation", "")

        color = COLORS.get(severity, "") if show_color else ""
        reset = COLORS["RESET"] if show_color else ""

        print(f"{color}[{severity}] {rule_id} - {title}{reset}")
        print(f"  Location: {location}")
        print(f"  Detail:   {message}")
        print(f"  Fix:      {remediation}\n")


def print_ast_findings(findings: list[ASTFinding], show_color: bool = True) -> None:
    """Print AST findings."""
    for finding in findings:
        color = COLORS.get(finding.severity, "") if show_color else ""
        reset = COLORS["RESET"] if show_color else ""

        print(f"{color}[{finding.severity}] {finding.rule_id} - {finding.title}{reset}")
        print(f"  File:     {finding.file_path}:{finding.line}:{finding.column}")
        print(f"  Detail:   {finding.message}")
        print(f"  Fix:      {finding.remediation}\n")


def _print_summary(findings: list, file_count: int = 1) -> None:
    """Print a summary line with finding counts by severity."""
    if not findings:
        print("[OK] No security issues found.")
        return

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = getattr(f, "severity", "MEDIUM")
        if sev in counts:
            counts[sev] += 1

    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            parts.append(f"{counts[sev]} {sev}")
    detail = ", ".join(parts) if parts else "0 findings"
    print(f"Summary: {len(findings)} findings ({detail}) in {file_count} file(s)")


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle the scan command."""
    config = Config.load(Path(args.config) if args.config else None)

    # Override config with CLI args
    if args.fail_on:
        config.fail_on = args.fail_on
    if args.no_auto_discover:
        config.auto_discover = False

    all_findings = []
    files_scanned = 0

    # Determine if we should auto-discover
    should_auto = args.auto or (not args.target and config.auto_discover)

    if should_auto:
        # Auto-discover MCP config files
        files = discover_mcp_files(auto_discover=config.auto_discover)
        if not files:
            print("No MCP configuration files found.")
            return 0
        print(f"Discovered {len(files)} MCP config file(s):")
        for f in files:
            print(f"  - {f}")
        print()

        for f in files:
            if config.should_ignore(f):
                continue
            all_findings.extend(scan_file(f, config))
            files_scanned += 1
    else:
        # Require target if not auto-discovering
        if not args.target:
            print("Error: target path required (or use --auto / set auto_discover: true in config)")
            return 2
        target = Path(args.target)
        # Original behavior: scan file or directory
        if target.is_file():
            all_findings.extend(scan_file(target, config))
            files_scanned = 1
        else:
            # For directory, count files scanned
            from .discovery import iter_json_files, _looks_like_mcp_config
            for json_file in iter_json_files(target):
                if config.should_ignore(json_file):
                    continue
                if _looks_like_mcp_config(json_file):
                    all_findings.extend(scan_file(json_file, config))
                    files_scanned += 1

    _print_summary(all_findings, files_scanned)

    if not all_findings:
        return 0

    print_findings(all_findings, show_color=not args.no_color)

    if args.sarif:
        export_sarif(all_findings, Path(args.sarif))
        print(f"SARIF report saved to {args.sarif}")

    threshold = SEVERITY_RANK[config.fail_on]
    if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in all_findings):
        return 1
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    """Handle the lock command - create lockfile from config."""
    config_path = Path(args.config_file)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        return 1

    lockfile = create_lock_from_config(config_path)

    output_path = Path(args.output) if args.output else Path.cwd() / "aegismcp.lock.json"
    lockfile.save(output_path)

    print(f"[OK] Lockfile created: {output_path}")
    print(f"  Servers locked: {len(lockfile.servers)}")
    for name, server in lockfile.servers.items():
        print(f"  - {name} (config hash: {server.config_hash[:16]}...)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle the verify command - check config against lockfile."""
    config_path = Path(args.config_file)
    lockfile_path = Path(args.lockfile) if args.lockfile else Path.cwd() / "aegismcp.lock.json"

    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        return 1

    if not lockfile_path.exists():
        print(f"Error: Lockfile not found: {lockfile_path}")
        return 1

    lockfile = Lockfile.load(lockfile_path)
    violations = verify_lockfile(lockfile, config_path)

    if not violations:
        print("[OK] Configuration matches lockfile. No violations found.")
        return 0

    print(f"[FAIL] Found {len(violations)} violation(s):\n")
    for v in violations:
        severity = v.get("severity", "MEDIUM")
        color = COLORS.get(severity, "")
        reset = COLORS["RESET"]
        print(f"{color}[{severity}] {v['type'].upper()} - {v['message']}{reset}")
        for k, val in v.items():
            if k not in ("type", "severity", "message"):
                print(f"  {k}: {val}")
        print()

    # Exit with error if any CRITICAL or HIGH violations
    if any(v.get("severity") in ("CRITICAL", "HIGH") for v in violations):
        return 1
    return 0


def cmd_ast_scan(args: argparse.Namespace) -> int:
    """Handle the AST scan command for Python source code."""
    target = Path(args.target)

    if target.is_file():
        findings = scan_python_file(target)
        file_count = 1
    else:
        findings = scan_python_directory(target, include_tests=args.include_tests)
        # Count Python files scanned
        from .ast_scanner import _is_test_file, _is_in_test_dir
        ignore_dirs = {".git", "__pycache__", ".venv", "venv", "env", "dist", "build", ".pytest_cache", ".mypy_cache", "node_modules"}
        file_count = 0
        for py_file in target.rglob("*.py"):
            if any(part in ignore_dirs for part in py_file.parts):
                continue
            if not args.include_tests:
                if _is_test_file(py_file) or _is_in_test_dir(py_file):
                    continue
            file_count += 1

    _print_summary(findings, file_count)

    if not findings:
        return 0

    print_ast_findings(findings, show_color=not args.no_color)

    if args.sarif:
        # Convert ASTFinding to regular Finding for SARIF export
        from .rules_core import Finding
        sarif_findings = [
            Finding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                message=f.message,
                location=f"{f.file_path}:{f.line}:{f.column}",
                remediation=f.remediation,
            )
            for f in findings
        ]
        export_sarif(sarif_findings, Path(args.sarif))
        print(f"SARIF report saved to {args.sarif}")

    threshold = SEVERITY_RANK[args.fail_on]
    if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in findings):
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aegismcp",
        description="Security scanner for MCP configs & AI agent tools.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Global options
    parser.add_argument("--config", type=str, help="Path to aegismcp.yaml config file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Scan MCP config file(s) or directory")
    scan_parser.add_argument("target", nargs="?", type=str, default=None, help="Path to MCP config file or folder (optional if --auto or auto_discover in config)")
    scan_parser.add_argument("--auto", action="store_true", help="Auto-discover MCP configs (Claude Desktop, Cursor, Windsurf, VS Code)")
    scan_parser.add_argument("--sarif", type=str, help="Export report to SARIF file")
    scan_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Exit with error if findings at or above this severity")
    scan_parser.add_argument("--no-auto-discover", action="store_true", help="Disable auto-discovery of platform configs")

    # --- lock command ---
    lock_parser = subparsers.add_parser("lock", help="Create lockfile from MCP config (rug-pull protection)")
    lock_parser.add_argument("config_file", type=str, help="Path to MCP config file")
    lock_parser.add_argument("-o", "--output", type=str, help="Output lockfile path (default: ./aegismcp.lock.json)")

    # --- verify command ---
    verify_parser = subparsers.add_parser("verify", help="Verify MCP config against lockfile")
    verify_parser.add_argument("config_file", type=str, help="Path to MCP config file")
    verify_parser.add_argument("-l", "--lockfile", type=str, help="Path to lockfile (default: ./aegismcp.lock.json)")

    # --- ast-scan command ---
    ast_parser = subparsers.add_parser("ast-scan", help="Scan Python MCP server source code for vulnerabilities")
    ast_parser.add_argument("target", type=str, help="Path to Python file or directory")
    ast_parser.add_argument("--sarif", type=str, help="Export report to SARIF file")
    ast_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Exit with error if findings at or above this severity")
    ast_parser.add_argument("--include-tests", action="store_true", help="Include test files/directories (tests/, test_*.py, *_test.py)")

    args = parser.parse_args()

    # Route to command handler
    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "lock":
        sys.exit(cmd_lock(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "ast-scan":
        sys.exit(cmd_ast_scan(args))


if __name__ == "__main__":
    main()