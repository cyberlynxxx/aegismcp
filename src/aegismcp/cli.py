"""Command-line interface for AegisMCP."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

try:
    from importlib.metadata import version as get_version
except ImportError:
    # Fallback for Python < 3.8
    from importlib_metadata import version as get_version  # type: ignore

from .ast_scanner import scan_python_directory, scan_python_file
from .config import Config
from .discovery import discover_mcp_files
from .html_report import HTMLReportOptions, save_html_report
from .inspector import (
    InspectorOptions,
    create_lock_from_live,
    inspect_live,
    verify_live,
)
from .lockfile import (
    Lockfile,
    create_lock_from_config,
    verify_lockfile,
)
from .proxy import ProxyConfig, run_proxy
from .reporter import ReportOptions, print_report
from .sarif import export_sarif
from .scanner import scan_file


def get_package_version() -> str:
    """Get the installed package version."""
    try:
        return get_version("aegismcp-security")
    except Exception:  # noqa: BLE001
        return "dev"

COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[96m",    # Cyan
    "LOW": "\033[90m",       # Gray
    "RESET": "\033[0m",
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _print_summary(findings: list, file_count: int = 1) -> None:
    """Print a summary line with finding counts by severity (legacy, kept for compat)."""
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
            from .discovery import _looks_like_mcp_config, iter_json_files
            for json_file in iter_json_files(target):
                if config.should_ignore(json_file):
                    continue
                if _looks_like_mcp_config(json_file):
                    all_findings.extend(scan_file(json_file, config))
                    files_scanned += 1

    # Use new reporter
    report_opts = ReportOptions(
        verbose=args.verbose if hasattr(args, 'verbose') else False,
        compact=args.compact if hasattr(args, 'compact') else False,
        show_color=not args.no_color,
        no_color=args.no_color,
        fail_on=config.fail_on,
    )
    return print_report(all_findings, files_scanned, report_opts)


def cmd_lock(args: argparse.Namespace) -> int:
    """Handle the lock command - create lockfile from config or live server."""
    if getattr(args, 'live', False):
        # Live mode: connect to server and create lockfile from live tools
        options = InspectorOptions(
            timeout=args.timeout,
            command=args.command,
            url=args.url,
            config_file=Path(args.config_file) if args.config_file else None,
        )

        _findings, server_info = asyncio.run(inspect_live(options))

        if not server_info:
            print("Error: Could not connect to server")
            return 1

        lockfile = create_lock_from_live(options, server_info)

        output_path = Path(args.output) if args.output else Path.cwd() / "aegismcp.lock.json"
        lockfile.save(output_path)

        print(f"[OK] Live lockfile created: {output_path}")
        print(f"  Server: {server_info.name}")
        print(f"  Tools locked: {len(server_info.tools)}")
        for tool in server_info.tools:
            print(f"  - {tool.name}")
        return 0

    # Static mode (original behavior)
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
    if getattr(args, 'live', False):
        # Live mode: connect to server and verify against lockfile
        options = InspectorOptions(
            timeout=args.timeout,
            command=args.command,
            url=args.url,
            config_file=Path(args.config_file) if args.config_file else None,
        )

        _findings, server_info = asyncio.run(inspect_live(options))

        if not server_info:
            print("Error: Could not connect to server")
            return 1

        lockfile_path = Path(args.lockfile) if args.lockfile else Path.cwd() / "aegismcp.lock.json"
        if not lockfile_path.exists():
            print(f"Error: Lockfile not found: {lockfile_path}")
            return 1

        lockfile = Lockfile.load(lockfile_path)
        violations = verify_live(options, server_info, lockfile)

        if not violations:
            print("[OK] Live server tools match lockfile. No violations found.")
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

        if any(v.get("severity") in ("CRITICAL", "HIGH") for v in violations):
            return 1
        return 0

    # Static mode (original behavior)
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
        from .ast_scanner import _is_in_test_dir, _is_test_file
        ignore_dirs = {".git", "__pycache__", ".venv", "venv", "env", "dist", "build", ".pytest_cache", ".mypy_cache", "node_modules"}
        file_count = 0
        for py_file in target.rglob("*.py"):
            if any(part in ignore_dirs for part in py_file.parts):
                continue
            if not args.include_tests and (_is_test_file(py_file) or _is_in_test_dir(py_file)):
                continue
            file_count += 1

    # Use new reporter for AST findings
    report_opts = ReportOptions(
        verbose=args.verbose if hasattr(args, 'verbose') else False,
        compact=args.compact if hasattr(args, 'compact') else False,
        show_color=not args.no_color,
        no_color=args.no_color,
        fail_on=args.fail_on,
    )
    exit_code = print_report(findings, file_count, report_opts)

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

    return exit_code


def cmd_inspect(args: argparse.Namespace) -> int:
    """Handle the inspect command - live MCP server introspection."""
    options = InspectorOptions(
        timeout=args.timeout,
        command=args.command,
        url=args.url,
        config_file=Path(args.config_file) if args.config_file else None,
        fail_on=args.fail_on,
        sarif=Path(args.sarif) if args.sarif else None,
        html=Path(args.html) if args.html else None,
        compact=args.compact,
        verbose=args.verbose,
        show_color=not args.no_color,
        no_color=args.no_color,
    )

    try:
        findings, server_info = asyncio.run(inspect_live(options))
    except Exception as e:  # noqa: BLE001
        print(f"Error: {e}")
        return 1

    if not server_info:
        print("Error: Could not connect to server or no tools found")
        return 1

    print(f"Connected to: {server_info.name} (protocol: {server_info.protocol_version})")
    print(f"Tools discovered: {len(server_info.tools)}")
    if args.verbose:
        for tool in server_info.tools:
            print(f"  - {tool.name}: {tool.description[:80]}...")
        print()

    report_opts = ReportOptions(
        verbose=args.verbose,
        compact=args.compact,
        show_color=not args.no_color,
        no_color=args.no_color,
        fail_on=args.fail_on,
    )
    exit_code = print_report(findings, 1, report_opts)

    # Export SARIF if requested
    if args.sarif:
        export_sarif(findings, Path(args.sarif))
        print(f"SARIF report saved to {args.sarif}")

    # Export HTML if requested
    if args.html:
        html_opts = HTMLReportOptions(
            title=f"AegisMCP Inspect Report - {server_info.name}",
            theme="dark"
        )
        metadata = {
            "Server": server_info.name,
            "Protocol": server_info.protocol_version,
            "Tools": len(server_info.tools),
            "Resources": len(server_info.resources),
            "Prompts": len(server_info.prompts),
        }
        save_html_report(findings, Path(args.html), 1, html_opts, metadata)
        print(f"HTML report saved to {args.html}")

    return exit_code


def cmd_proxy(args: argparse.Namespace) -> int:
    """Handle the proxy command - runtime MCP security proxy/firewall."""
    if not args.command and not args.url:
        print("Error: Either --command or --url is required")
        return 2

    host, port_str = args.bind.split(":", 1)
    port = int(port_str)

    if args.command:
        command = args.command.split()
        url = None
    else:
        command = None
        url = args.url

    config = ProxyConfig(
        command=command,
        url=url,
        bind_host=host,
        bind_port=port,
        timeout=args.timeout,
        fail_on=args.fail_on,
        audit_log=Path(args.audit_log) if args.audit_log else None,
        audit_format=args.audit_format,
        max_requests_per_second=args.rate_limit,
        max_request_size=args.max_size,
        block_critical=not args.no_block_critical,
        block_high=not args.no_block_high,
        block_medium=args.block_medium,
        block_low=args.block_low,
    )

    try:
        asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        pass
    except Exception as e:  # noqa: BLE001
        print(f"Error: {e}")
        return 1

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aegismcp",
        description="Security scanner for MCP configs & AI agent tools.",
    )
    # Global options
    parser.add_argument("--version", "-V", action="store_true", help="Show version and exit")
    parser.add_argument("--config", type=str, help="Path to aegismcp.yaml config file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    subparsers = parser.add_subparsers(dest="command", required=False)

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Scan MCP config file(s) or directory")
    scan_parser.add_argument("target", nargs="?", type=str, default=None, help="Path to MCP config file or folder (optional if --auto or auto_discover in config)")
    scan_parser.add_argument("--auto", action="store_true", help="Auto-discover MCP configs (Claude Desktop, Cursor, Windsurf, VS Code)")
    scan_parser.add_argument("--sarif", type=str, help="Export report to SARIF file")
    scan_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Exit with error if findings at or above this severity")
    scan_parser.add_argument("--no-auto-discover", action="store_true", help="Disable auto-discovery of platform configs")

    # --- lock command ---
    lock_parser = subparsers.add_parser("lock", help="Create lockfile from MCP config or live server (rug-pull protection)")
    lock_parser.add_argument("config_file", type=str, nargs="?", default=None, help="Path to MCP config file (optional with --live)")
    lock_parser.add_argument("-o", "--output", type=str, help="Output lockfile path (default: ./aegismcp.lock.json)")
    lock_parser.add_argument("--live", action="store_true", help="Create lockfile from live MCP server instead of static config")
    lock_parser.add_argument("--command", type=str, help="Command to start MCP server (e.g., 'python server.py')")
    lock_parser.add_argument("--url", type=str, help="HTTP/SSE URL of MCP server")
    lock_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")

    # --- verify command ---
    verify_parser = subparsers.add_parser("verify", help="Verify MCP config against lockfile")
    verify_parser.add_argument("config_file", type=str, nargs="?", default=None, help="Path to MCP config file (optional with --live)")
    verify_parser.add_argument("-l", "--lockfile", type=str, help="Path to lockfile (default: ./aegismcp.lock.json)")
    verify_parser.add_argument("--live", action="store_true", help="Verify live MCP server against lockfile instead of static config")
    verify_parser.add_argument("--command", type=str, help="Command to start MCP server (e.g., 'python server.py')")
    verify_parser.add_argument("--url", type=str, help="HTTP/SSE URL of MCP server")
    verify_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")

    # --- ast-scan command ---
    ast_parser = subparsers.add_parser("ast-scan", help="Scan Python MCP server source code for vulnerabilities")
    ast_parser.add_argument("target", type=str, help="Path to Python file or directory")
    ast_parser.add_argument("--sarif", type=str, help="Export report to SARIF file")
    ast_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Exit with error if findings at or above this severity")
    ast_parser.add_argument("--include-tests", action="store_true", help="Include test files/directories (tests/, test_*.py, *_test.py)")
    ast_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output with full details")
    ast_parser.add_argument("--compact", action="store_true", help="Compact table output for CI logs")

    # --- inspect command ---
    inspect_parser = subparsers.add_parser("inspect", help="Live MCP server introspection & security scan")
    inspect_group = inspect_parser.add_mutually_exclusive_group(required=True)
    inspect_group.add_argument("--command", type=str, help="Command to start MCP server (e.g., 'python server.py')")
    inspect_group.add_argument("--url", type=str, help="HTTP/SSE URL of MCP server")
    inspect_group.add_argument("--config-file", type=str, help="Path to MCP config JSON file (uses first server)")
    inspect_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")
    inspect_parser.add_argument("--sarif", type=str, help="Export report to SARIF file")
    inspect_parser.add_argument("--html", type=str, help="Export report to HTML file")
    inspect_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Exit with error if findings at or above this severity")
    inspect_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output with full details")
    inspect_parser.add_argument("--compact", action="store_true", help="Compact table output for CI logs")

    # --- proxy command ---
    proxy_parser = subparsers.add_parser("proxy", help="Runtime MCP Security Proxy/Firewall")
    proxy_group = proxy_parser.add_mutually_exclusive_group(required=True)
    proxy_group.add_argument("--command", type=str, help="Command to start MCP server (e.g., 'python server.py')")
    proxy_group.add_argument("--url", type=str, help="HTTP/SSE URL of MCP server")
    proxy_parser.add_argument("--bind", type=str, default="127.0.0.1:8080", help="Bind address (host:port)")
    proxy_parser.add_argument("--timeout", type=float, default=30.0, help="Upstream connection timeout")
    proxy_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Exit with error if findings at or above this severity")
    proxy_parser.add_argument("--audit-log", type=str, help="Path to audit log file")
    proxy_parser.add_argument("--audit-format", choices=["jsonl", "text"], default="jsonl", help="Audit log format")
    proxy_parser.add_argument("--rate-limit", type=int, default=100, help="Max requests per second")
    proxy_parser.add_argument("--max-size", type=int, default=1048576, help="Max request size in bytes")
    proxy_parser.add_argument("--no-block-critical", action="store_true", help="Don't block CRITICAL findings")
    proxy_parser.add_argument("--no-block-high", action="store_true", help="Don't block HIGH findings")
    proxy_parser.add_argument("--block-medium", action="store_true", help="Block MEDIUM findings")
    proxy_parser.add_argument("--block-low", action="store_true", help="Block LOW findings")

    # Add shared options to scan parser
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output with full details")
    scan_parser.add_argument("--compact", action="store_true", help="Compact table output for CI logs")

    args = parser.parse_args()

    # Handle --version flag
    if args.version:
        print(f"aegismcp {get_package_version()}")
        sys.exit(0)

    # Route to command handler
    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "lock":
        sys.exit(cmd_lock(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "ast-scan":
        sys.exit(cmd_ast_scan(args))
    elif args.command == "inspect":
        sys.exit(cmd_inspect(args))
    elif args.command == "proxy":
        sys.exit(cmd_proxy(args))
    elif args.command is None:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()