"""Clean, scannable CLI reporter for AegisMCP v3.0.0."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .rules_core import Finding
from .ast_scanner import ASTFinding


# Color codes (Windows PowerShell-safe, no emojis)
COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[96m",    # Cyan
    "LOW": "\033[90m",       # Gray
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_BADGE = {
    "CRITICAL": "[CRIT]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MED] ",
    "LOW":      "[LOW] ",
}


@dataclass
class ReportOptions:
    """Options controlling report output."""
    verbose: bool = False
    compact: bool = False
    show_color: bool = True
    no_color: bool = False
    fail_on: str = "HIGH"


def _colorize(text: str, severity: str, show_color: bool) -> str:
    """Apply color to text based on severity."""
    if not show_color:
        return text
    color = COLORS.get(severity, "")
    reset = COLORS["RESET"]
    return f"{color}{text}{reset}"


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + "..."


def _group_findings_by_target(findings: list) -> dict[str, list]:
    """Group findings by target file/server, sorted by severity."""
    grouped: dict[str, list] = {}
    for f in findings:
        location = getattr(f, "location", "unknown")
        # Extract file/server from location
        if ":" in location:
            target = location.split(":")[0]
        else:
            target = location
        grouped.setdefault(target, []).append(f)

    # Sort findings within each group by severity (CRITICAL first)
    for target_findings in grouped.values():
        target_findings.sort(key=lambda f: SEVERITY_RANK.get(getattr(f, "severity", "MEDIUM"), 0), reverse=True)

    return grouped


def _format_finding_compact(finding: Any, show_color: bool) -> str:
    """Format a finding in compact single-line table view."""
    severity = getattr(finding, "severity", "MEDIUM")
    rule_id = getattr(finding, "rule_id", "UNKNOWN")
    title = getattr(finding, "title", "Unknown Issue")
    location = getattr(finding, "location", "Unknown Location")

    badge = SEVERITY_BADGE.get(severity, "[?]")
    colored_badge = _colorize(badge, severity, show_color)

    # Format: [CRIT] AMCP005  Tool Poisoning          (server: helper_tool)
    loc_display = _truncate(location, 35)
    return f"{colored_badge} {rule_id:<7} {_truncate(title, 28):<28} ({loc_display})"


def _format_finding_default(finding: Any, show_color: bool) -> list[str]:
    """Format a finding in default 3-line aligned block."""
    severity = getattr(finding, "severity", "MEDIUM")
    rule_id = getattr(finding, "rule_id", "UNKNOWN")
    title = getattr(finding, "title", "Unknown Issue")
    location = getattr(finding, "location", "Unknown Location")
    message = getattr(finding, "message", "")
    remediation = getattr(finding, "remediation", "")

    badge = SEVERITY_BADGE.get(severity, "[?]")
    colored_badge = _colorize(badge, severity, show_color)

    lines = []

    # Line 1: [CRIT] AMCP005  Tool Poisoning          (server: helper_tool)
    loc_display = _truncate(location, 50)
    lines.append(f"{colored_badge} {rule_id:<7} {_truncate(title, 28):<28} ({loc_display})")

    # Line 2: Why: one concise sentence
    why = _truncate(message, 80) if message else "No details available"
    lines.append(f"       Why: {why}")

    # Line 3: Fix: one direct, actionable fix
    fix = _truncate(remediation, 80) if remediation else "No remediation available"
    lines.append(f"       Fix: {fix}")

    return lines


def _format_finding_verbose(finding: Any, show_color: bool) -> list[str]:
    """Format a finding in verbose mode with full details."""
    lines = _format_finding_default(finding, show_color)

    # Add extra context in verbose mode
    if hasattr(finding, "file_path") and hasattr(finding, "line"):
        # ASTFinding
        lines.append(f"       File:  {finding.file_path}:{finding.line}:{finding.column}")

    return lines


def print_report(
    findings: list,
    file_count: int = 1,
    options: ReportOptions | None = None,
    output: Any = None
) -> int:
    """
    Print a clean, scannable report of findings.

    Returns exit code: 0 = PASS, 1 = FAIL (findings >= fail_on threshold)
    """
    if options is None:
        options = ReportOptions()

    show_color = options.show_color and not options.no_color

    if output is None:
        output = sys.stdout

    if not findings:
        print(_colorize("[OK] No security issues found.", "LOW", show_color), file=output)
        print_summary_box(0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, file_count, True, show_color, output)
        return 0

    # Group by target
    grouped = _group_findings_by_target(findings)

    # Print findings
    if options.compact:
        # Compact table header
        header = f"{'SEV':<6} {'RULE':<7} {'TITLE':<28} {'LOCATION'}"
        if show_color:
            header = _colorize(header, "LOW", show_color)
        print(header, file=output)
        print("-" * 80, file=output)

        for target in sorted(grouped.keys()):
            for finding in grouped[target]:
                print(_format_finding_compact(finding, show_color), file=output)
    else:
        # Default grouped output
        for target in sorted(grouped.keys()):
            target_findings = grouped[target]
            # Target header
            target_label = _colorize(f"== {target} ({len(target_findings)} findings) ==", "LOW", show_color)
            print(target_label, file=output)

            for finding in target_findings:
                if options.verbose:
                    lines = _format_finding_verbose(finding, show_color)
                else:
                    lines = _format_finding_default(finding, show_color)
                for line in lines:
                    print(line, file=output)
            print(file=output)  # Blank line between targets

    # Summary box
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = getattr(f, "severity", "MEDIUM")
        if sev in counts:
            counts[sev] += 1

    threshold = SEVERITY_RANK.get(options.fail_on, 3)
    has_critical = any(SEVERITY_RANK.get(getattr(f, "severity", "MEDIUM"), 0) >= threshold for f in findings)

    print_summary_box(len(findings), counts, file_count, not has_critical, show_color, output)

    return 1 if has_critical else 0


def print_summary_box(
    total_findings: int,
    counts: dict[str, int],
    file_count: int,
    passed: bool,
    show_color: bool,
    output: Any = None
) -> None:
    """Print a compact, aligned Summary Box."""
    if output is None:
        output = sys.stdout

    # Security Score (0-100): deduct points per severity
    score = 100
    score -= counts.get("CRITICAL", 0) * 20
    score -= counts.get("HIGH", 0) * 10
    score -= counts.get("MEDIUM", 0) * 4
    score -= counts.get("LOW", 0) * 1
    score = max(0, score)

    # Build severity pills
    severity_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = counts.get(sev, 0)
        if count > 0:
            badge = SEVERITY_BADGE[sev].strip()
            pill = f"{badge}:{count}"
            if show_color:
                pill = _colorize(pill, sev, show_color)
            severity_parts.append(pill)

    severity_str = "  ".join(severity_parts) if severity_parts else "none"

    # Status
    status = "PASS" if passed else "FAIL"
    if show_color:
        status = _colorize(status, "LOW" if passed else "CRITICAL", show_color)

    print("+" + "-" * 62 + "+", file=output)
    print(f"| Security Score: {score:>3}/100  |  Findings: {severity_str:<35} |", file=output)
    print(f"| Targets Scanned: {file_count:<3}       |  Status:     {status:<45} |", file=output)
    print("+" + "-" * 62 + "+", file=output)


def calculate_security_score(findings: list) -> int:
    """Calculate security score (0-100) from findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = getattr(f, "severity", "MEDIUM")
        if sev in counts:
            counts[sev] += 1

    score = 100
    score -= counts.get("CRITICAL", 0) * 20
    score -= counts.get("HIGH", 0) * 10
    score -= counts.get("MEDIUM", 0) * 4
    score -= counts.get("LOW", 0) * 1
    return max(0, score)