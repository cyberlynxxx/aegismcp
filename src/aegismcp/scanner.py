"""Main scanner engine using rule registry."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Config
from .rules_core import Finding
from .rules.registry import registry


def scan_file(file_path: Path, config: Config | None = None) -> list[Finding]:
    """
    Scan a single MCP configuration file for security issues.

    Args:
        file_path: Path to the JSON config file
        config: Optional Config object for rule enable/disable and severity overrides

    Returns:
        List of Finding objects
    """
    if config is None:
        config = Config()

    # Add custom rules from config to registry
    registry.add_custom_rules(config.custom_rules)

    findings: list[Finding] = []

    try:
        data: Any = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return [
            Finding(
                rule_id="AMCP000",
                severity="LOW",
                title="Unreadable Config File",
                message=f"Could not parse JSON: {exc}",
                location=str(file_path),
                remediation="Ensure the file is valid UTF-8 JSON.",
            )
        ]

    if not isinstance(data, dict):
        return findings

    # Run all enabled built-in rules
    for rule in registry.enabled_rules(config.rules):
        # Get severity (config override or default)
        severity = config.get_rule_severity(rule.rule_id, rule.severity)

        # Run the rule check
        rule_findings = rule.check_fn(data, str(file_path))

        # Apply severity override
        for finding in rule_findings:
            finding.severity = severity
            findings.append(finding)

    # Run custom regex rules from config
    for custom_rule in config.custom_rules:
        custom_findings = _check_custom_rule(data, str(file_path), custom_rule, config)
        findings.extend(custom_findings)

    return findings


def _check_custom_rule(data: dict[str, Any], location: str, custom_rule: dict[str, Any], config: Config) -> list[Finding]:
    """Check a custom regex rule against the config data."""
    import re

    findings = []
    rule_id = custom_rule.get("id", "CUSTOM")
    pattern_str = custom_rule.get("pattern", "")
    severity = custom_rule.get("severity", "MEDIUM")
    title = custom_rule.get("title", "Custom Rule Match")
    message_template = custom_rule.get("message", "Custom rule matched")
    remediation = custom_rule.get("remediation", "Review the matched content.")
    target = custom_rule.get("target", "tools.description")  # tools.description, servers.env, etc.

    try:
        pattern = re.compile(pattern_str)
    except re.error:
        return findings

    # Apply config severity override
    severity = config.get_rule_severity(rule_id, severity)

    # Extract target data
    if target == "tools.description":
        tools = data.get("tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                t_name = str(tool.get("name", "unknown"))
                desc = str(tool.get("description", ""))
                if pattern.search(desc):
                    findings.append(Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        message=message_template.format(tool=t_name, match=pattern_str),
                        location=f"{location}:tools.{t_name}",
                        remediation=remediation,
                    ))
    elif target == "servers.env":
        servers = data.get("mcpServers", {}) or data.get("servers", {})
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if not isinstance(cfg, dict):
                    continue
                env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
                for k, v in env.items():
                    val = str(v)
                    if pattern.search(val):
                        findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=title,
                            message=message_template.format(server=name, key=k, match=pattern_str),
                            location=f"{location}:mcpServers.{name}.env.{k}",
                            remediation=remediation,
                        ))

    return findings


def scan_directory(root: Path, config: Config | None = None) -> list[Finding]:
    """Scan all MCP config files in a directory."""
    from .discovery import iter_json_files, _looks_like_mcp_config

    if config is None:
        config = Config()

    all_findings = []

    for json_file in iter_json_files(root):
        if config.should_ignore(json_file):
            continue
        if _looks_like_mcp_config(json_file):
            all_findings.extend(scan_file(json_file, config))

    return all_findings