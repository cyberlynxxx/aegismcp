"""Cross-server scanning rules (AMCP201-203).

These rules check interactions across multiple servers/tool definitions.
The check functions are defined in this module.
"""
from __future__ import annotations

from typing import Any

from ...rules_core import Finding
from ..registry import Rule


def check_tool_shadowing(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP201: Tool Shadowing Across Servers."""
    findings = []
    tools = data.get("tools", [])
    if isinstance(tools, list):
        seen = {}
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name = str(tool.get("name", "unknown"))
            if t_name in seen:
                findings.append(Finding(
                    rule_id="AMCP201",
                    severity="HIGH",
                    title="Tool Shadowing Across Servers",
                    message=f"Tool '{t_name}' defined multiple times, later definition shadows earlier.",
                    location=f"{location}:tools.{t_name}",
                    remediation="Rename conflicting tools or use namespacing.",
                ))
            seen[t_name] = tool
    return findings


def check_schema_drift(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP202: Schema Drift Detected."""
    findings = []
    lockfile = data.get("lockfile")
    live_schema = data.get("live_schema")
    if lockfile and live_schema and lockfile != live_schema:
        findings.append(Finding(
            rule_id="AMCP202",
            severity="HIGH",
            title="Schema Drift Detected",
            message="Live server schema differs from lockfile.",
            location=location,
            remediation="Update lockfile if the drift is intentional.",
        ))
    return findings


def _check_schema_recursive(schema: dict[str, Any]) -> bool:
    """Recursively check if a schema has meaningful security constraints (pattern, enum, min/max)."""
    if not isinstance(schema, dict):
        return False

    t = schema.get("type")
    if isinstance(t, list):
        return False

    if t == "string":
        # Check if there are meaningful security constraints. Format is advisory only.
        meaningful = ("pattern", "minimum", "maximum", "enum", "const")
        if not any(k in schema for k in meaningful):
            return False
        pattern = schema.get("pattern")
        return pattern not in (".*", "^.*$")

    props = schema.get("properties")
    if isinstance(props, dict) and len(props) > 0:
        all_constrained = True
        for prop_def in props.values():
            if not _check_schema_recursive(prop_def):
                all_constrained = False
                break
        return all_constrained

    items = schema.get("items")
    if isinstance(items, dict):
        return _check_schema_recursive(items)
    elif isinstance(items, list):
        return all(_check_schema_recursive(item) for item in items if isinstance(item, dict))

    meaningful_constraints = ("pattern", "minimum", "maximum", "enum", "const", "required")
    return bool(any(k in schema for k in meaningful_constraints))


def check_overly_permissive_schema(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP203: Overly Permissive Input Schema."""
    findings = []
    tools = data.get("tools", [])
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name = str(tool.get("name", "unknown"))
            schema = tool.get("inputSchema") or tool.get("parameters")
            if isinstance(schema, dict) and not _check_schema_recursive(schema):
                    findings.append(Finding(
                        rule_id="AMCP203",
                        severity="MEDIUM",
                        title="Overly Permissive Input Schema",
                        message=f"Tool '{t_name}' input schema lacks validation constraints (pattern, enum, min/max, etc.).",
                        location=f"{location}:tools.{t_name}",
                        remediation="Add pattern, enum, or numeric constraints to tool input parameters to prevent injection.",
                    ))
    return findings


CROSS_SERVER_RULES = [
    Rule("AMCP201", "HIGH", "Tool Shadowing Across Servers",
         "Detects duplicate tool names across multiple servers",
         "Rename conflicting tools.", check_fn=check_tool_shadowing),
    Rule("AMCP202", "HIGH", "Schema Drift Detected",
         "Detects changes between live server schema and lockfile",
         "Update lockfile if intended.", check_fn=check_schema_drift),
    Rule("AMCP203", "MEDIUM", "Overly Permissive Input Schema",
         "Detects tools without strict input constraints",
         "Add pattern/min/max constraints.", check_fn=check_overly_permissive_schema),
]
