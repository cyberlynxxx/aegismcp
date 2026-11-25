"""Cross-Server & Schema Security Rules - AMCP201, AMCP202, AMCP203."""
from __future__ import annotations

from dataclasses import dataclass, field

from .inspector import MCPServerInfo, MCPTool
from .lockfile import Lockfile as LockfileType
from .lockfile import compute_tool_hash
from .rules.builtins.cross_rules import _check_schema_recursive
from .rules_core import Finding


@dataclass
class CrossServerConfig:
    """Configuration for cross-server checks."""
    check_shadowing: bool = True
    check_schema_drift: bool = True
    check_permissive_schemas: bool = True
    allowlist: list[str] = field(default_factory=list)  # Tool names to ignore


class CrossServerChecker:
    """Cross-server security rule checker."""

    def __init__(self, config: CrossServerConfig | None = None):
        self.config = config or CrossServerConfig()
        self.findings: list[Finding] = []

    def check_servers(self, servers: list[MCPServerInfo]) -> list[Finding]:
        """Run all cross-server checks on a list of servers."""
        self.findings = []

        if self.config.check_shadowing:
            self.findings.extend(self._check_tool_shadowing(servers))

        if self.config.check_permissive_schemas:
            for server in servers:
                self.findings.extend(self._check_permissive_schemas(server))

        return self.findings

    def check_schema_drift(self, current: list[MCPServerInfo], lockfile: LockfileType) -> list[Finding]:
        """Detect schema drift between live servers and lockfile (AMCP202)."""
        self.findings = []

        if not self.config.check_schema_drift:
            return self.findings

        for server in current:
            locked_server = lockfile.servers.get(server.name)
            if not locked_server:
                # New server not in lockfile
                self.findings.append(Finding(
                    rule_id="AMCP202",
                    severity="HIGH",
                    title="New Server Not in Lockfile",
                    message=f"Server '{server.name}' is not present in the lockfile",
                    location=f"{server.name}:server",
                    remediation="Update lockfile with 'aegismcp lock --live' or investigate unexpected server"
                ))
                continue

            # Check each tool for drift
            locked_tools = {t.name: t for t in locked_server.tools}
            current_tools = {t.name: t for t in server.tools}

            # Tools removed
            for name in locked_tools:
                if name not in current_tools:
                    self.findings.append(Finding(
                        rule_id="AMCP202",
                        severity="CRITICAL",
                        title="Tool Removed - Schema Drift",
                        message=f"Tool '{name}' was in lockfile but is missing from live server",
                        location=f"{server.name}:tools.{name}",
                        remediation="Investigate immediately - tool may have been removed maliciously or server downgraded"
                    ))

            # Tools added
            for name, tool in current_tools.items():
                if name not in locked_tools:
                    self.findings.append(Finding(
                        rule_id="AMCP202",
                        severity="HIGH",
                        title="New Tool Added - Schema Drift",
                        message=f"Tool '{name}' not in lockfile - possible rug-pull or new feature",
                        location=f"{server.name}:tools.{name}",
                        remediation="Verify this tool is expected; update lockfile if legitimate"
                    ))
                else:
                    # Check for modifications
                    locked_tool = locked_tools[name]
                    current_hash = compute_tool_hash(tool.name, tool.description, tool.input_schema)
                    if current_hash != locked_tool.hash:
                        # Determine what changed
                        changes = []
                        if tool.description != locked_tool.description:
                            changes.append("description")
                        if tool.input_schema != locked_tool.input_schema:
                            changes.append("inputSchema")

                        severity = "CRITICAL" if "description" in changes else "HIGH"
                        self.findings.append(Finding(
                            rule_id="AMCP202",
                            severity=severity,
                            title="Tool Definition Changed - Schema Drift",
                            message=f"Tool '{name}' has drifted: {', '.join(changed for changed in changes)}",
                            location=f"{server.name}:tools.{name}",
                            remediation="Investigate immediately - possible tool poisoning or unauthorized update"
                        ))

        return self.findings

    def check_lockfile_drift(self, lockfile1: LockfileType, lockfile2: LockfileType) -> list[Finding]:
        """Compare two lockfiles for drift (e.g., CI vs production)."""
        self.findings = []

        all_servers = set(lockfile1.servers.keys()) | set(lockfile2.servers.keys())

        for server_name in all_servers:
            server1 = lockfile1.servers.get(server_name)
            server2 = lockfile2.servers.get(server_name)

            if server1 and not server2:
                self.findings.append(Finding(
                    rule_id="AMCP202",
                    severity="HIGH",
                    title="Server Missing in Second Lockfile",
                    message=f"Server '{server_name}' present in first lockfile but not second",
                    location=f"{server_name}:server",
                    remediation="Verify server configuration consistency across environments"
                ))
            elif server2 and not server1:
                self.findings.append(Finding(
                    rule_id="AMCP202",
                    severity="HIGH",
                    title="New Server in Second Lockfile",
                    message=f"Server '{server_name}' present in second lockfile but not first",
                    location=f"{server_name}:server",
                    remediation="Verify new server is expected and authorized"
                ))
            elif server1 and server2:
                tools1 = {t.name: t for t in server1.tools}
                tools2 = {t.name: t for t in server2.tools}

                all_tools = set(tools1.keys()) | set(tools2.keys())
                for tool_name in all_tools:
                    t1 = tools1.get(tool_name)
                    t2 = tools2.get(tool_name)

                    if t1 and not t2:
                        self.findings.append(Finding(
                            rule_id="AMCP202",
                            severity="CRITICAL",
                            title="Tool Missing in Second Lockfile",
                            message=f"Tool '{tool_name}' in server '{server_name}' missing from second lockfile",
                            location=f"{server_name}:tools.{tool_name}",
                            remediation="Investigate tool removal across environments"
                        ))
                    elif t2 and not t1:
                        self.findings.append(Finding(
                            rule_id="AMCP202",
                            severity="HIGH",
                            title="New Tool in Second Lockfile",
                            message=f"Tool '{tool_name}' in server '{server_name}' is new in second lockfile",
                            location=f"{server_name}:tools.{tool_name}",
                            remediation="Verify new tool is authorized"
                        ))
                    elif t1 and t2 and t1.hash != t2.hash:
                        self.findings.append(Finding(
                            rule_id="AMCP202",
                            severity="HIGH",
                            title="Tool Hash Mismatch Between Lockfiles",
                            message=f"Tool '{tool_name}' has different hash in two lockfiles",
                            location=f"{server_name}:tools.{tool_name}",
                            remediation="Investigate definition difference; ensure consistent deployments"
                        ))

        return self.findings

    def _check_tool_shadowing(self, servers: list[MCPServerInfo]) -> list[Finding]:
        """AMCP201 - Tool shadowing: same tool name across multiple servers."""
        findings = []

        # Build tool name -> (server, tool) mapping
        tool_map: dict[str, list[tuple[str, MCPTool]]] = {}

        for server in servers:
            if server.name in self.config.allowlist:
                continue
            for tool in server.tools:
                if tool.name in self.config.allowlist:
                    continue
                tool_map.setdefault(tool.name, []).append((server.name, tool))

        # Find duplicates
        for tool_name, occurrences in tool_map.items():
            if len(occurrences) > 1:
                server_names = [s for s, _ in occurrences]
                findings.append(Finding(
                    rule_id="AMCP201",
                    severity="HIGH",
                    title="Tool Shadowing Across Servers",
                    message=f"Tool '{tool_name}' defined in {len(occurrences)} servers: {', '.join(server_names)}",
                    location=f"cross-server:tools.{tool_name}",
                    remediation=f"Rename tools to be unique (e.g., '{tool_name}_server1') or use namespaced calls"
                ))

        return findings

    def _check_permissive_schemas(self, server: MCPServerInfo) -> list[Finding]:
        """AMCP203 - Over-permissive tool input schemas (cross-server awareness)."""
        findings = []

        for tool in server.tools:
            if tool.name in self.config.allowlist:
                continue

            schema = tool.input_schema
            if not isinstance(schema, dict):
                continue

            if not _check_schema_recursive(schema):
                # Include tool description in message for XSS detection/escaping
                desc = tool.description or ""
                findings.append(Finding(
                    rule_id="AMCP203",
                    severity="MEDIUM",
                    title="Overly Permissive Input Schema",
                    message=f"Tool '{tool.name}' input schema lacks validation constraints (pattern, enum, min/max, etc.). Description: {desc}",
                    location=f"{server.name}:tools.{tool.name}.inputSchema",
                    remediation="Add pattern, enum, or numeric constraints to tool input parameters to prevent injection.",
                ))

        return findings


def check_cross_server(servers: list[MCPServerInfo], config: CrossServerConfig | None = None) -> list[Finding]:
    """Main entry point for cross-server checks."""
    checker = CrossServerChecker(config)
    return checker.check_servers(servers)


def check_schema_drift(current: list[MCPServerInfo], lockfile: LockfileType, config: CrossServerConfig | None = None) -> list[Finding]:
    """Main entry point for schema drift detection."""
    checker = CrossServerChecker(config)
    return checker.check_schema_drift(current, lockfile)


def check_lockfile_drift(lockfile1: LockfileType, lockfile2: LockfileType, config: CrossServerConfig | None = None) -> list[Finding]:
    """Main entry point for lockfile comparison."""
    checker = CrossServerChecker(config)
    return checker.check_lockfile_drift(lockfile1, lockfile2)