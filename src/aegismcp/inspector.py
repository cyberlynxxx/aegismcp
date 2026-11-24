"""Live MCP Server Introspection - JSON-RPC 2.0 client for runtime security checks."""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
except ImportError:
    httpx = None

from .rules_core import Finding
from .lockfile import Lockfile, ServerLock, ToolDefinition, verify_tools, update_lockfile_with_tools, compute_tool_hash


@dataclass
class MCPTool:
    """Represents an MCP tool from tools/list."""
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class MCPServerInfo:
    """Information about a connected MCP server."""
    name: str
    protocol_version: str
    capabilities: dict[str, Any]
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)


@dataclass
class InspectorOptions:
    """Options for the inspector."""
    timeout: float = 10.0
    command: Optional[list[str]] = None
    url: Optional[str] = None
    config_file: Optional[Path] = None
    fail_on: str = "HIGH"
    sarif: Optional[Path] = None
    html: Optional[Path] = None
    compact: bool = False
    verbose: bool = False
    show_color: bool = True
    no_color: bool = False


class JSONRPCClient:
    """Lightweight JSON-RPC 2.0 client for MCP communication."""

    def __init__(self, process: Optional[subprocess.Popen] = None, http_client: Optional[Any] = None):
        self.process = process
        self.http_client = http_client
        self.request_id = 0

    def _next_id(self) -> int:
        self.request_id += 1
        return self.request_id

    async def send_request(self, method: str, params: Optional[dict] = None) -> dict:
        """Send a JSON-RPC request and return the response."""
        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            request["params"] = params

        if self.process:
            return await self._send_stdio(request)
        elif self.http_client:
            return await self._send_http(request)
        else:
            raise RuntimeError("No transport configured")

    async def send_notification(self, method: str, params: Optional[dict] = None):
        """Send a JSON-RPC notification (no response expected)."""
        request = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            request["params"] = params

        if self.process:
            await self._send_stdio_notification(request)
        elif self.http_client:
            await self._send_http(request)  # For HTTP, we still send and ignore response
        else:
            raise RuntimeError("No transport configured")

    async def _send_stdio_notification(self, request: dict):
        """Send notification via stdio transport (no response read)."""
        if not self.process or self.process.stdin is None:
            raise RuntimeError("Process not available for stdio")

        # Write request
        request_line = (json.dumps(request) + "\n").encode()
        try:
            self.process.stdin.write(request_line)
            await self.process.stdin.drain()
        except (BrokenPipeError, OSError) as e:
            raise RuntimeError(f"Failed to write to process: {e}")

    async def _send_stdio(self, request: dict) -> dict:
        """Send request via stdio transport."""
        if not self.process or self.process.stdin is None:
            raise RuntimeError("Process not available for stdio")

        # Write request
        request_line = (json.dumps(request) + "\n").encode()
        try:
            self.process.stdin.write(request_line)
            await self.process.stdin.drain()
        except (BrokenPipeError, OSError) as e:
            raise RuntimeError(f"Failed to write to process: {e}")

        # Read response with timeout
        try:
            response_line = await asyncio.wait_for(
                self.process.stdout.readline(),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            raise RuntimeError("Timeout waiting for response")

        if not response_line:
            raise RuntimeError("Process closed connection")

        try:
            response = json.loads(response_line.decode().strip())
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON response: {e}")

        if "error" in response:
            raise RuntimeError(f"RPC Error: {response['error']}")

        return response.get("result", {})

    async def _send_http(self, request: dict) -> dict:
        """Send request via HTTP/SSE transport."""
        if not self.http_client:
            raise RuntimeError("HTTP client not available")

        response = await self.http_client.post(
            self.http_client.base_url,
            json=request,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"RPC Error: {data['error']}")
        return data.get("result", {})

    async def close(self):
        """Close the connection."""
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass
        if self.http_client:
            await self.http_client.aclose()


class MCPInspector:
    """MCP Server Inspector for live runtime security checks."""

    def __init__(self, options: InspectorOptions):
        self.options = options
        self.client: Optional[JSONRPCClient] = None
        self.server_info: Optional[MCPServerInfo] = None
        self.findings: list[Finding] = []

    async def connect_stdio(self, command: list[str]) -> MCPServerInfo:
        """Connect to an MCP server via stdio."""
        # Spawn the server process
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        self.client = JSONRPCClient(process=process)
        return await self._handshake(command[0])

    async def connect_http(self, url: str) -> MCPServerInfo:
        """Connect to an MCP server via HTTP/SSE."""
        if not httpx:
            raise RuntimeError("httpx required for HTTP transport. Install with: pip install httpx")

        self.client = JSONRPCClient(
            http_client=httpx.AsyncClient(base_url=url, timeout=self.options.timeout)
        )
        return await self._handshake(url)

    async def connect_from_config(self, config_path: Path) -> MCPServerInfo:
        """Connect using server config from an MCP JSON file."""
        import json
        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)

        servers = config.get("mcpServers") or config.get("servers") or {}
        if not servers:
            raise RuntimeError("No servers found in config file")

        # Use the first server
        server_name, server_config = next(iter(servers.items()))
        command = server_config.get("command")
        args = server_config.get("args", [])
        url = server_config.get("url")

        if url:
            return await self.connect_http(url)
        elif command:
            full_command = [command] + args
            return await self.connect_stdio(full_command)
        else:
            raise RuntimeError(f"Server '{server_name}' has no command or url")

    async def _handshake(self, identifier: str) -> MCPServerInfo:
        """Perform MCP handshake: initialize -> notifications/initialized -> tools/list"""
        # Initialize
        init_result = await self.client.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {}
            },
            "clientInfo": {
                "name": "aegismcp-inspector",
                "version": "3.0.1"
            }
        })

        # Send initialized notification (no response expected)
        await self.client.send_notification("notifications/initialized", {})

        # List tools
        tools_result = await self.client.send_request("tools/list", {})
        tools = [
            MCPTool(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {})
            )
            for t in tools_result.get("tools", [])
        ]

        # List resources (optional)
        resources = []
        try:
            resources_result = await self.client.send_request("resources/list", {})
            resources = resources_result.get("resources", [])
        except Exception:
            pass

        # List prompts (optional)
        prompts = []
        try:
            prompts_result = await self.client.send_request("prompts/list", {})
            prompts = prompts_result.get("prompts", [])
        except Exception:
            pass

        self.server_info = MCPServerInfo(
            name=identifier,
            protocol_version=init_result.get("protocolVersion", "unknown"),
            capabilities=init_result.get("capabilities", {}),
            tools=tools,
            resources=resources,
            prompts=prompts
        )

        return self.server_info

    def inspect_tools(self) -> list[Finding]:
        """Run security checks on live tool definitions."""
        if not self.server_info:
            return []

        findings = []

        for tool in self.server_info.tools:
            # AMCP005 - Tool poisoning patterns
            findings.extend(self._check_tool_poisoning(tool))

            # AMCP006 - Abnormally long descriptions
            findings.extend(self._check_long_description(tool))

            # AMCP007 - Hidden invisible Unicode characters
            findings.extend(self._check_invisible_chars(tool))

            # AMCP203 - Over-permissive tool input schema
            findings.extend(self._check_permissive_schema(tool))

        # AMCP201 - Tool shadowing (duplicate names across servers - single server check)
        # This is more relevant cross-server, but we check for duplicate names within one server
        tool_names = [t.name for t in self.server_info.tools]
        if len(tool_names) != len(set(tool_names)):
            from collections import Counter
            duplicates = [name for name, count in Counter(tool_names).items() if count > 1]
            for dup in duplicates:
                findings.append(Finding(
                    rule_id="AMCP201",
                    severity="HIGH",
                    title="Tool Shadowing - Duplicate Tool Name",
                    message=f"Tool '{dup}' is defined multiple times within the same server",
                    location=f"{self.server_info.name}:tools.{dup}",
                    remediation="Ensure unique tool names within each server to prevent shadowing"
                ))

        self.findings = findings
        return findings

    def _check_tool_poisoning(self, tool: MCPTool) -> list[Finding]:
        """Check for tool poisoning patterns (AMCP005)."""
        from .rules_core import PROMPT_INJECTION_PATTERNS
        findings = []

        for pattern_name, pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(tool.description):
                findings.append(Finding(
                    rule_id="AMCP005",
                    severity="CRITICAL",
                    title=f"Tool Poisoning ({pattern_name})",
                    message=f"Tool '{tool.name}' description matches suspicious prompt injection pattern: {pattern_name}",
                    location=f"{self.server_info.name}:tools.{tool.name}",
                    remediation="Audit and sanitize the tool description; remove hidden LLM directives"
                ))

        return findings

    def _check_long_description(self, tool: MCPTool) -> list[Finding]:
        """Check for abnormally long descriptions (AMCP006)."""
        findings = []
        if len(tool.description) > 500:
            findings.append(Finding(
                rule_id="AMCP006",
                severity="MEDIUM",
                title="Abnormally Long Tool Description",
                message=f"Tool '{tool.name}' description is {len(tool.description)} chars, which can conceal injected prompts",
                location=f"{self.server_info.name}:tools.{tool.name}",
                remediation="Keep tool descriptions concise and review the full text manually"
            ))
        return findings

    def _check_invisible_chars(self, tool: MCPTool) -> list[Finding]:
        """Check for invisible Unicode characters (AMCP007)."""
        findings = []
        invisible_chars = []
        for i, ch in enumerate(tool.description):
            if ch in ("​", "‌", "‍", "⁠", "﻿", "‪", "‫", "‬", "‭", "‮"):
                invisible_chars.append((i, ch))

        if invisible_chars:
            findings.append(Finding(
                rule_id="AMCP007",
                severity="CRITICAL",
                title="Hidden Invisible Characters Detected",
                message=f"Tool '{tool.name}' description contains {len(invisible_chars)} invisible Unicode character(s)",
                location=f"{self.server_info.name}:tools.{tool.name}",
                remediation="Remove all zero-width, bidi, and Unicode tag characters from the description"
            ))
        return findings

    def _check_permissive_schema(self, tool: MCPTool) -> list[Finding]:
        """Check for over-permissive input schemas (AMCP203)."""
        findings = []
        schema = tool.input_schema
        if not isinstance(schema, dict):
            return findings

        dangerous_params = {"command", "cmd", "url", "path", "file", "filename", "sql", "query", "script", "code"}
        properties = schema.get("properties", {})

        for param_name, prop_schema in properties.items():
            if param_name.lower() in dangerous_params:
                if not isinstance(prop_schema, dict):
                    continue
                # Check if it's an unconstrained string
                if prop_schema.get("type") == "string":
                    has_constraints = any(k in prop_schema for k in ("enum", "pattern", "maxLength", "format"))
                    if not has_constraints:
                        findings.append(Finding(
                            rule_id="AMCP203",
                            severity="MEDIUM",
                            title="Over-Permissive Tool Input Schema",
                            message=f"Tool '{tool.name}' parameter '{param_name}' is an unconstrained string (dangerous: {param_name})",
                            location=f"{self.server_info.name}:tools.{tool.name}.inputSchema.{param_name}",
                            remediation=f"Add constraints: enum, pattern, maxLength, or format to '{param_name}'"
                        ))
        return findings

    async def close(self):
        """Close the connection."""
        if self.client:
            await self.client.close()


async def inspect_live(options: InspectorOptions) -> tuple[list[Finding], Optional[MCPServerInfo]]:
    """Main entry point for live inspection."""
    inspector = MCPInspector(options)

    try:
        if options.command:
            await inspector.connect_stdio(options.command)
        elif options.url:
            await inspector.connect_http(options.url)
        elif options.config_file:
            await inspector.connect_from_config(options.config_file)
        else:
            raise RuntimeError("One of --command, --url, or --config-file is required")

        findings = inspector.inspect_tools()
        return findings, inspector.server_info
    finally:
        await inspector.close()


def create_lock_from_live(options: InspectorOptions, server_info: MCPServerInfo) -> Lockfile:
    """Create a lockfile from live server tool definitions."""
    lockfile = Lockfile()
    server_lock = lockfile.servers[server_info.name] = ServerLock(name=server_info.name)

    tools = []
    for tool in server_info.tools:
        tool_hash = compute_tool_hash(tool.name, tool.description, tool.input_schema)
        tools.append(ToolDefinition(
            name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            hash=tool_hash
        ))

    lockfile.servers[server_info.name].tools = tools
    return lockfile


def verify_live(options: InspectorOptions, server_info: MCPServerInfo, lockfile: Lockfile) -> list[dict]:
    """Verify live server tools against lockfile."""
    current_tools = [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema
        }
        for t in server_info.tools
    ]
    return verify_tools(lockfile, server_info.name, current_tools)