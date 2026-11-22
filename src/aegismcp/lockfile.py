"""Lockfile management for trusted MCP tool definitions (aegismcp lock/verify)."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOCKFILE_NAME = "aegismcp.lock.json"


@dataclass
class ToolDefinition:
    """A single tool definition with its hash."""
    name: str
    description: str
    input_schema: dict[str, Any]
    # Hash of the canonical representation
    hash: str


@dataclass
class ServerLock:
    """Lock data for a single MCP server."""
    name: str
    command: str | None = None
    args: list[str] = None
    env: dict[str, str] = None
    url: str | None = None
    tools: list[ToolDefinition] = None
    # Hash of the entire server config (for cross-server shadowing detection)
    config_hash: str = ""

    def __post_init__(self):
        if self.args is None:
            self.args = []
        if self.env is None:
            self.env = {}
        if self.tools is None:
            self.tools = []


@dataclass
class Lockfile:
    """Complete lockfile for all trusted MCP servers."""
    version: int = 1
    created_at: str = ""
    updated_at: str = ""
    servers: dict[str, ServerLock] = None

    def __post_init__(self):
        if self.servers is None:
            self.servers = {}
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = datetime.now(timezone.utc).isoformat()

    @classmethod
    def load(cls, path: Path | None = None) -> Lockfile:
        """Load lockfile from disk."""
        if path is None:
            path = Path.cwd() / LOCKFILE_NAME

        if not path.exists():
            return cls()

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # Deserialize
        servers = {}
        for name, server_data in data.get("servers", {}).items():
            tools = [
                ToolDefinition(**t) for t in server_data.get("tools", [])
            ]
            servers[name] = ServerLock(
                name=server_data["name"],
                command=server_data.get("command"),
                args=server_data.get("args", []),
                env=server_data.get("env", {}),
                url=server_data.get("url"),
                tools=tools,
                config_hash=server_data.get("config_hash", ""),
            )

        return cls(
            version=data.get("version", 1),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            servers=servers,
        )

    def save(self, path: Path | None = None) -> None:
        """Save lockfile to disk."""
        if path is None:
            path = Path.cwd() / LOCKFILE_NAME

        self.updated_at = datetime.now(timezone.utc).isoformat()

        data = {
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "servers": {},
        }

        for name, server in self.servers.items():
            data["servers"][name] = {
                "name": server.name,
                "command": server.command,
                "args": server.args,
                "env": server.env,
                "url": server.url,
                "tools": [asdict(t) for t in server.tools],
                "config_hash": server.config_hash,
            }

        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def compute_tool_hash(name: str, description: str, input_schema: dict[str, Any]) -> str:
    """Compute SHA-256 hash of a tool definition."""
    # Canonical representation: sorted keys for deterministic hashing
    canonical = json.dumps(
        {"name": name, "description": description, "input_schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_server_config_hash(server_config: dict[str, Any]) -> str:
    """Compute SHA-256 hash of server configuration (for cross-server shadowing)."""
    # Include command, args, env (keys only, not values for secrets), url
    canonical = json.dumps(
        {
            "command": server_config.get("command"),
            "args": server_config.get("args", []),
            "env_keys": sorted(server_config.get("env", {}).keys()),
            "url": server_config.get("url"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_lock_from_config(config_path: Path) -> Lockfile:
    """Create a lockfile from an MCP configuration file."""
    import json

    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)

    lockfile = Lockfile()

    # Handle both "mcpServers" (Claude Desktop) and "servers" formats
    servers_config = config.get("mcpServers") or config.get("servers") or {}

    for server_name, server_config in servers_config.items():
        server_lock = ServerLock(
            name=server_name,
            command=server_config.get("command"),
            args=server_config.get("args", []),
            env=server_config.get("env", {}),
            url=server_config.get("url"),
        )

        # Compute config hash for cross-server shadowing detection
        server_lock.config_hash = compute_server_config_hash(server_config)

        # Note: Tools are typically discovered dynamically at runtime.
        # For static locking, we'd need to either:
        # 1. Run the server and fetch tools/list (dynamic)
        # 2. Parse tool definitions from source code (static AST)
        # For now, we store the config hash and allow tool hashes to be added later.

        lockfile.servers[server_name] = server_lock

    return lockfile


def verify_lockfile(lockfile: Lockfile, config_path: Path) -> list[dict[str, Any]]:
    """
    Verify current config against lockfile.
    Returns list of violations found.
    """
    import json

    violations = []

    with config_path.open("r", encoding="utf-8") as f:
        current_config = json.load(f)

    current_servers = current_config.get("mcpServers") or current_config.get("servers") or {}

    # Check for removed servers
    for locked_name in lockfile.servers:
        if locked_name not in current_servers:
            violations.append({
                "type": "server_removed",
                "server": locked_name,
                "message": f"Server '{locked_name}' was in lockfile but is missing from current config",
                "severity": "HIGH",
            })

    # Check each server
    for server_name, server_config in current_servers.items():
        if server_name not in lockfile.servers:
            violations.append({
                "type": "server_added",
                "server": server_name,
                "message": f"New server '{server_name}' not in lockfile",
                "severity": "MEDIUM",
            })
            continue

        locked_server = lockfile.servers[server_name]

        # Check config hash (cross-server shadowing detection)
        current_hash = compute_server_config_hash(server_config)
        if current_hash != locked_server.config_hash:
            violations.append({
                "type": "config_changed",
                "server": server_name,
                "message": f"Server '{server_name}' configuration has changed (possible shadowing/rug-pull)",
                "severity": "CRITICAL",
                "expected_hash": locked_server.config_hash,
                "actual_hash": current_hash,
            })

        # TODO: Verify tool hashes when we have dynamic inspection
        # This would require running the server or AST scanning

    return violations


def update_lockfile_with_tools(lockfile: Lockfile, server_name: str, tools: list[dict[str, Any]]) -> None:
    """Update lockfile with tool definitions fetched from a running server."""
    if server_name not in lockfile.servers:
        return

    server = lockfile.servers[server_name]
    server.tools = [
        ToolDefinition(
            name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("inputSchema", {}),
            hash=compute_tool_hash(t["name"], t.get("description", ""), t.get("inputSchema", {})),
        )
        for t in tools
    ]
    lockfile.updated_at = datetime.now(timezone.utc).isoformat()


def verify_tools(lockfile: Lockfile, server_name: str, current_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Verify tool definitions against lockfile."""
    violations = []

    if server_name not in lockfile.servers:
        return violations

    locked_server = lockfile.servers[server_name]
    locked_tools = {t.name: t for t in locked_server.tools}

    current_tool_map = {t["name"]: t for t in current_tools}

    # Check for removed tools
    for name, locked_tool in locked_tools.items():
        if name not in current_tool_map:
            violations.append({
                "type": "tool_removed",
                "server": server_name,
                "tool": name,
                "message": f"Tool '{name}' was in lockfile but is missing from server",
                "severity": "HIGH",
            })

    # Check each current tool
    for name, current_tool in current_tool_map.items():
        if name not in locked_tools:
            violations.append({
                "type": "tool_added",
                "server": server_name,
                "tool": name,
                "message": f"New tool '{name}' not in lockfile",
                "severity": "MEDIUM",
            })
            continue

        locked_tool = locked_tools[name]
        current_hash = compute_tool_hash(
            current_tool["name"],
            current_tool.get("description", ""),
            current_tool.get("inputSchema", {}),
        )

        if current_hash != locked_tool.hash:
            violations.append({
                "type": "tool_changed",
                "server": server_name,
                "tool": name,
                "message": f"Tool '{name}' definition has changed (possible tool poisoning)",
                "severity": "CRITICAL",
                "expected_hash": locked_tool.hash,
                "actual_hash": current_hash,
            })

    return violations