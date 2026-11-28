"""Lockfile management for trusted MCP tool definitions (aegismcp lock/verify)."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import validate_file_size

LOCKFILE_NAME = "aegismcp.lock.json"
LOCKFILE_VERSION = "1.0"

# Unicode stealth character patterns for rug-pull detection
STEALTH_UNICODE_PATTERNS = [
    ("Zero-Width Space (ZWSP)", re.compile(r"[\u200B]")),
    ("Zero-Width Non-Joiner (ZWNJ)", re.compile(r"[\u200C]")),
    ("Zero-Width Joiner (ZWJ)", re.compile(r"[\u200D]")),
    ("Word Joiner (WJ)", re.compile(r"[\u2060]")),
    ("Zero-Width No-Break Space (BOM)", re.compile(r"[\uFEFF]")),
    ("Left-to-Right Embedding (LRE)", re.compile(r"[\u202A]")),
    ("Right-to-Left Embedding (RLE)", re.compile(r"[\u202B]")),
    ("Pop Directional Formatting (PDF)", re.compile(r"[\u202C]")),
    ("Left-to-Right Override (LRO)", re.compile(r"[\u202D]")),
    ("Right-to-Left Override (RLO)", re.compile(r"[\u202E]")),
    ("Left-to-Right Isolate (LRI)", re.compile(r"[\u2066]")),
    ("Right-to-Left Isolate (RLI)", re.compile(r"[\u2067]")),
    ("First Strong Isolate (FSI)", re.compile(r"[\u2068]")),
    ("Pop Directional Isolate (PDI)", re.compile(r"[\u2069]")),
    ("Invisible Separators", re.compile(r"[\u2061-\u2064]")),
    ("Mongolian Vowel Separator (MVS)", re.compile(r"[\u180E]")),
    ("Unicode Tag Block (E0000-E007F)", re.compile(r"[\uE0000-\uE007F]")),
]


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
    args: list[str] | None = None
    env: dict[str, str] | None = None
    url: str | None = None
    tools: list[ToolDefinition] = field(default_factory=list)
    # Hash of the entire server config (for cross-server shadowing detection)
    config_hash: str = ""
    # Aggregate hash of all tool hashes for quick server-level verification
    tools_manifest_hash: str = ""

    def __post_init__(self):
        if self.args is None:
            self.args = []
        if self.env is None:
            self.env = {}


@dataclass
class Lockfile:
    """Complete lockfile for all trusted MCP servers."""
    lockfile_version: str = LOCKFILE_VERSION
    created_at: str = ""
    updated_at: str = ""
    servers: dict[str, ServerLock] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> Lockfile:
        """Load lockfile from disk."""
        if path is None:
            path = Path.cwd() / LOCKFILE_NAME

        if not path.exists():
            return cls()

        # Validate file size
        is_valid, _warning = validate_file_size(path)
        if not is_valid:
            return cls()

        try:
            from .security import safe_json_load
            data = safe_json_load(path)
        except (ValueError, OSError):
            return cls()

        # Handle legacy version field (integer) for backward compatibility
        lockfile_version = data.get("lockfile_version") or str(data.get("version", "1"))

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
                tools_manifest_hash=server_data.get("tools_manifest_hash", ""),
            )

        return cls(
            lockfile_version=lockfile_version,
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            servers=servers,
        )

    def save(self, path: Path | None = None) -> None:
        """Save lockfile to disk with deterministic JSON serialization."""
        if path is None:
            path = Path.cwd() / LOCKFILE_NAME

        self.updated_at = datetime.now(timezone.utc).isoformat()

        data: dict[str, Any] = {
            "lockfile_version": self.lockfile_version,
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
                "tools_manifest_hash": server.tools_manifest_hash,
            }

        # Deterministic JSON: sorted keys, no whitespace, UTF-8, preserve exact chars
        json_str = json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        with path.open("w", encoding="utf-8") as f:
            f.write(json_str)


def compute_tool_hash(name: str, description: str, input_schema: dict[str, Any]) -> str:
    """Compute SHA-256 hash of a tool definition."""
    # Canonical representation: sorted keys for deterministic hashing
    canonical = json.dumps(
        {"name": name, "description": description, "input_schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_tools_manifest_hash(tools: list[ToolDefinition]) -> str:
    """Compute aggregate SHA-256 hash of all tool hashes for server-level verification."""
    # Sort tool hashes for deterministic aggregation
    sorted_hashes = sorted(t.hash for t in tools)
    manifest = json.dumps(sorted_hashes, separators=(",", ":"))
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()


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


def detect_stealth_unicode(text: str) -> list[tuple[str, list[int]]]:
    """
    Detect stealth Unicode characters in text.
    Returns list of (pattern_name, positions) tuples.
    """
    results = []
    for pattern_name, pattern in STEALTH_UNICODE_PATTERNS:
        matches = [m.start() for m in pattern.finditer(text)]
        if matches:
            results.append((pattern_name, matches))
    return results


def generate_git_style_diff(old_content: str, new_content: str, context_lines: int = 3) -> list[tuple[str, int, str]]:
    """
    Generate git-style unified diff between two strings.
    Returns list of (type, line_number, content) where type is 'remove', 'add', 'context', or 'header'.
    """
    old_lines = old_content.splitlines() if old_content else []
    new_lines = new_content.splitlines() if new_content else []

    # Simple diff algorithm - find common prefix/suffix
    prefix_len = 0
    while prefix_len < len(old_lines) and prefix_len < len(new_lines):
        if old_lines[prefix_len] == new_lines[prefix_len]:
            prefix_len += 1
        else:
            break

    suffix_len = 0
    while suffix_len < len(old_lines) - prefix_len and suffix_len < len(new_lines) - prefix_len:
        if old_lines[-(suffix_len + 1)] == new_lines[-(suffix_len + 1)]:
            suffix_len += 1
        else:
            break

    diff = []

    # Context before changes
    context_start = max(0, prefix_len - context_lines)
    for i in range(context_start, prefix_len):
        diff.append(("context", i + 1, old_lines[i]))

    # Removed lines
    for i in range(prefix_len, len(old_lines) - suffix_len):
        diff.append(("remove", i + 1, old_lines[i]))

    # Added lines
    for i in range(prefix_len, len(new_lines) - suffix_len):
        diff.append(("add", i + 1, new_lines[i]))

    # Context after changes
    for i in range(len(new_lines) - suffix_len, min(len(new_lines), len(new_lines) - suffix_len + context_lines)):
        diff.append(("context", i + 1, new_lines[i]))

    return diff


def classify_diff_type(old_content: str, new_content: str, diff_lines: list[tuple[str, int, str]]) -> str:
    """
    Classify the type of diff for semantic reporting.
    """
    has_remove = any(d[0] == "remove" for d in diff_lines)
    has_add = any(d[0] == "add" for d in diff_lines)

    # Check for stealth unicode in new content
    if detect_stealth_unicode(new_content):
        return "stealth_unicode_injected"

    # Check if it's a tool description/schema change
    if "inputSchema" in old_content or "inputSchema" in new_content:
        if has_remove and has_add:
            return "tool_changed"
        elif has_add:
            return "tool_added"
        elif has_remove:
            return "tool_removed"
        return "schema_drift"

    # Check if it's a config change
    if "command" in old_content or "args" in old_content or "env" in old_content:
        return "config_changed"

    if has_remove and has_add:
        return "tool_changed"
    elif has_add:
        return "tool_added"
    elif has_remove:
        return "tool_removed"
    return "unknown"


def create_lock_from_config(config_path: Path) -> Lockfile:
    """Create a lockfile from an MCP configuration file."""
    from .security import safe_json_load

    try:
        config = safe_json_load(config_path)
    except (ValueError, OSError):
        return Lockfile()

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
    from .security import safe_json_load

    violations: list[dict[str, Any]] = []

    try:
        current_config = safe_json_load(config_path)
    except (ValueError, OSError):
        return violations

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
    violations: list[dict[str, Any]] = []

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


def verify_lockfile_enhanced(
    lockfile: Lockfile,
    config_path: Path,
    fetch_tools_func=None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Enhanced verification with git-style diffs and stealth unicode detection.
    Returns (violations, diffs_by_server) where diffs_by_server maps server_name to diff details.
    """
    from .security import safe_json_load

    violations: list[dict[str, Any]] = []
    diffs: dict[str, Any] = {}

    try:
        current_config = safe_json_load(config_path)
    except (ValueError, OSError):
        return violations, diffs

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

            # Generate git-style diff for config change
            old_config_json = json.dumps({
                "command": locked_server.command,
                "args": locked_server.args,
                "env_keys": sorted(locked_server.env.keys()) if locked_server.env else [],
                "url": locked_server.url,
            }, sort_keys=True, separators=(",", ":"))
            new_config_json = json.dumps({
                "command": server_config.get("command"),
                "args": server_config.get("args", []),
                "env_keys": sorted(server_config.get("env", {}).keys()),
                "url": server_config.get("url"),
            }, sort_keys=True, separators=(",", ":"))

            diff_lines = generate_git_style_diff(old_config_json, new_config_json)
            diff_type = classify_diff_type(old_config_json, new_config_json, diff_lines)

            stealth_unicode = detect_stealth_unicode(new_config_json)
            if stealth_unicode:
                diff_type = "stealth_unicode_injected"
                violations.append({
                    "type": "stealth_unicode_injected",
                    "server": server_name,
                    "message": "Stealth Unicode characters detected in server config",
                    "severity": "CRITICAL",
                    "unicode_patterns": [p[0] for p in stealth_unicode],
                })

            diffs[server_name] = {
                "diff_type": diff_type,
                "diff_lines": diff_lines,
                "old_hash": locked_server.config_hash,
                "new_hash": current_hash,
            }

        # If fetch_tools_func provided, verify tools dynamically
        if fetch_tools_func:
            try:
                current_tools = fetch_tools_func(server_name, server_config)
                tool_violations, tool_diffs = verify_tools_enhanced(lockfile, server_name, current_tools)
                violations.extend(tool_violations)
                if tool_diffs:
                    diffs[f"{server_name}_tools"] = tool_diffs
            except (ValueError, OSError, RuntimeError):
                # If dynamic fetch fails, skip tool verification
                pass

    return violations, diffs


def verify_tools_enhanced(
    lockfile: Lockfile,
    server_name: str,
    current_tools: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Enhanced tool verification with git-style diffs and stealth unicode detection.
    Returns (violations, diffs_by_tool) where diffs_by_tool maps tool_name to diff details.
    """
    violations: list[dict[str, Any]] = []
    diffs: dict[str, Any] = {}

    if server_name not in lockfile.servers:
        return violations, diffs

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
            # Generate diff for removed tool
            old_tool_json = json.dumps({
                "name": locked_tool.name,
                "description": locked_tool.description,
                "input_schema": locked_tool.input_schema,
            }, sort_keys=True, separators=(",", ":"))
            diff_lines = generate_git_style_diff(old_tool_json, "")
            diffs[name] = {
                "diff_type": "tool_removed",
                "diff_lines": diff_lines,
                "old_hash": locked_tool.hash,
                "new_hash": "",
            }

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
            # Generate diff for added tool
            new_tool_json = json.dumps({
                "name": current_tool["name"],
                "description": current_tool.get("description", ""),
                "input_schema": current_tool.get("inputSchema", {}),
            }, sort_keys=True, separators=(",", ":"))
            diff_lines = generate_git_style_diff("", new_tool_json)

            # Check for stealth unicode in new tool
            stealth_unicode = detect_stealth_unicode(new_tool_json)
            diff_type = "tool_added"
            if stealth_unicode:
                diff_type = "stealth_unicode_injected"
                violations.append({
                    "type": "stealth_unicode_injected",
                    "server": server_name,
                    "tool": name,
                    "message": f"Stealth Unicode characters detected in new tool '{name}'",
                    "severity": "CRITICAL",
                    "unicode_patterns": [p[0] for p in stealth_unicode],
                })

            diffs[name] = {
                "diff_type": diff_type,
                "diff_lines": diff_lines,
                "old_hash": "",
                "new_hash": compute_tool_hash(
                    current_tool["name"],
                    current_tool.get("description", ""),
                    current_tool.get("inputSchema", {}),
                ),
            }
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

            # Generate git-style diff for tool change
            old_tool_json = json.dumps({
                "name": locked_tool.name,
                "description": locked_tool.description,
                "input_schema": locked_tool.input_schema,
            }, sort_keys=True, separators=(",", ":"))
            new_tool_json = json.dumps({
                "name": current_tool["name"],
                "description": current_tool.get("description", ""),
                "input_schema": current_tool.get("inputSchema", {}),
            }, sort_keys=True, separators=(",", ":"))

            diff_lines = generate_git_style_diff(old_tool_json, new_tool_json)
            diff_type = classify_diff_type(old_tool_json, new_tool_json, diff_lines)

            # Check for stealth unicode
            stealth_unicode = detect_stealth_unicode(new_tool_json)
            if stealth_unicode:
                diff_type = "stealth_unicode_injected"
                violations.append({
                    "type": "stealth_unicode_injected",
                    "server": server_name,
                    "tool": name,
                    "message": f"Stealth Unicode characters detected in tool '{name}'",
                    "severity": "CRITICAL",
                    "unicode_patterns": [p[0] for p in stealth_unicode],
                })

            diffs[name] = {
                "diff_type": diff_type,
                "diff_lines": diff_lines,
                "old_hash": locked_tool.hash,
                "new_hash": current_hash,
            }

    return violations, diffs


def compute_verification_exit_code(violations: list[dict[str, Any]]) -> int:
    """
    Compute exit code based on violations.
    0 = clean, 1 = drift, 2 = rug-pull, 3 = error
    """
    if not violations:
        return 0

    has_critical = any(v.get("severity") == "CRITICAL" for v in violations)
    has_high = any(v.get("severity") == "HIGH" for v in violations)
    has_rug_pull = any(
        v.get("type") in ("stealth_unicode_injected", "config_changed", "tool_changed")
        for v in violations
    )

    if has_rug_pull and has_critical:
        return 2  # Rug-pull detected
    elif has_critical or has_high:
        return 1  # Drift or high severity
    else:
        return 1  # Drift (medium/low)
