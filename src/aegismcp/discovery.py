"""Auto-discovery of MCP configuration files across platforms."""
from __future__ import annotations

import os
import platform
from collections.abc import Iterator
from pathlib import Path


def get_config_paths() -> list[Path]:
    """
    Get all known MCP configuration file paths for the current platform.
    Returns paths that exist on the filesystem.
    """
    paths = []
    system = platform.system().lower()

    # Common paths across platforms
    home = Path.home()

    if system == "windows":
        # Windows: %APPDATA% and %USERPROFILE%
        appdata = os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))
        localappdata = os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))

        # Claude Desktop
        paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
        # Cursor
        paths.append(Path(appdata) / "Cursor" / "mcp.json")
        paths.append(Path(localappdata) / "Cursor" / "mcp.json")
        # Windsurf
        paths.append(Path(appdata) / "Windsurf" / "mcp.json")
        paths.append(Path(localappdata) / "Windsurf" / "mcp.json")
        # VS Code (user settings)
        paths.append(Path(appdata) / "Code" / "User" / "mcp.json")
        paths.append(Path(localappdata) / "Code" / "User" / "mcp.json")

    elif system == "darwin":  # macOS
        # Claude Desktop
        paths.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
        # Cursor
        paths.append(home / "Library" / "Application Support" / "Cursor" / "mcp.json")
        # Windsurf
        paths.append(home / "Library" / "Application Support" / "Windsurf" / "mcp.json")
        # VS Code
        paths.append(home / "Library" / "Application Support" / "Code" / "User" / "mcp.json")

    else:  # Linux and others
        # XDG_CONFIG_HOME or ~/.config
        xdg_config = os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))

        # Claude Desktop
        paths.append(Path(xdg_config) / "Claude" / "claude_desktop_config.json")
        # Cursor
        paths.append(Path(xdg_config) / "Cursor" / "mcp.json")
        # Windsurf
        paths.append(Path(xdg_config) / "Windsurf" / "mcp.json")
        # VS Code
        paths.append(Path(xdg_config) / "Code" / "User" / "mcp.json")

    # Project-local files (always checked)
    cwd = Path.cwd()
    paths.append(cwd / "mcp.json")
    paths.append(cwd / ".mcp.json")
    paths.append(cwd / "mcp.config.json")
    paths.append(cwd / ".claude" / "mcp.json")

    # Filter to only existing files
    return [p for p in paths if p.exists() and p.is_file()]


def discover_mcp_files(root: Path | None = None, auto_discover: bool = True) -> list[Path]:
    """
    Discover all MCP configuration files.

    Args:
        root: Root directory to scan (default: cwd). If a file, returns [file].
        auto_discover: Whether to include platform-specific config locations.

    Returns:
        List of discovered MCP config file paths.
    """
    if root is None:
        root = Path.cwd()

    files = []

    # If root is a file, just return it
    if root.is_file():
        return [root]

    # Scan project directory for JSON files that look like MCP configs
    for json_file in root.rglob("*.json"):
        # Skip node_modules, .git, __pycache__, etc.
        if any(part in json_file.parts for part in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build")):
            continue
        if _looks_like_mcp_config(json_file):
            files.append(json_file)

    # Add platform-specific configs if auto_discover is enabled
    if auto_discover:
        files.extend(get_config_paths())

    # Deduplicate while preserving order
    seen = set()
    unique_files = []
    for f in files:
        resolved = f.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique_files.append(f)

    return unique_files


def _looks_like_mcp_config(path: Path) -> bool:
    """Heuristic: does this JSON file look like an MCP config?"""
    # Skip lockfiles
    if path.name.endswith(".lock.json") or "lock" in path.name.lower():
        return False
    try:
        import json
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        # Check for MCP-specific keys
        if isinstance(data, dict):
            return any(key in data for key in ("mcpServers", "servers", "tools", "resources", "prompts"))
    except (OSError, json.JSONDecodeError):
        pass
    return False


def iter_json_files(root: Path) -> Iterator[Path]:
    """Iterate over JSON files in a directory, skipping common ignore dirs."""
    ignore_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache", ".mypy_cache"}

    for json_file in root.rglob("*.json"):
        if any(part in ignore_dirs for part in json_file.parts):
            continue
        yield json_file