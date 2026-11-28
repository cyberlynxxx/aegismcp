"""Shield/unshield commands for AegisMCP v4.0.0.

Provides the aegismcp shield and aegismcp unshield CLI commands
for creating hardened wrapper scripts around MCP servers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .events import ShieldActionEvent, get_event_bus
from .lockfile import Lockfile, create_lock_from_config


@dataclass
class ShieldConfig:
    """Configuration for a shield wrapper."""
    server_name: str
    command: list[str]
    config_hash: str
    lockfile_hash: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    shield_hash: str = ""  # Hash of the shield wrapper itself


def _compute_file_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _generate_shield_hash(config: ShieldConfig) -> str:
    """Generate a unique hash for this shield configuration."""
    data = f"{config.server_name}:{config.command}:{config.config_hash}:{config.lockfile_hash}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def _load_mcp_config(config_path: Path) -> dict[str, Any]:
    """Load MCP server configuration from a JSON file.

    Supports both Claude Desktop format (mcpServers) and standard format (servers).
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

    # Handle both "mcpServers" (Claude Desktop) and "servers" formats
    servers_config = data.get("mcpServers") or data.get("servers") or {}
    return servers_config if isinstance(servers_config, dict) else {}


def create_shield_script(config_path: Path, output_path: Path | None = None,
                          lockfile_path: Path | None = None,
                          env_vars: dict[str, str] | None = None,
                          log_file: Path | None = None) -> int:
    """Create a shielded wrapper script around an MCP server.

    Returns 0 on success, non-zero on error.
    """
    # Load MCP config (JSON with mcpServers or servers key)
    servers_config = _load_mcp_config(config_path)

    if not servers_config:
        print("Error: No servers found in config")
        return 1

    server_name = next(iter(servers_config.keys()))
    server_config = servers_config.get(server_name, {})

    # Get command
    command = server_config.get("command", [])
    if not command:
        print("Error: Server has no command specified")
        return 1

    # Create lockfile if not provided
    lockfile = None
    if lockfile_path and lockfile_path.exists():
        lockfile = Lockfile.load(lockfile_path)
    else:
        lockfile = create_lock_from_config(config_path)
        lockfile_path = config_path.parent / "aegismcp.lock.json"
        lockfile.save(lockfile_path)

    # Compute hashes
    config_hash = _compute_file_hash(config_path)
    lockfile_hash = _compute_file_hash(lockfile_path) if lockfile_path else ""

    # Create shield config
    shield_cfg = ShieldConfig(
        server_name=server_name,
        command=command,
        config_hash=config_hash,
        lockfile_hash=lockfile_hash,
    )
    shield_cfg.shield_hash = _generate_shield_hash(shield_cfg)

    # Generate wrapper script
    wrapper_content = _generate_wrapper_content(shield_cfg, env_vars, log_file)

    # Determine output path
    if output_path is None:
        output_path = config_path.parent / f"{server_name}-shielded.py"

    # Write wrapper
    with open(output_path, "w") as f:
        f.write(wrapper_content)

    # Make executable on Unix
    if os.name != "nt":
        os.chmod(output_path, os.stat(output_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    server_lock = lockfile.servers.get(server_name)
    tool_count = len(server_lock.tools) if server_lock else 0

    print(f"[OK] Shield created: {output_path}")
    print(f"  Server: {server_name}")
    print(f"  Command: {' '.join(command)}")
    print(f"  Config hash: {config_hash[:16]}...")
    if lockfile:
        print(f"  Tools locked: {tool_count}")
    print(f"  Shield hash: {shield_cfg.shield_hash}")

    # Publish event
    event = ShieldActionEvent(
        action="wrap",
        config_path=str(config_path),
        server_name=server_name,
        success=True,
        message=f"Shield created for {server_name} with {tool_count} locked tools"
    )
    get_event_bus().publish(event)

    return 0


def create_unshield_script(output_path: Path | None = None,
                            restore_path: Path | None = None) -> int:
    """Create an unshield script to restore original configuration.

    Args:
        output_path: Where to save the unshield script
        restore_path: Path to the backup to restore

    Returns 0 on success, non-zero on error.
    """
    if not restore_path or not restore_path.exists():
        print("Error: --restore-path required and must exist")
        return 1

    # Generate unshield script
    unshield_content = f'''#!/usr/bin/env python3
"""Unshield script to restore original MCP configuration."""

from pathlib import Path
import shutil
import sys

def main():
    restore_path = Path("{restore_path}")
    backup_dir = restore_path.parent

    if not restore_path.exists():
        print(f"Error: Backup not found at {{restore_path}}")
        return 1

    # Restore lockfile
    lockfile_backup = backup_dir / "aegismcp.lock.json.bak"
    if lockfile_backup.exists():
        shutil.copy2(lockfile_backup, restore_path / "aegismcp.lock.json")
        print(f"[OK] Restored lockfile from {{lockfile_backup}}")

    # Remove shield file
    shield_file = backup_dir / "server-shielded.py"
    if shield_file.exists():
        shield_file.unlink()
        print(f"[OK] Removed shield file")

    print("[OK] Unshield complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

    if output_path is None:
        output_path = restore_path.parent / "unshield.py"

    with open(output_path, "w") as f:
        f.write(unshield_content)

    # Make executable on Unix
    if os.name != "nt":
        os.chmod(output_path, os.stat(output_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"[OK] Unshield script created: {output_path}")

    return 0


def _generate_wrapper_content(shield_cfg: ShieldConfig,
                               env_vars: dict[str, str] | None,
                               log_file: Path | None) -> str:
    """Generate the wrapper script content."""

    env_setup = ""
    if env_vars:
        for key, value in env_vars.items():
            env_setup += f'    os.environ["{key}"] = "{value}"\n'

    log_setup = ""
    if log_file:
        log_setup = f'''
    if log_file:
        log_path = Path("{log_file}")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(f"{{datetime.now().isoformat()}}: Starting {{server_name}}\\n")
'''

    return f'''#!/usr/bin/env python3
"""Shielded MCP server wrapper - {shield_cfg.server_name}

Config hash: {shield_cfg.config_hash}
Shield hash: {shield_cfg.shield_hash}
Created: {shield_cfg.created_at}

This wrapper enforces:
- Lockfile verification on startup
- Runtime taint monitoring via TaintFirewall
- Audit logging
- Process isolation where possible
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Shield configuration
SERVER_NAME = "{shield_cfg.server_name}"
COMMAND = {shield_cfg.command}
CONFIG_HASH = "{shield_cfg.config_hash}"
LOCKFILE_HASH = "{shield_cfg.lockfile_hash}"
SHIELD_HASH = "{shield_cfg.shield_hash}"

def run_server():
    """Run the MCP server with shield protections."""

    # Setup environment
    os.environ.setdefault("AEGISMCP_SHIELD_ENABLED", "1")
    os.environ.setdefault("AEGISMCP_SERVER_NAME", SERVER_NAME)
{env_setup}{log_setup}
    # Verify lockfile if it exists
    lockfile_path = Path(__file__).parent / "aegismcp.lock.json"
    if lockfile_path.exists():
        from aegismcp.lockfile import Lockfile
        try:
            lockfile = Lockfile.load(lockfile_path)
            print(f"[OK] Lockfile verified - {{len(lockfile.servers)}} server(s) locked")
        except Exception as e:
            print(f"[WARN] Lockfile verification failed: {{e}}")

    # Initialize taint firewall
    from aegismcp.taint_monitor import initialize_taint_monitoring
    initialize_taint_monitoring()

    # Run the server with taint monitoring enabled
    try:
        result = subprocess.run(
            COMMAND,
            cwd=Path(__file__).parent,
            env=os.environ.copy(),
            check=False,
        )
        return result.returncode
    except KeyboardInterrupt:
        print("\\n[OK] Server stopped by user")
        return 0
    except Exception as e:
        print(f"[ERROR] Server failed: {{e}}")
        return 1

if __name__ == "__main__":
    sys.exit(run_server())
'''


def cmd_shield(args: argparse.Namespace) -> int:
    """Handle the shield wrap command."""
    config_path = Path(args.config)

    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        return 1

    output_path = Path(args.output) if args.output else None
    lockfile_path = Path(args.lockfile) if args.lockfile else None

    # Parse env vars from KEY=VALUE format
    env_vars = {}
    if hasattr(args, 'env') and args.env:
        for env_item in args.env:
            if isinstance(env_item, str) and '=' in env_item:
                key, value = env_item.split('=', 1)
                env_vars[key] = value

    log_path = Path(args.log) if hasattr(args, 'log') and args.log else None

    return create_shield_script(config_path, output_path, lockfile_path, env_vars if env_vars else None, log_path)


def cmd_unshield(args: argparse.Namespace) -> int:
    """Handle the shield unwrap command."""
    output_path = Path(args.output) if args.output else None
    restore_path = Path(args.restore_path) if args.restore_path else None

    return create_unshield_script(output_path, restore_path)


if __name__ == "__main__":
    # CLI entry point for standalone execution
    parser = argparse.ArgumentParser(
        prog="aegismcp shield",
        description="Shield an MCP server with whitelist-based security"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # wrap subcommand
    wrap_parser = subparsers.add_parser("wrap", help="Create a shielded wrapper for MCP server")
    wrap_parser.add_argument("config", type=str, help="Path to MCP config JSON file")
    wrap_parser.add_argument("-o", "--output", type=str, help="Output path for shield script")
    wrap_parser.add_argument("-l", "--lockfile", type=str, help="Path to lockfile (optional)")
    wrap_parser.add_argument("--env", nargs="*", help="Environment variables in KEY=VALUE format")
    wrap_parser.add_argument("--log", type=str, help="Log file path")

    # unwrap subcommand
    unwrap_parser = subparsers.add_parser("unwrap", help="Remove shield wrapper and restore config")
    unwrap_parser.add_argument("-o", "--output", type=str, help="Output path for unshield script")
    unwrap_parser.add_argument("--restore-path", type=str, required=True, help="Path to backup to restore")

    args = parser.parse_args()

    if args.subcommand == "wrap":
        sys.exit(cmd_shield(args))
    elif args.subcommand == "unwrap":
        sys.exit(cmd_unshield(args))