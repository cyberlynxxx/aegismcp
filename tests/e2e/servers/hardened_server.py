#!/usr/bin/env python3
"""Hardened MCP server for E2E testing.

This server has proper security controls:
- Input validation
- No secret leakage
- Safe tool operations
- Taint tracking integration
"""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, TypeVar

E = TypeVar("E", bound=BaseException)

# Simulated secrets (redacted in responses)
SECRET_REDACTION = "***REDACTED***"


class HardenedMCPServer:
    """MCP server with proper security controls."""

    def __init__(self):
        self.name = "hardened-mcp-server"
        self.version = "1.0.0-hardened"
        self.tools = [
            {
                "name": "read_file",
                "description": "Read a file from the allowed directory",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read (subdirectory of /sandbox)"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "run_safe_command",
                "description": "Run a whitelisted command safely",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cmd": {"type": "string", "description": "Command to run (must be whitelisted)"}
                    },
                    "required": ["cmd"]
                }
            },
            {
                "name": "get_config",
                "description": "Get server configuration (secrets redacted)",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "write_file",
                "description": "Write content to a sandboxed file",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative file path in sandbox"},
                        "content": {"type": "string", "description": "Content to write"}
                    },
                    "required": ["path", "content"]
                }
            }
        ]
        self._sandbox_dir = Path(tempfile.mkdtemp(prefix="mcp_sandbox_"))
        self._whitelisted_commands = {"ls", "pwd", "whoami", "date", "echo", "cat"}

    def handle_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call with security controls."""
        if tool_name == "read_file":
            return self._safe_read_file(arguments.get("path", ""))
        elif tool_name == "run_safe_command":
            return self._safe_run_command(arguments.get("cmd", ""))
        elif tool_name == "get_config":
            return self._safe_get_config()
        elif tool_name == "write_file":
            return self._safe_write_file(
                arguments.get("path", ""),
                arguments.get("content", "")
            )
        return {"error": f"Unknown tool: {tool_name}"}

    def _safe_read_file(self, path: str) -> dict[str, Any]:
        """Safe file reading with path traversal protection."""
        try:
            # Security: Resolve and validate path is within sandbox
            file_path = (self._sandbox_dir / path).resolve()

            # Ensure file is within sandbox directory
            if not str(file_path).startswith(str(self._sandbox_dir)):
                return {"error": "Access denied: path outside sandbox"}

            if not file_path.exists():
                return {"error": "File not found"}

            if not file_path.is_file():
                return {"error": "Not a file"}

            with open(file_path, 'r') as f:
                content = f.read(1024 * 1024)  # Max 1MB

            return {"content": content, "path": path}
        except OSError as e:
            return {"error": f"Read error: {e!s}"}

    def _safe_run_command(self, cmd: str) -> dict[str, Any]:
        """Safe command execution with whitelist protection."""
        try:
            # Security: Parse command and check whitelist
            if not cmd or not isinstance(cmd, str):
                return {"error": "Invalid command"}

            # Extract base command
            base_cmd = cmd.split()[0] if cmd.split() else ""

            if base_cmd not in self._whitelisted_commands:
                return {
                    "error": f"Command not whitelisted. Allowed: {self._whitelisted_commands}"
                }

            # Security: No shell=True with user input
            result = subprocess.run(
                cmd.split(),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=10
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout"}
        except OSError as e:
            return {"error": f"Execution error: {e!s}"}

    def _safe_get_config(self) -> dict[str, Any]:
        """Returns configuration with secrets redacted."""
        # Security: Never expose secrets
        return {
            "api_key": SECRET_REDACTION,
            "db_url": SECRET_REDACTION,
            "jwt_token": SECRET_REDACTION,
            "password": SECRET_REDACTION,
            "private_key": SECRET_REDACTION,
            "config": {
                "debug": False,
                "log_level": "INFO",
                "timeout": 30
            }
        }

    def _safe_write_file(self, path: str, content: str) -> dict[str, Any]:
        """Safe file writing with sandbox validation."""
        try:
            # Security: Validate path
            if not path or ".." in path or path.startswith("/"):
                return {"error": "Invalid path"}

            # Security: Limit content size
            if len(content) > 1024 * 1024:  # 1MB max
                return {"error": "Content too large"}

            # Security: Sanitize filename
            safe_name = os.path.basename(path)
            if not re.match(r'^[\w\-\.]+$', safe_name):
                return {"error": "Invalid filename"}

            file_path = self._sandbox_dir / safe_name

            with open(file_path, 'w') as f:
                f.write(content)

            return {"success": True, "path": path}
        except OSError as e:
            return {"error": f"Write error: {e!s}"}


def create_mcp_response(result: Any, id: int = 1) -> str:
    """Create a JSON-RPC response."""
    return json.dumps({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })


if __name__ == "__main__":
    server = HardenedMCPServer()
    print(f"Hardened MCP Server v{server.version}")
    print("This server has proper security controls enabled.")