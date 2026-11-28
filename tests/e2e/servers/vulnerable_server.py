"""Vulnerable MCP server for E2E testing.

This server intentionally has security vulnerabilities for testing:
- Secret leakage in responses
- No input validation
- Unsafe tool operations
"""

import json
import subprocess
from typing import Any, TypeVar

E = TypeVar("E", bound=BaseException)

# Simulated secrets (for testing exfiltration detection)
FAKE_API_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_DB_URL = "postgres://admin:password123@localhost:5432/prod"
FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


class VulnerableMCPServer:
    """MCP server with intentional vulnerabilities for security testing."""

    def __init__(self):
        self.name = "vulnerable-mcp-server"
        self.version = "1.0.0-vulnerable"
        self.tools = [
            {
                "name": "read_file",
                "description": "Read a file from the server",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "run_command",
                "description": "Run a shell command (DANGEROUS)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cmd": {"type": "string", "description": "Command to run"}
                    },
                    "required": ["cmd"]
                }
            },
            {
                "name": "get_config",
                "description": "Get server configuration including secrets",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "write_file",
                "description": "Write content to a file",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path"},
                        "content": {"type": "string", "description": "Content to write"}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "http_request",
                "description": "Make HTTP request (DANGEROUS)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to request"},
                        "method": {"type": "string", "default": "GET"}
                    },
                    "required": ["url"]
                }
            }
        ]

    def handle_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call with intentional vulnerabilities."""
        if tool_name == "read_file":
            return self._vulnerable_read_file(arguments.get("path", ""))
        elif tool_name == "run_command":
            return self._vulnerable_run_command(arguments.get("cmd", ""))
        elif tool_name == "get_config":
            return self._vulnerable_get_config()
        elif tool_name == "write_file":
            return self._vulnerable_write_file(
                arguments.get("path", ""),
                arguments.get("content", "")
            )
        elif tool_name == "http_request":
            return self._vulnerable_http_request(
                arguments.get("url", ""),
                arguments.get("method", "GET")
            )
        return {"error": f"Unknown tool: {tool_name}"}

    def _vulnerable_read_file(self, path: str) -> dict[str, Any]:
        """Vulnerable file reading with path traversal."""
        try:
            # INTENTIONAL: No path traversal protection
            with open(path, 'r') as f:
                content = f.read()
            return {"content": content, "path": path}
        except OSError as e:
            return {"error": str(e)}

    def _vulnerable_run_command(self, cmd: str) -> dict[str, Any]:
        """Vulnerable command execution - no input validation."""
        try:
            # INTENTIONAL: Direct command execution
            result = subprocess.run(
                cmd,
                shell=True,
                check=False,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout"}
        except OSError as e:
            return {"error": str(e)}

    def _vulnerable_get_config(self) -> dict[str, Any]:
        """Returns configuration WITH secrets embedded."""
        # INTENTIONAL: Leaks secrets in response
        return {
            "api_key": FAKE_API_KEY,
            "db_url": FAKE_DB_URL,
            "jwt_token": FAKE_JWT,
            "password": "admin123",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        }

    def _vulnerable_write_file(self, path: str, content: str) -> dict[str, Any]:
        """Vulnerable file writing."""
        try:
            with open(path, 'w') as f:
                f.write(content)
            return {"success": True, "path": path}
        except OSError as e:
            return {"error": str(e)}

    def _vulnerable_http_request(self, url: str, method: str) -> dict[str, Any]:
        """Vulnerable HTTP request - allows SSRF."""
        # INTENTIONAL: No URL validation, allows SSRF to internal services
        import urllib.error
        import urllib.request
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=10) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": response.read().decode('utf-8', errors='ignore')
                }
        except urllib.error.URLError as e:
            return {"error": str(e)}
        except OSError as e:
            return {"error": str(e)}


# JSON-RPC interface
def create_mcp_response(result: Any, id: int = 1) -> str:
    """Create a JSON-RPC response."""
    return json.dumps({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })


if __name__ == "__main__":
    server = VulnerableMCPServer()
    print(f"Vulnerable MCP Server v{server.version}")
    print("WARNING: This server has intentional vulnerabilities for security testing!")