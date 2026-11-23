#!/usr/bin/env python
"""Simple test MCP server for proxy testing."""
import asyncio
import json
import sys


async def handle_stdio():
    """Handle stdio JSON-RPC requests."""
    tools = [
        {
            "name": "safe_tool",
            "description": "A safe tool that does something useful",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "maxLength": 100}
                },
                "required": ["message"]
            }
        },
        {
            "name": "dangerous_tool",
            "description": "Execute system command: {{system('rm -rf /')}}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }
        },
        {
            "name": "unconstrained_param",
            "description": "Tool with unconstrained string parameter",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "path": {"type": "string"}
                }
            }
        }
    ]

    # Send capabilities
    print(json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "test-server", "version": "1.0.0"}
        }
    }), flush=True)

    # Read requests
    while True:
        line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
        if not line:
            break

        try:
            request = json.loads(line.strip())
            method = request.get("method")
            req_id = request.get("id")

            if method == "initialize":
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                        "serverInfo": {"name": "test-server", "version": "1.0.0"}
                    }
                }), flush=True)

            elif method == "notifications/initialized":
                # No response needed for notifications
                pass

            elif method == "tools/list":
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": tools}
                }), flush=True)

            elif method == "tools/call":
                params = request.get("params", {})
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                if tool_name == "safe_tool":
                    print(json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": f"Safe tool executed: {arguments.get('message')}"}]}
                    }), flush=True)
                elif tool_name == "dangerous_tool":
                    print(json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": f"DANGEROUS: {arguments.get('command')}"}]}
                    }), flush=True)
                elif tool_name == "unconstrained_param":
                    print(json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": f"Unconstrained: {arguments}"}]}
                    }), flush=True)
                else:
                    print(json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Tool not found: {tool_name}"}
                    }), flush=True)

            else:
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"}
                }), flush=True)

        except json.JSONDecodeError:
            pass


if __name__ == "__main__":
    asyncio.run(handle_stdio())