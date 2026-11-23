#!/usr/bin/env python
"""Simple MCP server for testing inspector."""
import asyncio
import json
import sys

tools = [
    {
        "name": "safe_tool",
        "description": "A safe tool that does something useful",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string", "maxLength": 100}}, "required": ["message"]}
    },
    {
        "name": "dangerous_tool",
        "description": "Execute system command: {{\"system(\\\"rm -rf /\\\")\"}}",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}
    },
    {
        "name": "unconstrained_param",
        "description": "Tool with unconstrained string parameter",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "path": {"type": "string"}}}
    }
]

async def main():
    # Send initial capabilities broadcast
    init_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "mock-server", "version": "1.0.0"}
        }
    }
    print(json.dumps(init_msg), flush=True)

    while True:
        line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        try:
            req = json.loads(line.strip())
            method = req.get("method")
            rid = req.get("id")

            if method == "initialize":
                result_msg = {
                    "jsonrpc": "2.0", "id": rid,
                    "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "mock-server", "version": "1.0.0"}}
                }
                print(json.dumps(result_msg), flush=True)
            elif method == "notifications/initialized":
                pass
            elif method == "tools/list":
                tools_msg = {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}}
                print(json.dumps(tools_msg), flush=True)
            elif method == "tools/call":
                params = req.get("params", {})
                name = params.get("name")
                args = params.get("arguments", {})
                if name == "safe_tool":
                    msg = args.get("message", "")
                    resp = {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "Safe tool executed: " + msg}]}}
                    print(json.dumps(resp), flush=True)
                elif name == "dangerous_tool":
                    cmd = args.get("command", "")
                    resp = {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "DANGEROUS: " + cmd}]}}
                    print(json.dumps(resp), flush=True)
                elif name == "unconstrained_param":
                    resp = {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "Unconstrained: " + str(args)}]}}
                    print(json.dumps(resp), flush=True)
                else:
                    err = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Tool not found: " + str(name)}}
                    print(json.dumps(err), flush=True)
            else:
                err = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
                print(json.dumps(err), flush=True)
        except:
            pass

asyncio.run(main())