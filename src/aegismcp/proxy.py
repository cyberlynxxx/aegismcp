"""Runtime MCP Security Proxy/Firewall - intercepts and validates all MCP traffic."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
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

from .inspector import JSONRPCClient, MCPInspector, InspectorOptions
from .rules_core import (
    Finding,
    SECRET_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    RESPONSE_INJECTION_PATTERNS,
    RESPONSE_SECRET_PATTERNS,
    RESPONSE_INVISIBLE_UNICODE_PATTERNS,
)
from .normalizer import Normalizer, is_suspicious_ip
from .scoring import PromptInjectionScorer, ScoringMode, create_scorer_from_config
from .reporter import print_report, ReportOptions


@dataclass
class ProxyConfig:
    """Configuration for the MCP proxy."""
    # Server to proxy to
    command: Optional[list[str]] = None
    url: Optional[str] = None

    # Proxy binding
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080

    # Security settings
    fail_on: str = "HIGH"
    block_critical: bool = True
    block_high: bool = True
    block_medium: bool = False
    block_low: bool = False

    # Prompt injection scoring
    prompt_injection_mode: str = "balanced"  # "strict" or "balanced"
    response_scanning_enabled: bool = True

    # Anti-evasion normalizer
    normalizer_max_iterations: int = 5

    # Audit logging
    audit_log: Optional[Path] = None
    audit_format: str = "jsonl"  # jsonl or text

    # Rate limiting
    max_requests_per_second: int = 100
    max_request_size: int = 1024 * 1024  # 1MB

    # Connection
    timeout: float = 30.0
    max_concurrent: int = 50

    # Custom patterns (loaded from policy file)
    custom_prompt_injection_patterns: list[dict] = field(default_factory=list)


@dataclass
class AuditEntry:
    """Single audit log entry."""
    timestamp: str
    request_id: str
    method: str
    direction: str  # "request" or "response"
    client_ip: str
    allowed: bool
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps({
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "method": self.method,
            "direction": self.direction,
            "client_ip": self.client_ip,
            "allowed": self.allowed,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "message": f.message,
                    "location": f.location,
                }
                for f in self.findings
            ],
            "error": self.error,
        }, ensure_ascii=False)

    def to_text(self) -> str:
        status = "ALLOW" if self.allowed else "BLOCK"
        findings_str = ""
        if self.findings:
            findings_str = f" | Findings: {len(self.findings)} ({', '.join(f.severity for f in self.findings)})"
        return f"[{self.timestamp}] {status} | {self.method} | {self.client_ip} | {self.request_id}{findings_str}"


class RateLimiter:
    """Simple token bucket rate limiter."""

    def __init__(self, rate_per_second: int):
        self.rate = rate_per_second
        self.tokens = rate_per_second
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        """Try to acquire a token. Returns True if allowed."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


class MCPProxy:
    """Runtime MCP Security Proxy with real-time threat detection."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.max_requests_per_second)
        self.inspector: Optional[MCPInspector] = None
        self.server_info = None
        self.request_count = 0
        self.blocked_count = 0
        self.logger = logging.getLogger("aegismcp.proxy")

        # Initialize prompt injection scorer
        mode = ScoringMode.STRICT if config.prompt_injection_mode == "strict" else ScoringMode.BALANCED
        self.scorer = PromptInjectionScorer(mode=mode)
        if config.custom_prompt_injection_patterns:
            self.scorer = create_scorer_from_config({
                "prompt_injection_mode": config.prompt_injection_mode,
                "custom_prompt_injection_patterns": config.custom_prompt_injection_patterns,
            })

        # Initialize normalizer
        self.normalizer = Normalizer()

    async def start(self):
        """Start the proxy - connect to upstream server and begin listening."""
        # Connect to upstream MCP server
        await self._connect_upstream()

        # Start HTTP server
        from aiohttp import web
        app = web.Application()
        app.router.add_post("/mcp", self._handle_request)
        app.router.add_get("/health", self._health_check)
        app.router.add_get("/stats", self._stats)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.bind_host, self.config.bind_port)
        await site.start()

        print(f"[OK] MCP Proxy started on http://{self.config.bind_host}:{self.config.bind_port}")
        print(f"     Upstream: {'stdio' if self.config.command else self.config.url}")
        print(f"     Security: fail_on={self.config.fail_on}")
        print(f"     Audit log: {self.config.audit_log or 'disabled'}")

        # Keep running
        try:
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            print("\n[OK] Shutting down proxy...")
        finally:
            await runner.cleanup()
            if self.inspector:
                await self.inspector.close()

    async def _connect_upstream(self):
        """Connect to the upstream MCP server."""
        options = InspectorOptions(
            timeout=self.config.timeout,
            command=self.config.command,
            url=self.config.url,
        )

        inspector = MCPInspector(options)

        if self.config.command:
            await inspector.connect_stdio(self.config.command)
        elif self.config.url:
            await inspector.connect_http(self.config.url)
        else:
            raise RuntimeError("Either --command or --url required")

        # Run initial security scan on tools
        findings = inspector.inspect_tools()
        if findings:
            print(f"[WARN] Upstream server has {len(findings)} security findings:")
            for f in findings:
                print(f"  [{f.severity}] {f.rule_id}: {f.title}")

        self.inspector = inspector
        self.server_info = inspector.server_info

    async def _handle_request(self, request):
        """Handle incoming MCP JSON-RPC request."""
        from aiohttp import web

        # Rate limiting
        if not await self.rate_limiter.acquire():
            return web.Response(status=429, text="Rate limit exceeded")

        # Size limit
        try:
            body = await request.read()
            if len(body) > self.config.max_request_size:
                return web.Response(status=413, text="Request too large")
        except Exception:
            return web.Response(status=400, text="Invalid request body")

        # Parse JSON-RPC
        try:
            rpc_request = json.loads(body.decode())
        except json.JSONDecodeError:
            return web.Response(status=400, text="Invalid JSON")

        request_id = rpc_request.get("id", str(uuid.uuid4()))
        method = rpc_request.get("method", "unknown")
        client_ip = request.remote or "unknown"

        # Validate JSON-RPC structure
        if rpc_request.get("jsonrpc") != "2.0":
            return web.Response(status=400, text="Invalid JSON-RPC version")

        # Security scan on request
        allowed, findings = await self._scan_request(rpc_request)

        # Audit logging
        await self._audit_request(AuditEntry(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            request_id=str(request_id),
            method=method,
            direction="request",
            client_ip=client_ip,
            allowed=allowed,
            findings=findings,
        ))

        if not allowed:
            self.blocked_count += 1
            blocked_response = self._create_blocked_response(request_id, findings)
            return web.Response(
                status=403,
                content_type="application/json",
                text=json.dumps(blocked_response)
            )

        # Forward to upstream
        try:
            response = await self._forward_to_upstream(rpc_request)
            self.request_count += 1

            # Scan response for AMCP309 threats
            resp_findings = self._scan_response(method, response)

            if resp_findings:
                await self._audit_request(AuditEntry(
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    request_id=str(request_id),
                    method=method,
                    direction="response",
                    client_ip=client_ip,
                    allowed=self._should_block(resp_findings),
                    findings=resp_findings,
                ))

                # Check if response should be blocked
                if self._should_block(resp_findings):
                    self.blocked_count += 1
                    blocked_response = self._create_blocked_response(request_id, resp_findings)
                    return web.Response(
                        status=403,
                        content_type="application/json",
                        text=json.dumps(blocked_response)
                    )

            return web.Response(
                content_type="application/json",
                text=json.dumps(response)
            )
        except Exception as e:
            self.logger.error(f"Upstream error: {e}")
            await self._audit_request(AuditEntry(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                request_id=str(request_id),
                method=method,
                direction="request",
                client_ip=client_ip,
                allowed=False,
                error=str(e),
            ))
            return web.Response(
                status=502,
                content_type="application/json",
                text=json.dumps({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": "Upstream error"}
                })
            )

    async def _scan_request(self, request: dict) -> tuple[bool, list[Finding]]:
        """Scan an incoming request for threats."""
        if not self.inspector or not self.server_info:
            return True, []

        findings = []
        method = request.get("method", "")
        params = request.get("params", {})

        # Normalize params first (anti-evasion)
        normalized_params = self.normalizer.normalize_dict(params, self.config.normalizer_max_iterations)

        # Scan tool calls for injection
        if method == "tools/call":
            tool_name = normalized_params.get("name", "")
            arguments = normalized_params.get("arguments", {})

            # Find the tool definition
            tool = next((t for t in self.server_info.tools if t.name == tool_name), None)
            if tool:
                # Check arguments against schema
                arg_findings = self._validate_tool_arguments(tool, arguments)
                findings.extend(arg_findings)

                # Check for prompt injection in string arguments using weighted scorer
                for key, value in arguments.items():
                    if isinstance(value, str):
                        inj_findings = self._check_prompt_injection(value, f"tools.{tool_name}.arguments.{key}")
                        findings.extend(inj_findings)

        # Scan resource access
        elif method in ("resources/read", "resources/list"):
            uri = normalized_params.get("uri", "")
            if uri and self._is_suspicious_uri(uri):
                findings.append(Finding(
                    rule_id="AMCP301",
                    severity="HIGH",
                    title="Suspicious Resource URI",
                    message=f"Resource URI contains potentially dangerous pattern: {uri}",
                    location=f"resources.{method}",
                    remediation="Validate resource URIs against allowlist; block file://, internal IPs"
                ))

            # Enhanced SSRF check using normalizer
            if uri and is_suspicious_ip(uri):
                findings.append(Finding(
                    rule_id="AMCP301",
                    severity="HIGH",
                    title="SSRF Attempt - Suspicious IP in URI",
                    message=f"Resource URI contains suspicious IP address: {uri}",
                    location=f"resources.{method}",
                    remediation="Block access to internal/private IP addresses"
                ))

        # Scan prompt arguments
        elif method in ("prompts/get", "prompts/list"):
            prompt_name = normalized_params.get("name", "")
            arguments = normalized_params.get("arguments", {})
            for key, value in arguments.items():
                if isinstance(value, str):
                    inj_findings = self._check_prompt_injection(value, f"prompts.{prompt_name}.arguments.{key}")
                    findings.extend(inj_findings)

        # Determine if request should be blocked
        blocked = self._should_block(findings)
        return not blocked, findings

    def _validate_tool_arguments(self, tool: Any, arguments: dict) -> list[Finding]:
        """Validate tool arguments against input schema."""
        from .rules_core import Finding
        findings = []
        schema = tool.input_schema
        if not isinstance(schema, dict):
            return findings

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Check required fields
        for req in required:
            if req not in arguments:
                findings.append(Finding(
                    rule_id="AMCP302",
                    severity="MEDIUM",
                    title="Missing Required Tool Argument",
                    message=f"Tool '{tool.name}' missing required argument: {req}",
                    location=f"tools.{tool.name}.arguments.{req}",
                    remediation=f"Provide required argument '{req}'"
                ))

        # Check argument types and constraints
        for arg_name, arg_value in arguments.items():
            prop_schema = properties.get(arg_name, {})
            if not isinstance(prop_schema, dict):
                continue

            expected_type = prop_schema.get("type")
            if expected_type == "string" and not isinstance(arg_value, str):
                findings.append(Finding(
                    rule_id="AMCP303",
                    severity="MEDIUM",
                    title="Tool Argument Type Mismatch",
                    message=f"Argument '{arg_name}' expected string, got {type(arg_value).__name__}",
                    location=f"tools.{tool.name}.arguments.{arg_name}",
                    remediation=f"Ensure '{arg_name}' is a string"
                ))
            elif expected_type == "number" and not isinstance(arg_value, (int, float)):
                findings.append(Finding(
                    rule_id="AMCP303",
                    severity="MEDIUM",
                    title="Tool Argument Type Mismatch",
                    message=f"Argument '{arg_name}' expected number, got {type(arg_value).__name__}",
                    location=f"tools.{tool.name}.arguments.{arg_name}",
                    remediation=f"Ensure '{arg_name}' is a number"
                ))
            elif expected_type == "boolean" and not isinstance(arg_value, bool):
                findings.append(Finding(
                    rule_id="AMCP303",
                    severity="MEDIUM",
                    title="Tool Argument Type Mismatch",
                    message=f"Argument '{arg_name}' expected boolean, got {type(arg_value).__name__}",
                    location=f"tools.{tool.name}.arguments.{arg_name}",
                    remediation=f"Ensure '{arg_name}' is a boolean"
                ))

            # Check enum constraints
            if "enum" in prop_schema:
                if arg_value not in prop_schema["enum"]:
                    findings.append(Finding(
                        rule_id="AMCP304",
                        severity="HIGH",
                        title="Tool Argument Enum Violation",
                        message=f"Argument '{arg_name}' value not in allowed enum: {prop_schema['enum']}",
                        location=f"tools.{tool.name}.arguments.{arg_name}",
                        remediation=f"Use one of allowed values: {prop_schema['enum']}"
                    ))

            # Check pattern constraints
            if "pattern" in prop_schema and isinstance(arg_value, str):
                import re
                if not re.match(prop_schema["pattern"], arg_value):
                    findings.append(Finding(
                        rule_id="AMCP305",
                        severity="HIGH",
                        title="Tool Argument Pattern Violation",
                        message=f"Argument '{arg_name}' does not match required pattern",
                        location=f"tools.{tool.name}.arguments.{arg_name}",
                        remediation=f"Ensure '{arg_name}' matches pattern: {prop_schema['pattern']}"
                    ))

            # Check maxLength
            if "maxLength" in prop_schema and isinstance(arg_value, str):
                if len(arg_value) > prop_schema["maxLength"]:
                    findings.append(Finding(
                        rule_id="AMCP306",
                        severity="MEDIUM",
                        title="Tool Argument Length Exceeded",
                        message=f"Argument '{arg_name}' exceeds maxLength of {prop_schema['maxLength']}",
                        location=f"tools.{tool.name}.arguments.{arg_name}",
                        remediation=f"Shorten '{arg_name}' to {prop_schema['maxLength']} characters or less"
                    ))

        return findings

    def _check_prompt_injection(self, text: str, location: str) -> list[Finding]:
        """Check text for prompt injection patterns using weighted scorer."""
        import re
        from .rules_core import Finding
        findings = []

        # Use weighted scorer
        result = self.scorer.score(text)

        for pattern in result.triggered_patterns:
            # Map risk level to severity
            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
            }
            severity = severity_map.get(pattern.category.upper(), "MEDIUM")
            # Override for high-weight patterns
            if pattern.weight >= 0.85:
                severity = "CRITICAL"
            elif pattern.weight >= 0.7:
                severity = "HIGH"
            elif pattern.weight >= 0.4:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            findings.append(Finding(
                rule_id="AMCP005",
                severity=severity,
                title=f"Prompt Injection Detected ({pattern.name})",
                message=f"Argument at {location} matches pattern: {pattern.name} (weight: {pattern.weight})",
                location=location,
                remediation="Sanitize input; reject requests with prompt injection patterns"
            ))

        # Check for dangerous command patterns (command injection) - keep existing
        dangerous_cmd_patterns = [
            (r"rm\s+-rf\s+/", "Recursive Root Deletion"),
            (r"rm\s+-rf\s+~", "Recursive Home Deletion"),
            (r"dd\s+if=", "Disk Dump Command"),
            (r"mkfs", "Filesystem Format"),
            (r">\s*/dev/", "Device Overwrite"),
            (r"chmod\s+777", "World-Writable Permissions"),
            (r"chown\s+root", "Root Ownership Change"),
            (r":\(\)\s*\{.*\}", "Fork Bomb"),
            (r"curl\s+.*\|\s*(bash|sh)", "Pipe to Shell"),
            (r"wget\s+.*\|\s*(bash|sh)", "Pipe to Shell"),
        ]

        for pattern, name in dangerous_cmd_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="AMCP301",
                    severity="CRITICAL",
                    title=f"Dangerous Command Pattern Detected ({name})",
                    message=f"Argument at {location} contains dangerous command pattern: {name}",
                    location=location,
                    remediation="Reject requests with dangerous command patterns; use allowlists for commands"
                ))

        # Check for invisible Unicode using normalizer's patterns
        invisible_patterns = [
            ("Zero-Width Characters", re.compile(r"[​-‏﻿]")),
            ("Bidi Override Characters", re.compile(r"[‪-‮⁦-⁩]")),
            ("Invisible Separators", re.compile(r"[⁠-⁤]")),
            ("Format Characters", re.compile(r"[᠎]")),
        ]
        for pattern_name, pattern in invisible_patterns:
            if pattern.search(text):
                findings.append(Finding(
                    rule_id="AMCP007",
                    severity="CRITICAL",
                    title=f"Invisible Unicode in Runtime Argument ({pattern_name})",
                    message=f"Argument at {location} contains invisible Unicode character(s): {pattern_name}",
                    location=location,
                    remediation="Strip zero-width and bidi characters from all inputs"
                ))

        return findings

    def _is_suspicious_uri(self, uri: str) -> bool:
        """Check if a resource URI is suspicious."""
        suspicious_patterns = [
            "file://",
            "http://localhost",
            "http://127.0.0.1",
            "http://10.",
            "http://172.16.",
            "http://172.17.",
            "http://172.18.",
            "http://172.19.",
            "http://172.20.",
            "http://172.21.",
            "http://172.22.",
            "http://172.23.",
            "http://172.24.",
            "http://172.25.",
            "http://172.26.",
            "http://172.27.",
            "http://172.28.",
            "http://172.29.",
            "http://172.30.",
            "http://172.31.",
            "http://192.168.",
            "http://169.254.",
        ]
        uri_lower = uri.lower()
        return any(pattern in uri_lower for pattern in suspicious_patterns)

    def _scan_response(self, method: str, response: dict) -> list[Finding]:
        """Scan response for AMCP309 threats: indirect prompt injection, secret leakage, invisible Unicode."""
        from .rules_core import (
            Finding, RESPONSE_INJECTION_PATTERNS,
            RESPONSE_SECRET_PATTERNS, RESPONSE_INVISIBLE_UNICODE_PATTERNS
        )

        if not self.config.response_scanning_enabled:
            return []

        if not self.inspector or not self.server_info:
            return []

        findings = []
        result = response.get("result", {})

        # Existing tool list change detection (AMCP307, AMCP308)
        if method == "tools/list" and "tools" in result:
            current_tools = {t["name"]: t for t in result["tools"]}
            known_tools = {t.name: t for t in self.server_info.tools}

            # Check for new tools (possible rug-pull)
            for name, tool in current_tools.items():
                if name not in known_tools:
                    findings.append(Finding(
                        rule_id="AMCP307",
                        severity="HIGH",
                        title="New Tool Discovered at Runtime",
                        message=f"Tool '{name}' not in lockfile/initial scan - possible rug-pull",
                        location=f"tools.{name}",
                        remediation="Verify this tool is expected; update lockfile if legitimate"
                    ))

            # Check for modified tools
            for name, tool in current_tools.items():
                if name in known_tools:
                    known = known_tools[name]
                    if tool.get("description") != known.description or tool.get("inputSchema") != known.input_schema:
                        findings.append(Finding(
                            rule_id="AMCP308",
                            severity="CRITICAL",
                            title="Tool Definition Changed at Runtime",
                            message=f"Tool '{name}' definition differs from lockfile/initial scan",
                            location=f"tools.{name}",
                            remediation="Investigate immediately - possible tool poisoning/rug-pull"
                        ))

        # AMCP309: Response inspection for tools/call results, resources/read, prompts/get
        if method in ("tools/call", "resources/read", "prompts/get"):
            # Extract all string content from response
            strings = self.normalizer.extract_all_strings(result)

            for text in strings:
                # 1. Check for indirect prompt injection in responses
                for pattern_name, pattern in RESPONSE_INJECTION_PATTERNS:
                    if pattern.search(text):
                        findings.append(Finding(
                            rule_id="AMCP309",
                            severity="CRITICAL",
                            title=f"Indirect Prompt Injection in Response ({pattern_name})",
                            message=f"Server response contains indirect prompt injection pattern: {pattern_name}",
                            location=f"response.{method}",
                            remediation="Block or sanitize responses containing indirect injection directives"
                        ))

                # 2. Check for secret leakage in responses
                for pattern_name, pattern in RESPONSE_SECRET_PATTERNS:
                    if pattern.search(text):
                        findings.append(Finding(
                            rule_id="AMCP309",
                            severity="CRITICAL",
                            title=f"Secret Leakage in Response ({pattern_name})",
                            message=f"Server response contains leaked secret: {pattern_name}",
                            location=f"response.{method}",
                            remediation="Ensure server does not return secrets; rotate compromised credentials"
                        ))

                # 3. Check for invisible Unicode in responses
                for pattern_name, pattern in RESPONSE_INVISIBLE_UNICODE_PATTERNS:
                    if pattern.search(text):
                        findings.append(Finding(
                            rule_id="AMCP309",
                            severity="HIGH",
                            title=f"Invisible Unicode in Response ({pattern_name})",
                            message=f"Server response contains invisible Unicode characters: {pattern_name}",
                            location=f"response.{method}",
                            remediation="Strip zero-width and bidi characters from server responses"
                        ))

        return findings

    def _should_block(self, findings: list[Finding]) -> bool:
        """Determine if request should be blocked based on findings and config."""
        for f in findings:
            if f.severity == "CRITICAL" and self.config.block_critical:
                return True
            if f.severity == "HIGH" and self.config.block_high:
                return True
            if f.severity == "MEDIUM" and self.config.block_medium:
                return True
            if f.severity == "LOW" and self.config.block_low:
                return True
        return False

    def _create_blocked_response(self, request_id: Any, findings: list[Finding]) -> dict:
        """Create a JSON-RPC 2.0 error response for blocked requests (code -32001)."""
        finding_details = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "message": f.message,
                "location": f.location,
            }
            for f in findings
        ]
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32001,
                "message": "Request blocked by security policy",
                "data": {
                    "findings": finding_details,
                    "block_reason": "security_policy_violation"
                }
            }
        }

    async def _audit_request(self, entry: AuditEntry):
        """Write audit log entry."""
        if not self.config.audit_log:
            return

        try:
            if self.config.audit_format == "jsonl":
                line = entry.to_json()
            else:
                line = entry.to_text()

            # Append to file
            with self.config.audit_log.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            self.logger.error(f"Audit log write failed: {e}")

    async def _health_check(self, request):
        """Health check endpoint."""
        from aiohttp import web
        return web.json_response({
            "status": "healthy",
            "upstream_connected": self.inspector is not None,
            "server": self.server_info.name if self.server_info else None,
            "requests_processed": self.request_count,
            "requests_blocked": self.blocked_count,
        })

    async def _stats(self, request):
        """Statistics endpoint."""
        from aiohttp import web
        return web.json_response({
            "requests_processed": self.request_count,
            "requests_blocked": self.blocked_count,
            "block_rate": self.blocked_count / max(1, self.request_count),
            "upstream_tools": len(self.server_info.tools) if self.server_info else 0,
        })


async def run_proxy(config: ProxyConfig):
    """Run the MCP proxy."""
    proxy = MCPProxy(config)
    await proxy.start()


def main():
    """CLI entry point for proxy command."""
    import argparse

    parser = argparse.ArgumentParser(prog="aegismcp proxy", description="Runtime MCP Security Proxy/Firewall")
    parser.add_argument("--command", type=str, help="Command to start MCP server (e.g., 'python server.py')")
    parser.add_argument("--url", type=str, help="HTTP/SSE URL of MCP server")
    parser.add_argument("--bind", type=str, default="127.0.0.1:8080", help="Bind address (host:port)")
    parser.add_argument("--timeout", type=float, default=30.0, help="Upstream connection timeout")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH")
    parser.add_argument("--audit-log", type=str, help="Path to audit log file")
    parser.add_argument("--audit-format", choices=["jsonl", "text"], default="jsonl")
    parser.add_argument("--rate-limit", type=int, default=100, help="Max requests per second")
    parser.add_argument("--max-size", type=int, default=1048576, help="Max request size in bytes")
    parser.add_argument("--no-block-critical", action="store_true", help="Don't block CRITICAL findings")
    parser.add_argument("--no-block-high", action="store_true", help="Don't block HIGH findings")
    parser.add_argument("--block-medium", action="store_true", help="Block MEDIUM findings")
    parser.add_argument("--block-low", action="store_true", help="Block LOW findings")

    args = parser.parse_args()

    if not args.command and not args.url:
        parser.error("Either --command or --url is required")

    host, port_str = args.bind.split(":", 1)
    port = int(port_str)

    if args.command:
        command = args.command.split()
        url = None
    else:
        command = None
        url = args.url

    config = ProxyConfig(
        command=command,
        url=url,
        bind_host=host,
        bind_port=port,
        timeout=args.timeout,
        fail_on=args.fail_on,
        audit_log=Path(args.audit_log) if args.audit_log else None,
        audit_format=args.audit_format,
        max_requests_per_second=args.rate_limit,
        max_request_size=args.max_size,
        block_critical=not args.no_block_critical,
        block_high=not args.no_block_high,
        block_medium=args.block_medium,
        block_low=args.block_low,
    )

    try:
        asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()