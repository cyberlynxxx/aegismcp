"""Proxy / runtime scanning rules (AMCP301-309)."""
from __future__ import annotations

import ipaddress
from typing import Any

from ...rules_core import Finding
from ..registry import Rule

DANGEROUS_BINARIES = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}

SENSITIVE_ENV_KEYS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "MYSQL_PASSWORD",
    "REDIS_PASSWORD",
    "MONGODB_URI",
    "SECRET_KEY",
    "JWT_SECRET",
    "API_KEY",
    "PRIVATE_KEY",
}


def check_proxy_command_injection(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP301: Proxy command injection via subprocess."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            command = str(cfg.get("command", ""))
            args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
            full_cmd = " ".join([command] + args)
            if any(bin_name in full_cmd for bin_name in DANGEROUS_BINARIES):
                findings.append(Finding(
                    rule_id="AMCP301",
                    severity="CRITICAL",
                    title="Proxy Command Injection Risk",
                    message=f"Server '{name}' may allow shell command injection via proxy.",
                    location=loc,
                    remediation="Use allowlisted commands and avoid shell=True in subprocess calls.",
                ))
    return findings


def check_proxy_ssrf(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP302: SSRF via proxy using ipaddress module."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            for k, v in env.items():
                val = str(v).strip()
                if val.startswith(("http://", "https://")):
                    try:
                        # Extract host from URL
                        from urllib.parse import urlparse
                        parsed = urlparse(val)
                        host = parsed.hostname or ""
                        if host:
                            ip = ipaddress.ip_address(host)
                            if ip.is_private or ip.is_loopback or ip.is_link_local:
                                findings.append(Finding(
                                    rule_id="AMCP302",
                                    severity="HIGH",
                                    title="SSRF to Private/Loopback Address",
                                    message=f"Env '{k}' points to private IP {host} in server '{name}'.",
                                    location=f"{loc}.env.{k}",
                                    remediation="Use allowlist of public endpoints. Block private IP ranges.",
                                ))
                            elif ip.is_reserved or ip.is_multicast:
                                findings.append(Finding(
                                    rule_id="AMCP302",
                                    severity="MEDIUM",
                                    title="SSRF to Reserved/Multicast Address",
                                    message=f"Env '{k}' points to reserved IP {host} in server '{name}'.",
                                    location=f"{loc}.env.{k}",
                                    remediation="Validate target IPs against an allowlist.",
                                ))
                    except ValueError:
                        # Not an IP address, could be a hostname - check for suspicious patterns
                        host = val.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                            findings.append(Finding(
                                rule_id="AMCP302",
                                severity="HIGH",
                                title="SSRF to Localhost",
                                message=f"Env '{k}' points to localhost in server '{name}'.",
                                location=f"{loc}.env.{k}",
                                remediation="Block localhost/loopback in outbound requests.",
                            ))
    return findings


def check_proxy_sensitive_env_exposure(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP303: Sensitive environment variables exposed to proxy."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            for k in env:
                if k.upper() in SENSITIVE_ENV_KEYS:
                    findings.append(Finding(
                        rule_id="AMCP303",
                        severity="HIGH",
                        title="Sensitive Environment Variable Exposed",
                        message=f"Server '{name}' exposes sensitive env '{k}' to proxy.",
                        location=f"{loc}.env.{k}",
                        remediation="Use secret references or inject at runtime instead of config.",
                    ))
    return findings


def check_proxy_unrestricted_network(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP304: Unrestricted network egress in proxy."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            # Check for wildcard or overly broad network permissions
            env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            for k, v in env.items():
                val = str(v).strip().lower()
                if val in ("*", "0.0.0.0/0", "any", "all"):
                    findings.append(Finding(
                        rule_id="AMCP304",
                        severity="HIGH",
                        title="Unrestricted Network Egress",
                        message=f"Server '{name}' allows unrestricted outbound connections via '{k}'.",
                        location=f"{loc}.env.{k}",
                        remediation="Restrict egress to specific allowed domains/IPs.",
                    ))
    return findings


def check_proxy_tool_override(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP305: Tool override / shadowing in proxy."""
    findings = []
    tools = data.get("tools", [])
    if isinstance(tools, list):
        seen = {}
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name = str(tool.get("name", "unknown"))
            if t_name in seen:
                findings.append(Finding(
                    rule_id="AMCP305",
                    severity="HIGH",
                    title="Tool Name Collision in Proxy",
                    message=f"Tool '{t_name}' defined multiple times, later definition shadows earlier.",
                    location=f"{location}:tools.{t_name}",
                    remediation="Ensure unique tool names or use namespacing.",
                ))
            seen[t_name] = tool
    return findings


def check_proxy_jsonrpc_buffering(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP306: JSON-RPC message buffering issues in proxy."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            # Check for transport config that might indicate buffering issues
            transport = str(cfg.get("transport", "")).lower()
            if transport in ("stdio", "sse") and "buffer" not in str(cfg).lower():
                # This is a hint - actual buffering verification happens at runtime
                findings.append(Finding(
                    rule_id="AMCP306",
                    severity="MEDIUM",
                    title="Potential JSON-RPC Buffering Issue",
                    message=f"Server '{name}' uses {transport} transport without explicit buffering config.",
                    location=loc,
                    remediation="Verify JSON-RPC message framing handles partial reads/writes correctly.",
                ))
    return findings


def check_proxy_rate_limiting(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP307: Missing rate limiting on proxy."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            # Check for rate limit config
            has_rate_limit = any(
                k in str(cfg).lower()
                for k in ("rate_limit", "ratelimit", "throttle", "max_requests")
            )
            if not has_rate_limit:
                findings.append(Finding(
                    rule_id="AMCP307",
                    severity="MEDIUM",
                    title="Missing Rate Limiting on Proxy",
                    message=f"Server '{name}' has no rate limiting configured.",
                    location=loc,
                    remediation="Add rate limiting to prevent abuse and DoS.",
                ))
    return findings


def check_proxy_auth_bypass(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP308: Potential auth bypass in proxy."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            # Check for auth tokens in env that could be bypassed
            for k, v in env.items():
                val = str(v).strip()
                if val and any(kw in k.lower() for kw in ("token", "key", "secret", "auth", "bearer")) and ("bypass" in val.lower() or "skip" in val.lower() or "disable" in val.lower()):
                        findings.append(Finding(
                            rule_id="AMCP308",
                            severity="CRITICAL",
                            title="Potential Auth Bypass Configuration",
                            message=f"Server '{name}' env '{k}' contains auth bypass indicator.",
                            location=f"{loc}.env.{k}",
                            remediation="Remove auth bypass flags. Enforce authentication on all endpoints.",
                        ))
    return findings


def check_proxy_tls_verification(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP309: Disabled TLS verification in proxy."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            for k, v in env.items():
                val = str(v).strip().lower()
                if any(kw in k.lower() for kw in ("verify", "ssl", "tls", "cert")) and val in ("false", "0", "no", "disable", "skip"):
                        findings.append(Finding(
                            rule_id="AMCP309",
                            severity="HIGH",
                            title="TLS Verification Disabled",
                            message=f"Server '{name}' disables TLS verification via '{k}'.",
                            location=f"{loc}.env.{k}",
                            remediation="Enable TLS verification. Use proper certificates.",
                        ))
    return findings


PROXY_RULES = [
    Rule("AMCP301", "CRITICAL", "Proxy Command Injection Risk", "Detects command injection via proxy", "Use allowlisted commands.", check_proxy_command_injection),
    Rule("AMCP302", "HIGH", "SSRF to Private/Loopback Address", "Detects SSRF via ipaddress module", "Block private IPs.", check_proxy_ssrf),
    Rule("AMCP303", "HIGH", "Sensitive Environment Variable Exposed", "Detects sensitive env exposure", "Use secret references.", check_proxy_sensitive_env_exposure),
    Rule("AMCP304", "HIGH", "Unrestricted Network Egress", "Detects unrestricted outbound", "Restrict egress.", check_proxy_unrestricted_network),
    Rule("AMCP305", "HIGH", "Tool Name Collision in Proxy", "Detects tool shadowing", "Use unique names.", check_proxy_tool_override),
    Rule("AMCP306", "MEDIUM", "Potential JSON-RPC Buffering Issue", "Detects potential buffering issues", "Verify framing.", check_proxy_jsonrpc_buffering),
    Rule("AMCP307", "MEDIUM", "Missing Rate Limiting on Proxy", "Detects missing rate limits", "Add rate limiting.", check_proxy_rate_limiting),
    Rule("AMCP308", "CRITICAL", "Potential Auth Bypass Configuration", "Detects auth bypass config", "Enforce auth.", check_proxy_auth_bypass),
    Rule("AMCP309", "HIGH", "TLS Verification Disabled", "Detects disabled TLS verify", "Enable TLS.", check_proxy_tls_verification),
]