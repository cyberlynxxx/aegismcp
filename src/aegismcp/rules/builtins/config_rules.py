"""Config file scanning rules (AMCP001-008)."""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from ...rules_core import Finding
from ..registry import Rule

DANGEROUS_COMMANDS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}

SECRET_PATTERNS = [
    ("OpenAI / Anthropic API Key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Generic Bearer/Secret", re.compile(r"(?i)(?:secret|token|password|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}")),
]

PROMPT_INJECTION_PATTERNS = [
    ("Instruction Override", re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions")),
    ("Hidden Priority Tag", re.compile(r"(?i)<\s*(important|system|instructions)\s*>")),
    ("Stealth Exfiltration", re.compile(r"(?i)(do\s+not\s+(tell|inform|mention)\s+(the\s+)?user|silently\s+send)")),
    ("Sensitive File Read Trigger", re.compile(r"(?i)(read|cat|dump|send)\s+.*(\.ssh|\.env|id_rsa|aws/credentials)")),
    ("Remote Execution / Exfil", re.compile(r"(?i)\b(curl|wget|nc|powershell)\b.*https?://")),
    ("Template Injection", re.compile(r"\{\{.*\}\}|\$\{.*\}")),
]

def _is_env_placeholder(value: str) -> bool:
    v = value.strip()
    return (v.startswith("${") and v.endswith("}") and " " not in v) or v.startswith("$") or "YOUR_" in v.upper()

def _is_unicode_obfuscation(text: str) -> bool:
    """Detect Unicode homoglyphs and full-width characters used for evasion."""
    for ch in text:
        code = ord(ch)
        # Full-width forms (UFF01-UFF5E) often used to bypass ASCII regex
        if 0xFF01 <= code <= 0xFF5E:
            return True
        # Mathematical Alphanumeric Symbols (1D400-1D7FF)
        if 0x1D400 <= code <= 0x1D7FF:
            return True
    return False

def _count_invisible_chars(text: str) -> int:
    count = 0
    for ch in text:
        code = ord(ch)
        if (
            0x200B <= code <= 0x200F  # Zero-width spaces, LTR/RTL marks
            or 0x202A <= code <= 0x202E  # Bidi overrides
            or 0x2060 <= code <= 0x206F  # General punctuation/invisible
            or 0xFEFF == code            # BOM
            or 0xE0000 <= code <= 0xE007F # Tags
            or code == 0xAD              # Soft hyphen
        ):
            count += 1
    return count

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def check_shell_execution(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP001: Direct shell execution."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            cmd = str(cfg.get("command", "")).strip().lower()
            if Path(cmd).name in DANGEROUS_COMMANDS:
                findings.append(Finding(
                    rule_id="AMCP001",
                    severity="CRITICAL",
                    title="Direct Shell Execution Allowed",
                    message=f"Server '{name}' invokes shell '{cmd}' directly.",
                    location=loc,
                    remediation="Replace shell wrappers with a dedicated, scoped MCP server binary.",
                ))
    return findings

def check_unpinned_npx(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP002: Unpinned npx package."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            cmd = str(cfg.get("command", "")).strip().lower()
            args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
            if Path(cmd).name == "npx":
                for arg in args:
                    if arg.startswith("-"):
                        continue
                    if "@" not in arg[1:]:
                        findings.append(Finding(
                            rule_id="AMCP002",
                            severity="MEDIUM",
                            title="Unpinned npx Package Version",
                            message=f"Package '{arg}' runs without a pinned version, risking supply-chain hijacking.",
                            location=loc,
                            remediation=f"Pin an explicit version (e.g., '{arg}@1.0.0').",
                        ))
                    break
    return findings

def check_sensitive_paths(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP003: Sensitive filesystem paths."""
    findings = []
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            loc = f"{location}:mcpServers.{name}"
            args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
            for arg in args:
                cleaned = arg.strip()
                if cleaned in ("/", "C:\\") or any(s in cleaned.lower() for s in (".ssh", ".env", "id_rsa", "/etc", "/root")):
                    findings.append(Finding(
                        rule_id="AMCP003",
                        severity="HIGH",
                        title="Overly Broad or Sensitive Path Exposure",
                        message=f"Server '{name}' exposes sensitive path '{cleaned}'.",
                        location=loc,
                        remediation="Restrict filesystem access to a dedicated non-sensitive workspace directory.",
                    ))
    return findings

def check_hardcoded_secrets(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP004: Hardcoded secrets in env."""
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
                if _is_env_placeholder(val):
                    continue

                for label, pattern in SECRET_PATTERNS:
                    if pattern.search(val):
                        findings.append(Finding(
                            rule_id="AMCP004",
                            severity="CRITICAL",
                            title=f"Hardcoded Secret Detected ({label})",
                            message=f"Environment variable '{k}' in server '{name}' contains a hardcoded secret.",
                            location=f"{loc}.env.{k}",
                            remediation="Inject credentials via runtime environment variables or a secret manager.",
                        ))

                # Also check for template injection in env vars
                for label, pattern in PROMPT_INJECTION_PATTERNS:
                    if label == "Template Injection" and pattern.search(val):
                        findings.append(Finding(
                            rule_id="AMCP005",
                            severity="CRITICAL",
                            title=f"Potential Tool Poisoning ({label})",
                            message=f"Environment variable '{k}' in server '{name}' contains suspicious template injection.",
                            location=f"{loc}.env.{k}",
                            remediation="Do not use dynamic templates in environment variables.",
                        ))
    return findings

def check_tool_poisoning(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP005: Tool poisoning / prompt injection."""
    findings = []
    # Check root-level tools
    tools = data.get("tools", [])
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name = str(tool.get("name", "unknown"))
            desc = str(tool.get("description", ""))
            loc = f"{location}:tools.{t_name}"

            for label, pattern in PROMPT_INJECTION_PATTERNS:
                if pattern.search(desc):
                    findings.append(Finding(
                        rule_id="AMCP005",
                        severity="CRITICAL",
                        title=f"Potential Tool Poisoning ({label})",
                        message=f"Tool '{t_name}' description matches suspicious prompt injection pattern.",
                        location=loc,
                        remediation="Audit and sanitize the tool description; remove hidden LLM directives.",
                    ))

            if _is_unicode_obfuscation(desc):
                findings.append(Finding(
                    rule_id="AMCP005",
                    severity="HIGH",
                    title="Potential Tool Poisoning (Unicode Obfuscation)",
                    message=f"Tool '{t_name}' description uses non-standard Unicode characters to bypass filters.",
                    location=loc,
                    remediation="Use standard ASCII for tool descriptions.",
                ))

    # Check tools under mcpServers
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            server_tools = cfg.get("tools", [])
            if isinstance(server_tools, list):
                for tool in server_tools:
                    if not isinstance(tool, dict):
                        continue
                    t_name = str(tool.get("name", "unknown"))
                    desc = str(tool.get("description", ""))
                    loc = f"{location}:mcpServers.{name}.tools.{t_name}"

                    for label, pattern in PROMPT_INJECTION_PATTERNS:
                        if pattern.search(desc):
                            findings.append(Finding(
                                rule_id="AMCP005",
                                severity="CRITICAL",
                                title=f"Potential Tool Poisoning ({label})",
                                message=f"Tool '{t_name}' description matches suspicious prompt injection pattern.",
                                location=loc,
                                remediation="Audit and sanitize the tool description; remove hidden LLM directives.",
                            ))

                    if _is_unicode_obfuscation(desc):
                        findings.append(Finding(
                            rule_id="AMCP005",
                            severity="HIGH",
                            title="Potential Tool Poisoning (Unicode Obfuscation)",
                            message=f"Tool '{t_name}' description uses non-standard Unicode characters to bypass filters.",
                            location=loc,
                            remediation="Use standard ASCII for tool descriptions.",
                        ))
    return findings

def check_long_description(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP006: Abnormally long tool description."""
    findings = []
    # Check root-level tools
    tools = data.get("tools", [])
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name = str(tool.get("name", "unknown"))
            desc = str(tool.get("description", ""))
            loc = f"{location}:tools.{t_name}"

            if len(desc) > 1000:
                findings.append(Finding(
                    rule_id="AMCP006",
                    severity="MEDIUM",
                    title="Abnormally Long Tool Description",
                    message=f"Tool '{t_name}' description is {len(desc)} chars, which can conceal injected prompts.",
                    location=loc,
                    remediation="Keep tool descriptions concise and review the full text manually.",
                ))

    # Check tools under mcpServers
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            server_tools = cfg.get("tools", [])
            if isinstance(server_tools, list):
                for tool in server_tools:
                    if not isinstance(tool, dict):
                        continue
                    t_name = str(tool.get("name", "unknown"))
                    desc = str(tool.get("description", ""))
                    loc = f"{location}:mcpServers.{name}.tools.{t_name}"

                    if len(desc) > 1000:
                        findings.append(Finding(
                            rule_id="AMCP006",
                            severity="MEDIUM",
                            title="Abnormally Long Tool Description",
                            message=f"Tool '{t_name}' description is {len(desc)} chars, which can conceal injected prompts.",
                            location=loc,
                            remediation="Keep tool descriptions concise and review the full text manually.",
                        ))
    return findings

def check_invisible_unicode(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP007: Invisible Unicode character smuggling."""
    findings = []
    # Check root-level tools
    tools = data.get("tools", [])
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            t_name = str(tool.get("name", "unknown"))
            desc = str(tool.get("description", ""))
            loc = f"{location}:tools.{t_name}"

            hidden_count = _count_invisible_chars(desc)
            if hidden_count > 0:
                findings.append(Finding(
                    rule_id="AMCP007",
                    severity="CRITICAL",
                    title="Hidden Invisible Characters Detected",
                    message=f"Tool '{t_name}' description contains {hidden_count} invisible Unicode character(s).",
                    location=loc,
                    remediation="Remove all zero-width, bidi, and Unicode tag characters from the description.",
                ))

    # Check tools under mcpServers
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            server_tools = cfg.get("tools", [])
            if isinstance(server_tools, list):
                for tool in server_tools:
                    if not isinstance(tool, dict):
                        continue
                    t_name = str(tool.get("name", "unknown"))
                    desc = str(tool.get("description", ""))
                    loc = f"{location}:mcpServers.{name}.tools.{t_name}"

                    hidden_count = _count_invisible_chars(desc)
                    if hidden_count > 0:
                        findings.append(Finding(
                            rule_id="AMCP007",
                            severity="CRITICAL",
                            title="Hidden Invisible Characters Detected",
                            message=f"Tool '{t_name}' description contains {hidden_count} invisible Unicode character(s).",
                            location=loc,
                            remediation="Remove all zero-width, bidi, and Unicode tag characters from the description.",
                        ))
    return findings

def check_high_entropy_secrets(data: dict[str, Any], location: str) -> list[Finding]:
    """AMCP008: High-entropy unknown secrets."""
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
                if _is_env_placeholder(val):
                    continue

                matched_known = any(pattern.search(val) for _, pattern in SECRET_PATTERNS)
                if matched_known:
                    continue

                if len(val) >= 20 and " " not in val and not val.startswith(("http://", "https://")):
                    score = _shannon_entropy(val)
                    if score >= 4.2:
                        findings.append(Finding(
                            rule_id="AMCP008",
                            severity="HIGH",
                            title="High-Entropy Secret Suspected",
                            message=f"Environment variable '{k}' looks like a random secret (entropy: {score:.2f}).",
                            location=f"{loc}.env.{k}",
                            remediation="Verify whether this value is a secret and move it to a secret manager.",
                        ))
    return findings

CONFIG_RULES = [
    Rule("AMCP001", "CRITICAL", "Direct Shell Execution Allowed", "Detects direct shell invocation", "Use dedicated binary.", check_shell_execution),
    Rule("AMCP002", "MEDIUM", "Unpinned npx Package Version", "Detects unpinned npx package", "Pin explicit version.", check_unpinned_npx),
    Rule("AMCP003", "HIGH", "Overly Broad or Sensitive Path Exposure", "Detects sensitive paths", "Restrict access.", check_sensitive_paths),
    Rule("AMCP004", "CRITICAL", "Hardcoded Secret Detected", "Detects hardcoded secrets", "Use env vars.", check_hardcoded_secrets),
    Rule("AMCP005", "CRITICAL", "Potential Tool Poisoning", "Detects prompt injection in tool descriptions", "Sanitize description.", check_tool_poisoning),
    Rule("AMCP006", "MEDIUM", "Abnormally Long Tool Description", "Detects overly long descriptions", "Keep concise.", check_long_description),
    Rule("AMCP007", "CRITICAL", "Hidden Invisible Characters Detected", "Detects invisible Unicode", "Remove hidden chars.", check_invisible_unicode),
    Rule("AMCP008", "HIGH", "High-Entropy Secret Suspected", "Detects high-entropy strings", "Move to secret manager.", check_high_entropy_secrets),
]
