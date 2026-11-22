from dataclasses import dataclass
import re

@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    message: str
    location: str
    remediation: str

DANGEROUS_COMMANDS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}

SENSITIVE_PATHS = (
    "/",
    "C:\\",
    "~/.ssh",
    ".ssh",
    ".env",
    "/etc",
    "/root",
    "id_rsa",
)

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
]