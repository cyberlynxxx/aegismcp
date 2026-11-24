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
    ("AWS Secret Key", re.compile(r"\b[0-9A-Za-z/+=]{40}\b")),  # AWS secret access key
    ("Generic Bearer/Secret", re.compile(r"(?i)(?:secret|token|password|api_key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}")),
    ("JWT Token", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe Key", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("Generic High-Entropy String", re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")),  # Catch-all for long secrets
]

PROMPT_INJECTION_PATTERNS = [
    ("Instruction Override", re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions")),
    ("Hidden Priority Tag", re.compile(r"(?i)<\s*(important|system|instructions)\s*>")),
    ("Stealth Exfiltration", re.compile(r"(?i)(do\s+not\s+(tell|inform|mention)\s+(the\s+)?user|silently\s+send)")),
    ("Sensitive File Read Trigger", re.compile(r"(?i)(read|cat|dump|send)\s+.*(\.ssh|\.env|id_rsa|aws/credentials)")),
    ("Remote Execution / Exfil", re.compile(r"(?i)\b(curl|wget|nc|powershell)\b.*https?://")),
]

# AMCP309: Response inspection patterns for server-to-client threats
RESPONSE_INJECTION_PATTERNS = [
    ("Indirect Prompt Injection - Tool Result", re.compile(r"(?i)(the\s+(user|human)\s+(should|must|will)\s+(not|never)\s+(know|see|find\s+out|be\s+told))")),
    ("Indirect Prompt Injection - Hidden Directive", re.compile(r"(?i)(when\s+the\s+user\s+(asks|queries|requests)|if\s+the\s+user\s+(asks|queries|requests)).*(?:ignore|override|bypass|send|exfiltrate)")),
    ("Indirect Prompt Injection - Conditional Trigger", re.compile(r"(?i)(on\s+(next|future|subsequent)\s+(request|query|prompt|message)).*(?:ignore|override|bypass|execute|run)")),
    ("Response Manipulation - Output Control", re.compile(r"(?i)(output|return|respond\s+with|reply\s+with)\s+(only|just|exactly)\s+(this|the\s+following)")),
    ("Response Manipulation - Suppress Output", re.compile(r"(?i)(don['\']t|do\s+not|suppress|hide|filter)\s+(output|show|display|print|reveal|log)")),
]

RESPONSE_SECRET_PATTERNS = [
    ("API Key in Response", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("GitHub Token in Response", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("AWS Access Key in Response", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key in Response", re.compile(r"\b[0-9A-Za-z/+=]{40}\b")),
    ("JWT Token in Response", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("Slack Token in Response", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe Key in Response", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("Database Connection String", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@")),
    ("Private Key in Response", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----")),
]

RESPONSE_INVISIBLE_UNICODE_PATTERNS = [
    ("Zero-Width Characters", re.compile(r"[\u200B-\u200F\uFEFF]")),
    ("Bidi Override Characters", re.compile(r"[\u202A-\u202E\u2066-\u2069]")),
    ("Invisible Separators", re.compile(r"[\u2060-\u2064]")),
    ("Format Characters", re.compile(r"[\u180E]")),  # Mongolian vowel separator
]