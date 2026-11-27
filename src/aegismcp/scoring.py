"""Weighted prompt injection scoring engine for proxy."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class ScoringMode(str, Enum):
    """Scoring engine mode."""
    STRICT = "strict"
    BALANCED = "balanced"


@dataclass
class InjectionPattern:
    """A single injection detection pattern with weight."""
    name: str
    pattern: re.Pattern
    weight: float
    category: str


@dataclass
class ScoringResult:
    """Result of prompt injection scoring."""
    score: float
    max_score: float
    triggered_patterns: list[InjectionPattern] = field(default_factory=list)
    is_blocked: bool = False
    mode: ScoringMode = ScoringMode.BALANCED

    @property
    def normalized_score(self) -> float:
        """Score normalized to 0-1 range."""
        if self.max_score == 0:
            return 0.0
        return min(1.0, self.score / self.max_score)

    @property
    def risk_level(self) -> str:
        """Human-readable risk level."""
        norm = self.normalized_score
        if norm >= 0.8:
            return "CRITICAL"
        elif norm >= 0.5:
            return "HIGH"
        elif norm >= 0.2:
            return "MEDIUM"
        return "LOW"


# Default patterns with weights (balanced mode)
BALANCED_PATTERNS = [
    # Critical patterns - direct instruction override
    InjectionPattern(
        name="Instruction Override - Direct",
        pattern=re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions"),
        weight=1.0,
        category="instruction_override"
    ),
    InjectionPattern(
        name="Instruction Override - System Prompt",
        pattern=re.compile(r"(?i)(system\s+prompt|initial\s+instructions?|core\s+instructions?)\s*(?:is|:|to)"),
        weight=0.9,
        category="instruction_override"
    ),
    InjectionPattern(
        name="Role Manipulation",
        pattern=re.compile(r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:a\s+)?(developer|admin|root|system|unrestricted)"),
        weight=0.85,
        category="role_manipulation"
    ),

    # High patterns - hidden directives
    InjectionPattern(
        name="Hidden Priority Tag",
        pattern=re.compile(r"(?i)<\s*(important|system|instructions?|priority|urgent)\s*>"),
        weight=0.8,
        category="hidden_directive"
    ),
    InjectionPattern(
        name="Template Injection - Handlebar",
        pattern=re.compile(r"\{\{\s*(system|exec|eval|process|require|import|child_process|fs\.readFile)\s*\("),
        weight=0.9,
        category="template_injection"
    ),
    InjectionPattern(
        name="Template Injection - Jinja",
        pattern=re.compile(r"\{\%\s*(import|include|exec|eval)\s*\%\}"),
        weight=0.85,
        category="template_injection"
    ),
    InjectionPattern(
        name="XML/HTML Script Tag",
        pattern=re.compile(r"(?i)<\s*script\b[^>]*>"),
        weight=0.75,
        category="code_injection"
    ),

    # High patterns - data exfiltration
    InjectionPattern(
        name="Stealth Exfiltration",
        pattern=re.compile(r"(?i)(do\s+not\s+(tell|inform|mention)\s+(the\s+)?user|silently\s+send|exfiltrate|leak)"),
        weight=0.8,
        category="exfiltration"
    ),
    InjectionPattern(
        name="Sensitive File Read Trigger",
        pattern=re.compile(r"(?i)(read|cat|dump|send|exfiltrate)\s+.*(\.ssh|\.env|id_rsa|aws/credentials|\.aws|secrets|\.git)"),
        weight=0.85,
        category="exfiltration"
    ),
    InjectionPattern(
        name="Remote Execution / Exfil",
        pattern=re.compile(r"(?i)\b(curl|wget|nc|netcat|powershell|bash|sh)\b.*https?://"),
        weight=0.85,
        category="remote_execution"
    ),

    # Medium patterns - encoding/obfuscation
    InjectionPattern(
        name="Unicode Obfuscation - Fullwidth",
        pattern=re.compile(r"[！-～]"),  # Fullwidth forms
        weight=0.4,
        category="obfuscation"
    ),
    InjectionPattern(
        name="Unicode Obfuscation - Bidi",
        pattern=re.compile(r"[\u202a-\u202e\u2066-\u2069]"),  # Bidi override
        weight=0.5,
        category="obfuscation"
    ),
    InjectionPattern(
        name="Unicode Obfuscation - Zero Width",
        pattern=re.compile(r"[\u200b-\u200f\ufeff]"),  # Zero-width
        weight=0.5,
        category="obfuscation"
    ),
    InjectionPattern(
        name="Hex/Unicode Escape",
        pattern=re.compile(r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})"),
        weight=0.4,
        category="obfuscation"
    ),
    InjectionPattern(
        name="Base64 Encoded Payload",
        pattern=re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})"),
        weight=0.3,
        category="obfuscation"
    ),

    # Medium patterns - indirect injection
    InjectionPattern(
        name="Indirect - User Input Marker",
        pattern=re.compile(r"(?i)(###\s*USER\s+INPUT\s*###|<<<\s*USER\s+INPUT\s*>>>|\[\[USER\s+INPUT\]\])"),
        weight=0.6,
        category="indirect_injection"
    ),
    InjectionPattern(
        name="Indirect - Conversation History",
        pattern=re.compile(r"(?i)(previous\s+conversation|chat\s+history|context\s+above|earlier\s+messages?)"),
        weight=0.35,
        category="indirect_injection"
    ),

    # Lower patterns - suspicious keywords
    InjectionPattern(
        name="Suspicious - Developer/Debug Mode",
        pattern=re.compile(r"(?i)(developer\s+mode|debug\s+mode|admin\s+mode|maintenance\s+mode)"),
        weight=0.3,
        category="suspicious_keywords"
    ),
    InjectionPattern(
        name="Suspicious - Disable Safety",
        pattern=re.compile(r"(?i)(disable|turn\s+off|bypass)\s+(safety|filter|guard|protection)"),
        weight=0.6,
        category="suspicious_keywords"
    ),
    InjectionPattern(
        name="Suspicious - Output Raw/Internal",
        pattern=re.compile(r"(?i)(output|show|print|display|reveal)\s+(raw|internal|hidden|system)\s+(prompt|instructions|reasoning)"),
        weight=0.5,
        category="suspicious_keywords"
    ),
]


# Strict mode patterns - more aggressive, lower thresholds
STRICT_PATTERNS = BALANCED_PATTERNS + [
    # Additional strict patterns
    InjectionPattern(
        name="Strict - Any System Reference",
        pattern=re.compile(r"(?i)\b(system|assistant|ai|model)\b.*\b(instruction|prompt|directive|rule)\b"),
        weight=0.4,
        category="strict_broad"
    ),
    InjectionPattern(
        name="Strict - Code Block with Command",
        pattern=re.compile(r"```\s*(?:bash|sh|shell|python|powershell)\s*\n.*(?:rm|curl|wget|nc|exec|eval)"),
        weight=0.5,
        category="strict_broad"
    ),
    InjectionPattern(
        name="Strict - JSON/Structured Injection",
        pattern=re.compile(r"(?i)(\{\s*\"(?:system|prompt|instruction|role)\"\s*:)"),
        weight=0.45,
        category="strict_broad"
    ),
    InjectionPattern(
        name="Strict - Recursive Self-Reference",
        pattern=re.compile(r"(?i)(this\s+(prompt|message|request)|the\s+current\s+(prompt|instruction))"),
        weight=0.35,
        category="strict_broad"
    ),
]


# Thresholds for each mode
MODE_THRESHOLDS = {
    ScoringMode.BALANCED: {
        "block_threshold": 0.6,      # Block if normalized score >= 0.6
        "alert_threshold": 0.3,      # Alert if normalized score >= 0.3
    },
    ScoringMode.STRICT: {
        "block_threshold": 0.4,      # Block if normalized score >= 0.4
        "alert_threshold": 0.2,      # Alert if normalized score >= 0.2
    },
}

# Max possible scores for normalization
MAX_BALANCED_SCORE = sum(p.weight for p in BALANCED_PATTERNS)
MAX_STRICT_SCORE = sum(p.weight for p in STRICT_PATTERNS)


class PromptInjectionScorer:
    """Weighted prompt injection detection with configurable modes."""

    def __init__(self, mode: ScoringMode = ScoringMode.BALANCED, custom_patterns: list[InjectionPattern] | None = None):
        self.mode = mode
        self.patterns = (STRICT_PATTERNS if mode == ScoringMode.STRICT else BALANCED_PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self.max_score = MAX_STRICT_SCORE if mode == ScoringMode.STRICT else MAX_BALANCED_SCORE
        self.thresholds = MODE_THRESHOLDS[mode]

    def score(self, text: str) -> ScoringResult:
        """
        Score text for prompt injection risk.

        Args:
            text: Text to analyze

        Returns:
            ScoringResult with score, triggered patterns, and block decision
        """
        if not text:
            return ScoringResult(
                score=0.0,
                max_score=self.max_score,
                mode=self.mode
            )

        # Input size limit
        if len(text) > 10 * 1024 * 1024:  # 10 MB
            text = text[:10 * 1024 * 1024]

        triggered = []
        total_score = 0.0

        for pattern in self.patterns:
            try:
                if pattern.pattern.search(text):
                    triggered.append(pattern)
                    total_score += pattern.weight
            except re.error:
                continue

        result = ScoringResult(
            score=total_score,
            max_score=self.max_score,
            triggered_patterns=triggered,
            mode=self.mode
        )

        # Determine if should block
        result.is_blocked = result.normalized_score >= self.thresholds["block_threshold"]

        return result

    def score_dict(self, data: dict) -> dict[str, ScoringResult]:
        """Score all string values in a dict."""
        results = {}
        for key, value in data.items():
            if isinstance(value, str):
                results[key] = self.score(value)
            elif isinstance(value, dict):
                nested = self.score_dict(value)
                for nk, nr in nested.items():
                    results[f"{key}.{nk}"] = nr
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        results[f"{key}[{i}]"] = self.score(item)
                    elif isinstance(item, dict):
                        nested = self.score_dict(item)
                        for nk, nr in nested.items():
                            results[f"{key}[{i}].{nk}"] = nr
        return results


def create_scorer_from_config(config: dict) -> PromptInjectionScorer:
    """Create scorer from proxy policy configuration."""
    mode_str = config.get("prompt_injection_mode", "balanced").lower()
    mode = ScoringMode.STRICT if mode_str == "strict" else ScoringMode.BALANCED

    custom_patterns = []
    for cp in config.get("custom_prompt_injection_patterns", []):
        try:
            custom_patterns.append(InjectionPattern(
                name=cp.get("name", "Custom"),
                pattern=re.compile(cp["pattern"]),
                weight=cp.get("weight", 0.5),
                category=cp.get("category", "custom")
            ))
        except re.error:
            pass  # Skip invalid patterns

    return PromptInjectionScorer(mode=mode, custom_patterns=custom_patterns)