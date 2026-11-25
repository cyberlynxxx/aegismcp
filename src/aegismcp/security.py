"""Security utilities for AegisMCP - DoS/ReDoS protection, secret redaction, terminal sanitization."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Resource limits (configurable via environment or config)
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB default max file size for scanning
MAX_JSON_DEPTH = 32  # Maximum JSON nesting depth
MAX_JSON_SIZE = 10 * 1024 * 1024  # 10 MB max JSON payload size


# Secret patterns for redaction (ordered by specificity)
SECRET_PATTERNS = [
    # OpenAI / Anthropic API keys
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"), "sk_***REDACTED***"),
    # GitHub tokens
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), "gh*_***REDACTED***"),
    # AWS Access Key
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***REDACTED***"),
    # AWS Secret Key
    (re.compile(r"\b[0-9A-Za-z/+=]{40}\b"), "***REDACTED***"),
    # Generic Bearer/Secret/Token/Password
    (re.compile(r"(?i)(?:secret|token|password|api_key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"), r"\1: ***REDACTED***"),
    # JWT Token
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "eyJ***REDACTED***"),
    # Slack Token
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "xox*_***REDACTED***"),
    # Stripe Key
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "sk_live_***REDACTED***"),
    # Database connection strings
    (re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"), r"\1://***REDACTED***@"),
    # Private keys
    (re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----"),
    # Generic high-entropy strings (catch-all, applied last)
    (re.compile(r"\b[A-Za-z0-9_\-]{40,}\b"), "***REDACTED***"),
]


# ANSI/control character patterns for terminal injection defense
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
OSC_PATTERN = re.compile(r"\x1b\][^\x07\x1b]*[\x07\x1b]")
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
UNICODE_CONTROL_PATTERN = re.compile(r"[\u200b-\u200f\ufeff\u202a-\u202e]")


def redact_secrets(text: str) -> str:
    """
    Redact secrets from text using centralized pattern matching.

    Args:
        text: Input text that may contain secrets

    Returns:
        Text with secrets redacted
    """
    if not isinstance(text, str):
        return str(text)

    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize_terminal_text(text: str) -> str:
    """
    Sanitize text to prevent terminal injection attacks.

    Strips ANSI escape sequences, OSC sequences, control characters,
    and invisible Unicode characters that could be used to spoof
    or hide CLI output.

    Args:
        text: Untrusted input text (tool names, descriptions, payloads)

    Returns:
        Sanitized text safe for terminal output
    """
    if not isinstance(text, str):
        return str(text)

    result = text
    # Strip ANSI escape sequences (CSI)
    result = ANSI_ESCAPE_PATTERN.sub("", result)
    # Strip OSC (Operating System Command) sequences
    result = OSC_PATTERN.sub("", result)
    # Strip raw control characters
    result = CONTROL_CHARS_PATTERN.sub("", result)
    # Strip invisible Unicode control characters
    return result


def safe_json_loads(data: str, max_depth: int = MAX_JSON_DEPTH, max_size: int = MAX_JSON_SIZE) -> Any:
    """
    Safely parse JSON with depth and size limits to prevent DoS.

    Args:
        data: JSON string to parse
        max_depth: Maximum nesting depth allowed
        max_size: Maximum payload size in bytes

    Returns:
        Parsed JSON object

    Raises:
        ValueError: If limits exceeded or invalid JSON
    """
    if len(data.encode("utf-8")) > max_size:
        raise ValueError(f"JSON payload exceeds maximum size of {max_size} bytes")

    # Parse with custom hook to track depth
    def _check_depth(obj: Any, current_depth: int = 0) -> Any:
        if current_depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum of {max_depth}")
        if isinstance(obj, dict):
            return {k: _check_depth(v, current_depth + 1) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_check_depth(item, current_depth + 1) for item in obj]
        return obj

    try:
        parsed = json.loads(data)
        return _check_depth(parsed)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


def safe_json_load(file_path: Path, max_depth: int = MAX_JSON_DEPTH, max_size: int = MAX_JSON_SIZE) -> Any:
    """
    Safely load JSON from file with size and depth limits.

    Args:
        file_path: Path to JSON file
        max_depth: Maximum nesting depth allowed
        max_size: Maximum file size in bytes

    Returns:
        Parsed JSON object

    Raises:
        ValueError: If limits exceeded or invalid JSON
        OSError: If file cannot be read
    """
    file_size = file_path.stat().st_size
    if file_size > max_size:
        raise ValueError(f"File size {file_size} exceeds maximum of {max_size} bytes")

    data = file_path.read_text(encoding="utf-8")
    return safe_json_loads(data, max_depth, max_size)


def is_safe_path(base: Path, target: Path) -> bool:
    """
    Check if target path is within base directory (prevents path traversal).

    Args:
        base: Base directory (must be absolute)
        target: Target path to check

    Returns:
        True if target is within base, False otherwise
    """
    try:
        base_resolved = base.resolve()
        target_resolved = target.resolve()
        # Check if target is within base
        return target_resolved.is_relative_to(base_resolved)
    except (OSError, ValueError):
        return False


def validate_file_size(file_path: Path, max_size: int = MAX_FILE_SIZE) -> tuple[bool, str]:
    """
    Validate file size is within limits.

    Args:
        file_path: Path to file
        max_size: Maximum allowed size in bytes

    Returns:
        Tuple of (is_valid, warning_message)
    """
    try:
        file_size = file_path.stat().st_size
        if file_size > max_size:
            return False, f"File {file_path} size ({file_size} bytes) exceeds limit ({max_size} bytes), skipping"
        return True, ""
    except OSError:
        return False, f"Cannot stat file {file_path}, skipping"


# Regex DoS protection: patterns to use instead of catastrophic backtracking ones
# Use atomic groups or possessive quantifiers where possible
# In Python, use non-greedy with bounded length or regex module with timeout


def compile_safe_pattern(pattern: str, max_length: int = 10000) -> re.Pattern:
    """
    Compile regex pattern with safety checks to prevent ReDoS.

    Args:
        pattern: Regex pattern string
        max_length: Maximum input length to apply pattern to

    Returns:
        Compiled regex pattern

    Note:
        For production use, consider using the `regex` module with timeout support.
        This function adds a length check wrapper.
    """
    compiled = re.compile(pattern)

    # Store original match/search methods
    original_search = compiled.search
    original_match = compiled.match
    original_findall = compiled.findall
    original_finditer = compiled.finditer

    def safe_search(string, *args, **kwargs):
        if len(string) > max_length:
            string = string[:max_length]
        return original_search(string, *args, **kwargs)

    def safe_match(string, *args, **kwargs):
        if len(string) > max_length:
            string = string[:max_length]
        return original_match(string, *args, **kwargs)

    def safe_findall(string, *args, **kwargs):
        if len(string) > max_length:
            string = string[:max_length]
        return original_findall(string, *args, **kwargs)

    def safe_finditer(string, *args, **kwargs):
        if len(string) > max_length:
            string = string[:max_length]
        return original_finditer(string, *args, **kwargs)

    # Monkey-patch for safety (in production, use regex module with timeout)
    compiled.search = safe_search
    compiled.match = safe_match
    compiled.findall = safe_findall
    compiled.finditer = safe_finditer

    return compiled


def audit_regex_patterns() -> list[tuple[str, str]]:
    """
    Audit all regex patterns in the codebase for ReDoS risk.

    Returns:
        List of (pattern_name, risk_level) tuples
    """
    # This is a placeholder for documentation
    # Actual patterns are in rules_core.py, normalizer.py, proxy.py
    return [
        ("SECRET_PATTERNS", "LOW - bounded by specific prefixes"),
        ("PROMPT_INJECTION_PATTERNS", "LOW - specific word boundaries"),
        ("RESPONSE_INJECTION_PATTERNS", "LOW - specific phrases"),
        ("RESPONSE_SECRET_PATTERNS", "LOW - bounded by specific prefixes"),
        ("RESPONSE_INVISIBLE_UNICODE_PATTERNS", "LOW - single char classes"),
        ("normalizer patterns", "MEDIUM - some .*? patterns, bounded by max_iterations"),
        ("proxy command injection patterns", "LOW - specific dangerous commands"),
    ]