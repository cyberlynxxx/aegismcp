"""Taint Firewall implementation for AegisMCP v4.0.0."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from threading import RLock
from typing import Any, ClassVar


class TaintState(Enum):
    CLEAN = auto()
    TAINTED = auto()
    QUARANTINED = auto()


@dataclass
class SecretFingerprint:
    """Fingerprint of a detected secret for exfiltration tracking."""
    hash: str  # SHA-256 hash of normalized secret
    classification: str  # Type of secret (AWS Key, JWT, etc.)
    format: str  # Encoding format: Raw, Base64, Base64URL, Hex, URLEncoded
    detected_at: str  # ISO timestamp
    session_id: str = ""  # Session that contained this secret


@dataclass
class TaintSession:
    """Taint tracking session for a single MCP request context."""
    session_id: str
    state: TaintState = TaintState.CLEAN
    strikes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    secret_fingerprints: list[SecretFingerprint] = field(default_factory=list)


# High-risk sink tools - tools whose arguments should be blocked while TAINTED
HIGH_RISK_SINK_TOOLS: set[str] = {
    "bash", "shell", "execute", "run_command", "system", "subprocess",
    "write_file", "create_file", "edit_file", "delete_file",
    "http_request", "http_post", "curl", "wget", "request",
    "database_query", "sql_execute", "query_db",
    "ssh_connect", "remote_exec", "scp", "rsync",
    "git_push", "git_commit", "git_config",
    "upload", "download", "ftp", "sftp",
    "send_email", "send_message", "slack_post",
    "decrypt", "encrypt", "sign", "verify_signature",
}


# Dangerous argument patterns that enable exfiltration
DANGEROUS_ARG_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(aws_access_key_id|aws_secret_access_key|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)", "AWS Credentials"),
    (r"(?i)(api_key|apikey|secret_key|secret_key|access_token)", "API Key"),
    (r"(?i)(bearer\s+[A-Za-z0-9_\-\.]+)", "Bearer Token"),
    (r"(?i)(gh[ps]_[A-Za-z0-9]{36})", "GitHub Token"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Password"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^/\s]+", "Database URL"),
    (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT Token"),
]


class TaintFirewall:
    """Thread-safe firewall for monitoring and quarantining tainted requests.

    Tracks per-session taint state (CLEAN, TAINTED, QUARANTINED) with
    configurable strike thresholds. Includes data-flow fingerprinting for
    secret exfiltration detection across multiple encoding formats.
    """

    # Secret patterns to detect (API keys, tokens, passwords, etc.)
    SECRET_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        # AWS
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"[A-Za-z0-9/+=]{40}", "AWS Secret Access Key"),
        # Generic API keys
        (r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{20,}[\"']?", "API Key/Token"),
        # Bearer tokens
        (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "Bearer Token"),
        # GitHub tokens
        (r"gh[ps]_[A-Za-z0-9]{36}", "GitHub Token"),
        # Generic secrets
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?", "Password"),
        # Private keys
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key"),
        # Database URLs
        (r"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^/\s]+", "Database Connection String"),
        # JWT tokens
        (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT Token"),
    ]

    # Encoding detection patterns
    BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    BASE64_URL_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")
    HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
    URL_ENCODED_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

    def __init__(self, strike_threshold: int = 3) -> None:
        self.strike_threshold = strike_threshold
        self._sessions: dict[str, TaintSession] = {}
        self._lock = RLock()
        self._event_bus = None  # Lazy-loaded

    def _get_event_bus(self):
        """Lazily get the event bus."""
        if self._event_bus is None:
            from .events import get_event_bus
            self._event_bus = get_event_bus()
        return self._event_bus

    def _compute_fingerprint(self, data: str, format_name: str) -> str | None:
        """Compute SHA-256 fingerprint of a normalized secret."""
        if not data:
            return None
        # Normalize by removing whitespace and converting to lowercase for comparison
        normalized = re.sub(r"\s+", "", data.strip())
        if not normalized:
            return None
        return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()

    def _extract_secrets_from_data(self, data: str) -> list[tuple[str, str, str]]:
        """Extract secrets from data with their format info.

        Returns list of (secret, classification, format) tuples.
        """
        secrets = []

        # Check raw data first
        for pattern, name in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, data, re.IGNORECASE if pattern.startswith("(?i)") else 0)
            for match in matches:
                secrets.append((match.group(), name, "Raw"))

        # Check Base64 encoded secrets
        if self.BASE64_PATTERN.match(data.strip()):
            try:
                decoded_bytes = base64.b64decode(data.strip(), validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                for pattern, name in self.SECRET_PATTERNS:
                    if re.search(pattern, decoded_str):
                        secrets.append((decoded_str, name, "Base64"))
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

        # Check URL-safe Base64
        if self.BASE64_URL_PATTERN.match(data.strip()):
            try:
                padded = data.strip() + "=" * (-len(data.strip()) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                for pattern, name in self.SECRET_PATTERNS:
                    if re.search(pattern, decoded_str):
                        secrets.append((decoded_str, name, "Base64URL"))
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

        # Check Hex encoded
        if self.HEX_PATTERN.match(data) and len(data) % 2 == 0 and len(data) >= 4:
            try:
                decoded = bytes.fromhex(data).decode("utf-8", errors="ignore")
                for pattern, name in self.SECRET_PATTERNS:
                    if re.search(pattern, decoded):
                        secrets.append((decoded, name, "Hex"))
            except (ValueError, UnicodeDecodeError):
                pass

        # Check URL-encoded
        if self.URL_ENCODED_PATTERN.search(data):
            try:
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    for pattern, name in self.SECRET_PATTERNS:
                        if re.search(pattern, decoded):
                            secrets.append((decoded, name, "URLEncoded"))
            except (ValueError, UnicodeDecodeError):
                pass

        return secrets

    def store_secret_fingerprint(self, session_id: str, secret: str,
                                  classification: str, format_name: str) -> SecretFingerprint:
        """Store a secret fingerprint for a session."""
        fingerprint_hash = self._compute_fingerprint(secret, format_name)
        if fingerprint_hash is None:
            # Fallback to hash of raw string if we can't normalize
            fingerprint_hash = hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()

        fp = SecretFingerprint(
            hash=fingerprint_hash,
            classification=classification,
            format=format_name,
            detected_at=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
        )

        with self._lock:
            session = self._sessions.get(session_id, TaintSession(session_id))
            session.secret_fingerprints.append(fp)
            self._sessions[session_id] = session

        return fp

    def check_secret_exfiltration(self, session_id: str, data: str) -> tuple[bool, list[str], list[SecretFingerprint]]:
        """Check for 2-step exfiltration: secrets from responses flowing to dangerous sinks.

        Decodes outbound data in multiple formats (Raw, Base64, Base64URL, Hex, URLEncoded)
        and checks if any decoded content matches stored secret fingerprints.

        Returns (is_exfiltrating, classifications, matched_fingerprints)
        """
        sessions = []
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                sessions.append(session)

        exfiltrating = False
        classifications = []
        matched_fingerprints = []

        if not sessions:
            return False, [], []

        # Check multiple encodings of the outbound data
        variants = []

        # 1. Raw data
        variants.append(("Raw", data))

        # 2. Try Base64 decode
        if self.BASE64_PATTERN.match(data.strip()):
            try:
                decoded = base64.b64decode(data.strip(), validate=True).decode("utf-8", errors="ignore")
                variants.append(("Base64", decoded))
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

        # 3. Try URL-safe Base64 decode
        if self.BASE64_URL_PATTERN.match(data.strip()):
            try:
                padded = data.strip() + "=" * (-len(data.strip()) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
                variants.append(("Base64URL", decoded))
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

        # 4. Try Hex decode
        if self.HEX_PATTERN.match(data) and len(data) % 2 == 0 and len(data) >= 4:
            try:
                decoded = bytes.fromhex(data).decode("utf-8", errors="ignore")
                variants.append(("Hex", decoded))
            except (ValueError, UnicodeDecodeError):
                pass

        # 5. Try URL decode
        if self.URL_ENCODED_PATTERN.search(data):
            try:
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    variants.append(("URLEncoded", decoded))
            except (ValueError, UnicodeDecodeError):
                pass

        # Now check each variant against stored fingerprints
        for session in sessions:
            for fp in session.secret_fingerprints:
                for fmt_name, variant_data in variants:
                    # Compute hash of the decoded variant
                    variant_hash = hashlib.sha256(variant_data.encode("utf-8", errors="ignore")).hexdigest()
                    if fp.hash == variant_hash:
                        exfiltrating = True
                        classifications.append(f"{fp.classification} (exfil from {fp.format} via {fmt_name})")
                        matched_fingerprints.append(fp)

        return exfiltrating, classifications, matched_fingerprints

    def is_high_risk_sink_tool(self, tool_name: str) -> bool:
        """Check if a tool is a high-risk sink that should be blocked when TAINTED."""
        tool_lower = tool_name.lower()
        for sink in HIGH_RISK_SINK_TOOLS:
            if sink in tool_lower or tool_lower in sink:
                return True
        return False

    def check_outbound_arguments(self, session_id: str, tool_name: str,
                                  arguments: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
        """Check outbound tools/call arguments for secret exfiltration risk.

        Returns (is_blocked, findings, classifications)
        """
        if not self.is_high_risk_sink_tool(tool_name):
            return False, [], []

        # Check if session has any stored fingerprints or is tainted
        session = self.get_session(session_id)
        if not session or (session.state == TaintState.CLEAN and not session.secret_fingerprints):
            return False, [], []

        findings = []
        classifications = []

        # Scan all argument values for secrets
        for arg_name, arg_value in arguments.items():
            if isinstance(arg_value, str):
                # Check for direct secrets via pattern matching
                is_tainted, args_classifications = self.analyze_data_flow(session_id, arg_value)
                if is_tainted:
                    # Store fingerprints for detected secrets
                    for pattern, name in self.SECRET_PATTERNS:
                        if re.search(pattern, arg_value):
                            self.store_secret_fingerprint(session_id, arg_value, name, "Raw")
                    classifications.extend(args_classifications)
                    findings.append(f"Potential secret exfil in argument '{arg_name}' via high-risk sink tool '{tool_name}'")

                # Also check for fingerprint matches (2-step exfiltration)
                # If we have stored fingerprints, check if outbound data matches
                exfiltrating, exfil_classes, _matched_fps = self.check_secret_exfiltration(session_id, arg_value)
                if exfiltrating:
                    findings.append(f"2-step exfiltration detected in argument '{arg_name}' via high-risk sink tool '{tool_name}'")
                    classifications.extend(exfil_classes)

        # Also scan for encoded secrets
        for arg_name, arg_value in arguments.items():
            if isinstance(arg_value, str):
                secrets = self._extract_secrets_from_data(arg_value)
                if secrets:
                    for secret, classification, fmt in secrets:
                        self.store_secret_fingerprint(session_id, secret, classification, fmt)
                        classifications.append(f"{classification} ({fmt}) in {arg_name}")
                    findings.append(f"Encoded secret detected in argument '{arg_name}'")

        if findings:
            return True, findings, classifications
        return False, [], []

    def update_taint(self, session_id: str, is_tainted: bool, classification: str = "") -> TaintState:
        """Update taint state for a session."""
        with self._lock:
            session = self._sessions.get(session_id, TaintSession(session_id))

            if is_tainted:
                session.strikes += 1
                session.metadata["last_classification"] = classification

                if session.strikes >= self.strike_threshold:
                    session.state = TaintState.QUARANTINED
                else:
                    session.state = TaintState.TAINTED
            else:
                # Potential recovery, but strike count stays as history
                session.state = TaintState.CLEAN

            self._sessions[session_id] = session
            return session.state

    def is_quarantined(self, session_id: str) -> bool:
        """Check if session is quarantined."""
        with self._lock:
            session = self._sessions.get(session_id)
            return session is not None and session.state == TaintState.QUARANTINED

    def clear_session(self, session_id: str) -> None:
        """Remove session from cache."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]

    def analyze_data_flow(self, session_id: str, data: str) -> tuple[bool, list[str]]:
        """Analyze data flow for secret exfiltration across encoding formats.

        Detects secrets in:
        - Raw format
        - Base64 (standard and URL-safe)
        - Hex encoding
        - URL-encoded

        Returns (is_tainted, list_of_classifications)
        """
        classifications = []

        # Check raw data
        raw_classifications = self._scan_for_secrets(data)
        classifications.extend(raw_classifications)

        # Check Base64 decoded
        if self.BASE64_PATTERN.match(data) or self.BASE64_URL_PATTERN.match(data):
            # Try standard base64
            try:
                decoded = base64.b64decode(data, validate=True).decode("utf-8", errors="ignore")
                b64_classifications = self._scan_for_secrets(decoded)
                if b64_classifications:
                    classifications.extend([f"Base64:{c}" for c in b64_classifications])
                    # Store fingerprints for detected secrets
                    for pattern, name in self.SECRET_PATTERNS:
                        if re.search(pattern, decoded):
                            self.store_secret_fingerprint(session_id, decoded, name, "Base64")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

            # Try URL-safe base64
            try:
                # Add padding if needed
                padded = data + "=" * (-len(data) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
                b64u_classifications = self._scan_for_secrets(decoded)
                if b64u_classifications:
                    classifications.extend([f"Base64URL:{c}" for c in b64u_classifications])
                    # Store fingerprints
                    for pattern, name in self.SECRET_PATTERNS:
                        if re.search(pattern, decoded):
                            self.store_secret_fingerprint(session_id, decoded, name, "Base64URL")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

        # Check Hex decoded
        try:
            if self.HEX_PATTERN.match(data) and len(data) % 2 == 0 and len(data) >= 4:
                decoded = bytes.fromhex(data).decode("utf-8", errors="ignore")
                hex_classifications = self._scan_for_secrets(decoded)
                if hex_classifications:
                    classifications.extend([f"Hex:{c}" for c in hex_classifications])
                    # Store fingerprints
                    for pattern, name in self.SECRET_PATTERNS:
                        if re.search(pattern, decoded):
                            self.store_secret_fingerprint(session_id, decoded, name, "Hex")
        except (ValueError, UnicodeDecodeError):
            pass

        # Check URL-encoded
        try:
            if self.URL_ENCODED_PATTERN.search(data):
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    url_classifications = self._scan_for_secrets(decoded)
                    if url_classifications:
                        classifications.extend([f"URLEncoded:{c}" for c in url_classifications])
                        # Store fingerprints
                        for pattern, name in self.SECRET_PATTERNS:
                            if re.search(pattern, decoded):
                                self.store_secret_fingerprint(session_id, decoded, name, "URLEncoded")
        except (ValueError, UnicodeDecodeError):
            pass

        is_tainted = len(classifications) > 0
        return is_tainted, classifications

    def _scan_for_secrets(self, text: str) -> list[str]:
        """Scan text for secret patterns. Returns list of classification names."""
        found = []
        for pattern, name in self.SECRET_PATTERNS:
            if re.search(pattern, text):
                found.append(name)
        return found

    def get_session(self, session_id: str) -> TaintSession | None:
        """Get session data for inspection."""
        with self._lock:
            return self._sessions.get(session_id)

    def get_all_sessions(self) -> dict[str, TaintSession]:
        """Get all sessions (for monitoring/UI)."""
        with self._lock:
            return dict(self._sessions)

    def get_secret_fingerprints(self, session_id: str) -> list[SecretFingerprint]:
        """Get all secret fingerprints for a session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                return list(session.secret_fingerprints)
            return []

    def check_fingerprint_match(self, data: str) -> list[str]:
        """Check if data matches any stored fingerprint across all sessions.

        Returns list of matching classifications.
        """
        data_hash = hashlib.sha256(data.encode("utf-8", errors="ignore")).hexdigest()
        matches = []

        with self._lock:
            for session in self._sessions.values():
                for fp in session.secret_fingerprints:
                    if fp.hash == data_hash:
                        matches.append(fp.classification)

        return matches