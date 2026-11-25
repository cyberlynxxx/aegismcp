"""Multi-stage anti-evasion normalizer for MCP traffic."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any
from urllib.parse import unquote, urlparse


class Normalizer:
    """
    Multi-stage normalizer for anti-evasion.

    Pipeline stages:
    1. Unicode NFKC normalization
    2. Iterative URL decoding (multiple rounds)
    3. Iterative Base64 decoding
    4. Iterative Hex decoding
    5. Enhanced SSRF IP format detection
    """

    # Maximum iterations for iterative decoding to prevent infinite loops
    MAX_DECODE_ITERATIONS = 5

    # Regex patterns for detecting encoded content
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

    @classmethod
    def normalize(cls, text: str, max_iterations: int | None = None) -> str:
        """
        Apply full normalization pipeline to text.

        Args:
            text: Input text to normalize
            max_iterations: Max decode iterations (default: 5)

        Returns:
            Normalized text
        """
        if max_iterations is None:
            max_iterations = cls.MAX_DECODE_ITERATIONS

        # Stage 1: Unicode NFKC normalization
        text = cls._normalize_unicode(text)

        # Stage 2: Iterative URL decoding
        text = cls._iterative_url_decode(text, max_iterations)

        # Stage 3: Iterative Base64 decoding
        text = cls._iterative_base64_decode(text, max_iterations)

        # Stage 4: Iterative Hex decoding
        text = cls._iterative_hex_decode(text, max_iterations)

        # Stage 5: Final Unicode normalization after decoding
        text = cls._normalize_unicode(text)

        return text

    @classmethod
    def _normalize_unicode(cls, text: str) -> str:
        """Apply Unicode NFKC normalization."""
        if not text:
            return text
        return unicodedata.normalize('NFKC', text)

    @classmethod
    def _iterative_url_decode(cls, text: str, max_iterations: int) -> str:
        """Iteratively URL-decode until no more %XX sequences found."""
        if not text:
            return text

        for _ in range(max_iterations):
            # Find all %XX patterns
            if '%' not in text:
                break

            try:
                decoded = unquote(text)
                if decoded == text:
                    break
                text = decoded
            except (ValueError, UnicodeDecodeError):
                break

        return text

    @classmethod
    def _iterative_base64_decode(cls, text: str, max_iterations: int) -> str:
        """Iteratively Base64-decode strings that look like Base64."""
        if not text:
            return text

        for _ in range(max_iterations):
            # Only try to decode if it looks like Base64
            # Check if the whole string or a significant portion is Base64
            if cls._looks_like_base64(text):
                try:
                    decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                    if decoded == text:
                        break
                    text = decoded
                except (binascii.Error, UnicodeDecodeError):
                    break
            else:
                break

        return text

    @classmethod
    def _looks_like_base64(cls, text: str) -> bool:
        """Check if text looks like a Base64 encoded string."""
        if not text or len(text) < 4:
            return False
        # Must be valid Base64 charset and length multiple of 4 (with padding)
        if not cls.BASE64_PATTERN.match(text):
            return False
        # Check length is multiple of 4
        return len(text) % 4 == 0

    @classmethod
    def _iterative_hex_decode(cls, text: str, max_iterations: int) -> str:
        """Iteratively Hex-decode strings that look like hex."""
        if not text:
            return text

        for _ in range(max_iterations):
            # Only try to decode if it looks like hex
            if cls._looks_like_hex(text):
                try:
                    decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
                    if decoded == text:
                        break
                    text = decoded
                except (ValueError, UnicodeDecodeError):
                    break
            else:
                break

        return text

    @classmethod
    def _looks_like_hex(cls, text: str) -> bool:
        """Check if text looks like a hex encoded string."""
        if not text or len(text) < 2:
            return False
        # Must be even length and valid hex
        if len(text) % 2 != 0:
            return False
        return cls.HEX_PATTERN.match(text) is not None

    @classmethod
    def normalize_dict(cls, data: dict, max_iterations: int | None = None) -> dict[str, Any]:
        """Recursively normalize all string values in a dict."""
        if max_iterations is None:
            max_iterations = cls.MAX_DECODE_ITERATIONS

        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = cls.normalize(value, max_iterations)
            elif isinstance(value, dict):
                result[key] = cls.normalize_dict(value, max_iterations)
            elif isinstance(value, list):
                result[key] = cls.normalize_list(value, max_iterations)
            else:
                result[key] = value
        return result

    @classmethod
    def normalize_list(cls, data: list, max_iterations: int | None = None) -> list[Any]:
        """Recursively normalize all string values in a list."""
        if max_iterations is None:
            max_iterations = cls.MAX_DECODE_ITERATIONS

        result: list[Any] = []
        for item in data:
            if isinstance(item, str):
                result.append(cls.normalize(item, max_iterations))
            elif isinstance(item, dict):
                result.append(cls.normalize_dict(item, max_iterations))
            elif isinstance(item, list):
                result.append(cls.normalize_list(item, max_iterations))
            else:
                result.append(item)
        return result

    @classmethod
    def extract_all_strings(cls, data: Any) -> list[str]:
        """Extract all string values from nested data structure."""
        strings = []

        if isinstance(data, str):
            strings.append(data)
        elif isinstance(data, dict):
            for value in data.values():
                strings.extend(cls.extract_all_strings(value))
        elif isinstance(data, list):
            for item in data:
                strings.extend(cls.extract_all_strings(item))

        return strings


def is_suspicious_ip(address: str) -> bool:
    """
    Enhanced SSRF detection for alternative IP formats.

    Detects:
    - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
    - Localhost (127.0.0.1, ::1)
    - Link-local (169.254.x.x)
    - Metadata endpoints (169.254.169.254)
    - IPv6 equivalents
    - Decimal/hex/octal IP formats
    - IPv4-mapped IPv6 addresses
    """
    if not address:
        return False

    address = address.strip().lower()

    # Try to parse as URL first to extract hostname
    try:
        parsed = urlparse(address if '://' in address else 'http://' + address)
        hostname = parsed.hostname or ''
    except (ValueError, AttributeError):
        hostname = address

    if not hostname:
        return False

    # Check for IPv6 addresses
    if ':' in hostname and not hostname.startswith('['):
        # Could be IPv6
        return _check_ipv6_suspicious(hostname)

    # Check for IPv4 in various formats
    return _check_ipv4_suspicious(hostname)


def _check_ipv4_suspicious(hostname: str) -> bool:
    """Check IPv4 address in various formats for suspicious ranges."""
    # Standard dotted decimal
    ipv4_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = ipv4_pattern.match(hostname)
    if match:
        octets = [int(g) for g in match.groups()]
        if all(0 <= o <= 255 for o in octets):
            return _is_private_ipv4(octets)

    # Decimal format (single integer)
    try:
        decimal_ip = int(hostname)
        if 0 <= decimal_ip <= 0xFFFFFFFF:
            octets = [
                (decimal_ip >> 24) & 0xFF,
                (decimal_ip >> 16) & 0xFF,
                (decimal_ip >> 8) & 0xFF,
                decimal_ip & 0xFF,
            ]
            return _is_private_ipv4(octets)
    except ValueError:
        pass

    # Hex format (0x...)
    if hostname.startswith('0x'):
        try:
            hex_ip = int(hostname, 16)
            if 0 <= hex_ip <= 0xFFFFFFFF:
                octets = [
                    (hex_ip >> 24) & 0xFF,
                    (hex_ip >> 16) & 0xFF,
                    (hex_ip >> 8) & 0xFF,
                    hex_ip & 0xFF,
                ]
                return _is_private_ipv4(octets)
        except ValueError:
            pass

    # Octal format (0o... or leading zero)
    if hostname.startswith('0o') or (hostname.startswith('0') and len(hostname) > 1 and hostname[1].isdigit()):
        try:
            oct_ip = int(hostname, 8)
            if 0 <= oct_ip <= 0xFFFFFFFF:
                octets = [
                    (oct_ip >> 24) & 0xFF,
                    (oct_ip >> 16) & 0xFF,
                    (oct_ip >> 8) & 0xFF,
                    oct_ip & 0xFF,
                ]
                return _is_private_ipv4(octets)
        except ValueError:
            pass

    return False


def _check_ipv6_suspicious(hostname: str) -> bool:
    """Check IPv6 address for suspicious ranges."""
    # Remove brackets if present
    ipv6 = hostname.strip('[]')

    # Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if ipv6.startswith('::ffff:'):
        ipv4_part = ipv6[7:]
        return _check_ipv4_suspicious(ipv4_part)

    # Check for IPv4-compatible IPv6 (::x.x.x.x)
    if ipv6.startswith('::') and '.' in ipv6:
        ipv4_part = ipv6[2:]
        return _check_ipv4_suspicious(ipv4_part)

    # Check for loopback (::1)
    if ipv6 == '::1' or ipv6 == '0:0:0:0:0:0:0:1':
        return True

    # Check for link-local (fe80::/10)
    if ipv6.startswith('fe80:'):
        return True

    # Check for unique local (fc00::/7)
    return bool(ipv6.startswith(('fc', 'fd')))


def _is_private_ipv4(octets: list[int]) -> bool:
    """Check if IPv4 octets represent a private/suspicious address."""
    a, b, c, d = octets

    # Loopback (127.0.0.0/8)
    if a == 127:
        return True

    # Private ranges (RFC 1918)
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True

    # Link-local (169.254.0.0/16)
    if a == 169 and b == 254:
        return True

    # Metadata endpoint (169.254.169.254)
    if a == 169 and b == 254 and c == 169 and d == 254:
        return True

    # Zero network (0.0.0.0/8)
    if a == 0:
        return True

    # Broadcast (255.255.255.255)
    if a == 255 and b == 255 and c == 255 and d == 255:
        return True

    # TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if a == 192 and b == 0 and c == 2:
        return True
    if a == 198 and b == 51 and c == 100:
        return True
    return bool(a == 203 and b == 0 and c == 113)