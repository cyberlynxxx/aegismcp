"""JavaScript/TypeScript AST-based security scanning."""
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class JSFinding:
    """A security finding from JS/TS analysis."""
    rule_id: str
    severity: str
    confidence: str
    title: str
    message: str
    file_path: Path
    line: int
    column: int
    remediation: str

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line}:{self.column}"

class JSScanner:
    """Scans JS/TS files using regex-based pattern matching."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: list[JSFinding] = []

    def _add_finding(self, rule_id: str, severity: str, confidence: str, title: str, message: str,
                     line: int, column: int, remediation: str) -> None:
        self.findings.append(JSFinding(
            rule_id=rule_id,
            severity=severity,
            confidence=confidence,
            title=title,
            message=message,
            file_path=self.file_path,
            line=line,
            column=column,
            remediation=remediation,
        ))

    def scan(self) -> list[JSFinding]:
        # Check file size first (DoS protection)
        try:
            file_size = self.file_path.stat().st_size
            if file_size > 2 * 1024 * 1024:  # 2 MB limit
                return []
        except OSError:
            return []

        # Detect binary files (null bytes)
        try:
            with self.file_path.open("rb") as f:
                chunk = f.read(8192)
                if b"\x00" in chunk:
                    return []  # Skip binary files
        except OSError:
            return []

        # Read with encoding fallback
        lines = None
        for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                with self.file_path.open("r", encoding=encoding, errors="replace") as f:
                    lines = f.readlines()
                break
            except (UnicodeDecodeError, OSError):
                continue

        if lines is None:
            return []

        # Limit total content size
        total_size = sum(len(line) for line in lines)
        if total_size > 10 * 1024 * 1024:  # 10 MB limit
            # Truncate lines
            truncated = []
            running = 0
            for line in lines:
                running += len(line)
                if running > 10 * 1024 * 1024:
                    break
                truncated.append(line)
            lines = truncated

        # Simple patterns for common JS/TS security issues
        patterns = [
            (
                "AMCP401", "CRITICAL", "HIGH", "Exec call detected",
                r"child_process\.(exec|execSync)",
                "Avoid exec(). Use child_process.spawn() or execFile() with sanitized args."
            ),
            (
                "AMCP402", "CRITICAL", "HIGH", "Dangerously set innerHTML",
                r"\.innerHTML\s*=",
                "Avoid innerHTML. Use textContent or a sanitizer library like DOMPurify."
            ),
            (
                "AMCP403", "HIGH", "MEDIUM", "Hardcoded secret",
                r"(?i)(password|secret|apikey|token)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                "Do not hardcode secrets. Use environment variables or a secret manager."
            )
        ]

        for i, line in enumerate(lines):
            for rule_id, sev, conf, title, pattern, rem in patterns:
                if re.search(pattern, line):
                    self._add_finding(rule_id, sev, conf, title, line.strip(), i + 1, 0, rem)

        return self.findings

def scan_js_directory(root: Path) -> list[JSFinding]:
    """Recursively scan JS/TS files."""
    findings = []
    ignore_dirs = {"node_modules", "dist", "build", ".git"}

    for ext in ["*.js", "*.ts", "*.mjs", "*.cjs"]:
        for js_file in root.rglob(ext):
            if any(part in ignore_dirs for part in js_file.parts):
                continue
            scanner = JSScanner(js_file)
            findings.extend(scanner.scan())

    return findings
