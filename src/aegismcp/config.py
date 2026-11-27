"""Configuration loading for aegismcp.yaml"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class RuleConfig:
    """Configuration for a single rule."""
    enabled: bool = True
    severity: str | None = None  # Override severity: LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class Config:
    """Main configuration for aegismcp."""
    # Rule configurations: rule_id -> RuleConfig
    rules: dict[str, RuleConfig] = field(default_factory=dict)
    # Custom regex rules
    custom_rules: list[dict[str, Any]] = field(default_factory=list)
    # Paths to ignore during scan
    ignore_paths: list[str] = field(default_factory=list)
    # Default fail-on threshold
    fail_on: str = "HIGH"
    # Auto-discovery settings
    auto_discover: bool = True

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        """Load config from aegismcp.yaml, searching up the directory tree.

        If path is a file, loads that file directly.
        If path is a directory or None, searches for aegismcp.yaml up the tree.
        """
        if path is None:
            path = Path.cwd()

        config_file = None

        # If path is a file that exists, use it directly
        if path.is_file():
            config_file = path
        else:
            # Search for aegismcp.yaml in the directory and its parents
            for parent in [path] + list(path.parents):
                candidate = parent / "aegismcp.yaml"
                if candidate.exists():
                    config_file = candidate
                    break

        if config_file is None:
            return cls()  # Default config

        if yaml is None:
            raise RuntimeError("PyYAML required for config file. Install with: pip install pyyaml")

        # Check file size (DoS protection)
        try:
            file_size = config_file.stat().st_size
            if file_size > 2 * 1024 * 1024:  # 2 MB limit
                return cls()
        except OSError:
            return cls()

        # Detect binary files
        try:
            with config_file.open("rb") as f:
                chunk = f.read(8192)
                if b"\x00" in chunk:
                    return cls()
        except OSError:
            return cls()

        # Read with encoding fallback
        data = None
        for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                with config_file.open("r", encoding=encoding, errors="replace") as f:
                    content = f.read()
                if len(content) > 10 * 1024 * 1024:  # 10 MB limit
                    content = content[:10 * 1024 * 1024]
                data = yaml.safe_load(content) or {}
                break
            except (yaml.YAMLError, UnicodeDecodeError, OSError, MemoryError):
                continue

        if data is None:
            return cls()

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create Config from parsed YAML dict."""
        rules = {}
        for rule_id, rule_data in data.get("rules", {}).items():
            if isinstance(rule_data, bool):
                rules[rule_id] = RuleConfig(enabled=rule_data)
            elif isinstance(rule_data, dict):
                rules[rule_id] = RuleConfig(
                    enabled=rule_data.get("enabled", True),
                    severity=rule_data.get("severity"),
                )

        custom_rules = data.get("custom_rules", [])
        ignore_paths = data.get("ignore_paths", [])
        fail_on = data.get("fail_on", "HIGH")
        auto_discover = data.get("auto_discover", True)

        return cls(
            rules=rules,
            custom_rules=custom_rules,
            ignore_paths=ignore_paths,
            fail_on=fail_on,
            auto_discover=auto_discover,
        )

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled (considering config overrides)."""
        if rule_id in self.rules:
            return self.rules[rule_id].enabled
        return True  # Default: enabled

    def get_rule_severity(self, rule_id: str, default_severity: str) -> str:
        """Get severity for a rule (config override or default)."""
        if rule_id in self.rules and self.rules[rule_id].severity:
            return self.rules[rule_id].severity or default_severity
        return default_severity

    def should_ignore(self, path: Path) -> bool:
        """Check if a path should be ignored."""
        try:
            rel_path = path.relative_to(Path.cwd())
        except ValueError:
            rel_path = path

        for pattern in self.ignore_paths:
            if rel_path.match(pattern) or path.match(pattern):
                return True
        return False