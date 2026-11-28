"""Proxy policy configuration for runtime firewall."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    import types
    yaml = types.SimpleNamespace()  # type: ignore[assignment]
    YAML_AVAILABLE = False


@dataclass
class PromptInjectionConfig:
    """Config for prompt injection scoring."""
    mode: str = "balanced"  # "strict" or "balanced"
    custom_patterns: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ProxyPolicy:
    """Policy configuration for MCP Proxy."""
    mode: str = "enforce"
    fail_on: str = "HIGH"
    prompt_injection: PromptInjectionConfig = field(default_factory=PromptInjectionConfig)
    response_scanning: bool = True
    audit_log: str | None = None
    rate_limit: int = 100

    @classmethod
    def load(cls, path: Path) -> ProxyPolicy:
        """Load policy from YAML file."""
        if not path.exists() or not YAML_AVAILABLE:
            return cls()

        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}  # type: ignore[union-attr]

            # Parse injection config
            inj_data = data.get("prompt_injection", {})
            inj_config = PromptInjectionConfig(
                mode=inj_data.get("mode", "balanced"),
                custom_patterns=inj_data.get("custom_patterns", []),
            )

            return cls(
                mode=data.get("mode", "enforce"),
                fail_on=data.get("fail_on", "HIGH"),
                prompt_injection=inj_config,
                response_scanning=data.get("response_scanning", True),
                audit_log=data.get("audit_log"),
                rate_limit=data.get("rate_limit", 100),
            )
        except Exception:  # noqa: BLE001
            return cls()
