"""Rule registry for built-in and custom rules."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..rules_core import Finding


@dataclass
class Rule:
    """A security rule definition."""
    rule_id: str
    severity: str
    title: str
    description: str
    remediation: str
    # Function that takes (data, location) and returns list[Finding]
    check_fn: Callable[[dict[str, Any], str], list[Finding]] | None = None


class RuleRegistry:
    """Registry for all security rules."""

    def __init__(self):
        self._rules: dict[str, Rule] = {}
        self._custom_rules: list[dict[str, Any]] = []

    def register(self, rule: Rule) -> None:
        """Register a built-in rule."""
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> bool:
        """Unregister a rule by ID."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def get(self, rule_id: str) -> Rule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def all(self) -> list[Rule]:
        """Get all registered rules."""
        return list(self._rules.values())

    def enabled_rules(self, config_rules: dict[str, Any]) -> list[Rule]:
        """Get rules that are enabled according to config."""
        result = []
        for rule in self._rules.values():
            if rule.rule_id in config_rules:
                rule_config = config_rules[rule.rule_id]
                if isinstance(rule_config, bool) and not rule_config or isinstance(rule_config, dict) and not rule_config.get("enabled", True):
                    continue
            result.append(rule)
        return result

    def add_custom_rules(self, custom_rules: list[dict[str, Any]]) -> None:
        """Add custom regex-based rules from config."""
        self._custom_rules = custom_rules

    def get_custom_rules(self) -> list[dict[str, Any]]:
        """Get custom rules."""
        return self._custom_rules


# Global registry instance
registry = RuleRegistry()