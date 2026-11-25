"""Built-in security rules for AegisMCP.

This module re-exports all built-in rules from their domain-specific modules:
- config_rules.py: Configuration file scanning (AMCP001-008)
- ast_rules.py: AST-based Python code scanning (AMCP101-105)
- cross_rules.py: Cross-server analysis (AMCP201-203)
- proxy_rules.py: Proxy/runtime security (AMCP301-309)
"""
from __future__ import annotations

from ..registry import registry
from .ast_rules import AST_RULES
from .config_rules import CONFIG_RULES
from .cross_rules import CROSS_SERVER_RULES
from .proxy_rules import PROXY_RULES


def register_builtins() -> None:
    """Register all built-in rules with the global registry."""
    all_rules = CONFIG_RULES + AST_RULES + CROSS_SERVER_RULES + PROXY_RULES
    for rule in all_rules:
        registry.register(rule)


# Auto-register on import
register_builtins()

# Export rule lists for external access
__all__ = [
    "AST_RULES",
    "CONFIG_RULES",
    "CROSS_SERVER_RULES",
    "PROXY_RULES",
    "register_builtins",
]