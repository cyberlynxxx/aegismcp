"""Rules package for AegisMCP."""
from __future__ import annotations

from .builtins import register_builtins

# Auto-register built-in rules on import
register_builtins()

from .registry import Rule, registry

__all__ = ["Rule", "registry"]