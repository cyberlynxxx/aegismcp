"""AegisMCP - Security scanner for MCP configurations and AI agent tools."""

from .cli import main
from .config import Config
from .scanner import scan_file, scan_directory
from .discovery import discover_mcp_files, get_config_paths
from .lockfile import (
    Lockfile,
    create_lock_from_config,
    verify_lockfile,
    update_lockfile_with_tools,
    verify_tools,
)
from .ast_scanner import scan_python_file, scan_python_directory, ASTFinding
from .rules_core import Finding
from .rules.registry import registry, Rule
from .sarif import export_sarif

__version__ = "2.0.0"
__all__ = [
    "main",
    "Config",
    "scan_file",
    "scan_directory",
    "discover_mcp_files",
    "get_config_paths",
    "Lockfile",
    "create_lockfile_from_config",
    "verify_lockfile",
    "update_lockfile_with_tools",
    "verify_tools",
    "scan_python_file",
    "scan_python_directory",
    "ASTFinding",
    "Finding",
    "registry",
    "Rule",
    "export_sarif",
]