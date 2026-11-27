"""AegisMCP - Security scanner for MCP configurations and AI agent tools."""

from .ast_scanner import ASTFinding, scan_python_directory, scan_python_file
from .cli import main
from .config import Config
from .discovery import discover_mcp_files, get_config_paths
from .html_report import HTMLReportOptions, save_html_report
from .lockfile import (
    Lockfile,
    create_lock_from_config,
    update_lockfile_with_tools,
    verify_lockfile,
    verify_tools,
)
from .rules.registry import Rule, registry
from .rules_core import Finding
from .sarif import export_sarif
from .scanner import scan_directory, scan_file

__version__ = "3.2.8"
__all__ = [
    "ASTFinding",
    "Config",
    "Finding",
    "HTMLReportOptions",
    "Lockfile",
    "Rule",
    "create_lock_from_config",
    "create_lockfile_from_config",
    "discover_mcp_files",
    "export_sarif",
    "get_config_paths",
    "main",
    "registry",
    "save_html_report",
    "scan_directory",
    "scan_file",
    "scan_python_directory",
    "scan_python_file",
    "update_lockfile_with_tools",
    "verify_lockfile",
    "verify_tools",
]