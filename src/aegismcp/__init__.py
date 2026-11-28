"""AegisMCP - Security scanner for MCP configurations and AI agent tools."""

from .ast_scanner import ASTFinding, scan_python_directory, scan_python_file
from .cli import main
from .config import Config
from .discovery import discover_mcp_files, get_config_paths
from .events import (
    Event,
    EventBus,
    JsonlEventSink,
    PentestProofEvent,
    PhaseProgressEvent,
    ProxyInterceptEvent,
    RugPullDetectedEvent,
    ScanFindingEvent,
    ShieldActionEvent,
    TaintStateChangedEvent,
    get_event_bus,
)
from .html_report import HTMLReportOptions, save_html_report
from .lockfile import (
    Lockfile,
    create_lock_from_config,
    update_lockfile_with_tools,
    verify_lockfile,
    verify_tools,
)
from .proxy_policy import PromptInjectionConfig, ProxyPolicy
from .rules.registry import Rule, registry
from .rules_core import Finding
from .sarif import export_sarif
from .scanner import scan_directory, scan_file
from .taint_firewall import (
    HIGH_RISK_SINK_TOOLS,
    SecretFingerprint,
    TaintFirewall,
    TaintState,
)
from .ui import (
    ASCII_GLYPHS,
    UNICODE_GLYPHS,
    CodeFrameData,
    CodeFrameRenderer,
    ExecutiveHeaderRenderer,
    GlyphSet,
    LiveMonitor,
    LiveMonitorRenderer,
    PhaseProgressData,
    PhaseProgressRenderer,
    PhaseProgressTracker,
    RiskGaugeData,
    RugPullDiffData,
    RugPullDiffRenderer,
    SmartConsole,
    get_console,
    render_finding_compact,
)

__version__ = "4.0.0"
__all__ = [
    "ASCII_GLYPHS",
    "HIGH_RISK_SINK_TOOLS",
    "UNICODE_GLYPHS",
    "ASTFinding",
    "CodeFrameData",
    "CodeFrameRenderer",
    "Config",
    "Event",
    "EventBus",
    "ExecutiveHeaderRenderer",
    "Finding",
    "GlyphSet",
    "HTMLReportOptions",
    "JsonlEventSink",
    "LiveMonitor",
    "LiveMonitorRenderer",
    "Lockfile",
    "PentestProofEvent",
    "PhaseProgressData",
    "PhaseProgressEvent",
    "PhaseProgressRenderer",
    "PhaseProgressTracker",
    "PromptInjectionConfig",
    "ProxyInterceptEvent",
    "ProxyPolicy",
    "RiskGaugeData",
    "RugPullDetectedEvent",
    "RugPullDiffData",
    "RugPullDiffRenderer",
    "Rule",
    "ScanFindingEvent",
    "SecretFingerprint",
    "ShieldActionEvent",
    "SmartConsole",
    "TaintFirewall",
    "TaintState",
    "TaintStateChangedEvent",
    "create_lock_from_config",
    "discover_mcp_files",
    "export_sarif",
    "get_config_paths",
    "get_console",
    "get_event_bus",
    "main",
    "registry",
    "render_finding_compact",
    "save_html_report",
    "scan_directory",
    "scan_file",
    "scan_python_directory",
    "scan_python_file",
    "update_lockfile_with_tools",
    "verify_lockfile",
    "verify_tools",
]