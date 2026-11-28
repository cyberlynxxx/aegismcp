"""AegisMCP UI package - Professional terminal interface components."""

from __future__ import annotations

from .console import (
    ASCII_GLYPHS,
    UNICODE_GLYPHS,
    GlyphSet,
    SmartConsole,
    _is_cp1252_terminal,
    _is_piped_or_ci,
    get_console,
    set_console,
)
from .live_monitor import (
    LiveMonitor,
    MonitorConfig,
    PhaseProgressTracker,
    create_live_monitor,
)
from .renderers import (
    CodeFrameData,
    CodeFrameRenderer,
    ExecutiveHeaderRenderer,
    LiveMonitorRenderer,
    PhaseProgressData,
    PhaseProgressRenderer,
    RiskGaugeData,
    RugPullDiffData,
    RugPullDiffRenderer,
    render_finding_compact,
)

__all__ = [
    # Console
    "ASCII_GLYPHS",
    "UNICODE_GLYPHS",
    "CodeFrameData",
    "CodeFrameRenderer",
    "ExecutiveHeaderRenderer",
    "GlyphSet",
    "LiveMonitor",
    "LiveMonitorRenderer",
    "MonitorConfig",
    "PhaseProgressData",
    "PhaseProgressRenderer",
    "PhaseProgressTracker",
    "RiskGaugeData",
    "RugPullDiffData",
    "RugPullDiffRenderer",
    "SmartConsole",
    "_is_cp1252_terminal",
    "_is_piped_or_ci",
    "create_live_monitor",
    "get_console",
    "render_finding_compact",
    "set_console",
]