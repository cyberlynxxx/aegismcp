"""Professional renderers for AegisMCP v4.0.0 UI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from ..ui.console import GlyphSet


@dataclass
class RiskGaugeData:
    """Data for risk gauge display."""
    score: int  # 0-100
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


@dataclass
class CodeFrameData:
    """Data for code frame rendering."""
    file_path: str
    line_start: int
    line_end: int
    highlighted_line: int
    code_lines: list[str]
    rule_id: str = ""
    severity: str = ""
    message: str = ""


@dataclass
class RugPullDiffData:
    """Data for git-style rug-pull diff."""
    server_name: str
    diff_type: str  # tool_added, tool_removed, tool_changed, schema_drift, config_changed, stealth_unicode_injected
    old_content: str = ""
    new_content: str = ""
    old_hash: str = ""
    new_hash: str = ""


@dataclass
class PhaseProgressData:
    """Data for phase progress timeline."""
    phase: str
    step: str
    status: str  # started, completed, failed
    progress_pct: float = 0.0
    message: str = ""
    timestamp: str = ""


class ExecutiveHeaderRenderer:
    """Executive header with risk gauge for scan/proxy/pentest output."""

    def __init__(self, glyphs: GlyphSet | None = None) -> None:
        self.glyphs = glyphs or GlyphSet()

    def render(self, data: RiskGaugeData, title: str = "AegisMCP Security Scan") -> Panel:
        """Render executive header panel."""
        # Risk level determination
        if data.critical > 0:
            risk_level = "CRITICAL"
            risk_style = Style(color="red", bold=True)
            gauge_color = "red"
        elif data.high > 0:
            risk_level = "HIGH"
            risk_style = Style(color="red", bold=True)
            gauge_color = "red"
        elif data.medium > 0:
            risk_level = "MEDIUM"
            risk_style = Style(color="yellow", bold=True)
            gauge_color = "yellow"
        elif data.low > 0:
            risk_level = "LOW"
            risk_style = Style(color="blue", bold=True)
            gauge_color = "blue"
        else:
            risk_level = "CLEAN"
            risk_style = Style(color="green", bold=True)
            gauge_color = "green"

        # Build gauge bar
        gauge_width = 40
        filled = int((data.score / 100) * gauge_width)
        gauge_bar = "█" * filled + "░" * (gauge_width - filled)

        # Create content
        content = Table.grid(padding=(0, 2))
        content.add_column(justify="left")
        content.add_column(justify="right")

        # Left side: title and risk level
        left_text = Text()
        left_text.append(f"{self.glyphs.block} ", style="bold")
        left_text.append(title, style="bold white")
        left_text.append("\n")
        left_text.append("Risk Level: ", style="dim")
        left_text.append(risk_level, risk_style)

        # Right side: gauge and stats
        right_text = Text()
        right_text.append(f"Score: {data.score}/100\n", style="bold")
        right_text.append(f"{gauge_bar} {data.score}%\n", style=gauge_color)
        right_text.append(f"Findings: {data.total} ", style="dim")
        if data.critical:
            right_text.append(f"🔴 {data.critical}C ", style="red")
        if data.high:
            right_text.append(f"🟠 {data.high}H ", style="orange3")
        if data.medium:
            right_text.append(f"🟡 {data.medium}M ", style="yellow")
        if data.low:
            right_text.append(f"🔵 {data.low}L ", style="blue")

        content.add_row(left_text, right_text)

        return Panel(
            content,
            box=HEAVY,
            border_style="bright_blue",
            padding=(1, 2),
            title=f"[{self.glyphs.check}] AegisMCP v4.0.0",
            title_align="left",
        )


class CodeFrameRenderer:
    """Code frame renderer for scan/ast-scan/pentest findings."""

    def __init__(self, glyphs: GlyphSet | None = None, context_lines: int = 3) -> None:
        self.glyphs = glyphs or GlyphSet()
        self.context_lines = context_lines

    def render(self, data: CodeFrameData) -> Panel:
        """Render code frame with highlighted finding."""
        # Build line numbers and code
        table = Table(box=None, show_header=False, padding=(0, 1))
        table.add_column("line", style="dim", width=6, justify="right")
        table.add_column("marker", width=2, justify="center")
        table.add_column("code", style="white", no_wrap=False)

        start_idx = max(0, data.highlighted_line - data.line_start - self.context_lines)
        end_idx = min(len(data.code_lines), data.highlighted_line - data.line_start + self.context_lines + 1)

        for i in range(start_idx, end_idx):
            line_num = data.line_start + i + 1
            code = data.code_lines[i].rstrip("\n")
            is_highlighted = (line_num == data.highlighted_line)

            if is_highlighted:
                marker = Text(f"{self.glyphs.arrow}", style="bold red")
                line_style = Style(color="white", bgcolor="red", bold=True)
                code_style = Style(color="white", bgcolor="red", bold=True)
            else:
                marker = Text("")
                line_style = Style(dim=True)
                code_style = Style(color="white")

            table.add_row(
                Text(str(line_num), style=line_style),
                marker,
                Text(code, style=code_style),
            )

        # Header info
        header = Text()
        header.append(f"{self.glyphs.bullet} ", style="dim")
        header.append(f"{data.file_path}", style="bold underline")
        header.append(f":{data.highlighted_line}", style="bold")
        if data.rule_id:
            header.append(f"  [{data.rule_id}]", style="bold red")
        if data.severity:
            header.append(f" {data.severity}", style=self._severity_style(data.severity))
        header.append(f"\n{self.glyphs.bullet} {data.message}", style="dim")

        return Panel(
            table,
            title=header,
            border_style="yellow",
            box=ROUNDED,
            padding=(1, 1),
        )

    def _severity_style(self, severity: str) -> Style:
        styles = {
            "CRITICAL": Style(color="red", bold=True),
            "HIGH": Style(color="orange3", bold=True),
            "MEDIUM": Style(color="yellow", bold=True),
            "LOW": Style(color="blue", bold=True),
        }
        return styles.get(severity.upper(), Style())


class RugPullDiffRenderer:
    """Git-style unified diff renderer for rug-pull detection."""

    def __init__(self, glyphs: GlyphSet | None = None, context_lines: int = 3) -> None:
        self.glyphs = glyphs or GlyphSet()
        self.context_lines = context_lines

    def render(self, data: RugPullDiffData) -> Panel:
        """Render git-style diff panel."""
        diff_lines = self._generate_diff(data)

        # Build diff table
        table = Table(box=None, show_header=False, padding=(0, 1))
        table.add_column("marker", width=2, justify="center")
        table.add_column("line", style="dim", width=6, justify="right")
        table.add_column("content", style="white", no_wrap=False)

        for line_type, line_num, content in diff_lines:
            if line_type == "remove":
                marker = Text("-", style="bold red")
                line_style = Style(color="red")
                content_style = Style(color="red")
            elif line_type == "add":
                marker = Text("+", style="bold green")
                line_style = Style(color="green")
                content_style = Style(color="green")
            elif line_type == "context":
                marker = Text(" ")
                line_style = Style(color="dim")
                content_style = Style(color="white")
            else:  # header
                marker = Text("")
                line_style = Style(color="cyan", bold=True)
                content_style = Style(color="cyan", bold=True)

            line_str = str(line_num) if line_num > 0 else ""
            table.add_row(marker, Text(line_str, style=line_style), Text(content, style=content_style))

        # Diff type badge
        type_labels = {
            "tool_added": "TOOL ADDED",
            "tool_removed": "TOOL REMOVED",
            "tool_changed": "TOOL CHANGED",
            "schema_drift": "SCHEMA DRIFT",
            "config_changed": "CONFIG CHANGED",
            "stealth_unicode_injected": "STEALTH UNICODE INJECTED",
        }
        diff_label = type_labels.get(data.diff_type, data.diff_type.upper())

        header = Text()
        header.append(f"{self.glyphs.warning} RUG-PULL DETECTED: ", style="bold red")
        header.append(f"{diff_label}", style="bold white on red")
        header.append(f" in {data.server_name}", style="dim")
        if data.old_hash and data.new_hash:
            header.append(f"\n{self.glyphs.bullet} Old: {data.old_hash[:16]}...", style="dim")
            header.append(f"  New: {data.new_hash[:16]}...", style="dim")

        return Panel(
            table,
            title=header,
            border_style="red",
            box=HEAVY,
            padding=(1, 1),
        )

    def _generate_diff(self, data: RugPullDiffData) -> list[tuple]:
        """Generate unified diff lines."""
        old_lines = data.old_content.splitlines() if data.old_content else []
        new_lines = data.new_content.splitlines() if data.new_content else []

        # Simple diff algorithm - find common prefix/suffix
        prefix_len = 0
        while prefix_len < len(old_lines) and prefix_len < len(new_lines):
            if old_lines[prefix_len] == new_lines[prefix_len]:
                prefix_len += 1
            else:
                break

        suffix_len = 0
        while suffix_len < len(old_lines) - prefix_len and suffix_len < len(new_lines) - prefix_len:
            if old_lines[-(suffix_len + 1)] == new_lines[-(suffix_len + 1)]:
                suffix_len += 1
            else:
                break

        diff = []

        # Context before changes
        context_start = max(0, prefix_len - self.context_lines)
        for i in range(context_start, prefix_len):
            diff.append(("context", i + 1, old_lines[i]))

        # Removed lines
        for i in range(prefix_len, len(old_lines) - suffix_len):
            diff.append(("remove", i + 1, old_lines[i]))

        # Added lines
        for i in range(prefix_len, len(new_lines) - suffix_len):
            diff.append(("add", i + 1, new_lines[i]))

        # Context after changes
        for i in range(len(new_lines) - suffix_len, min(len(new_lines), len(new_lines) - suffix_len + self.context_lines)):
            diff.append(("context", i + 1, new_lines[i]))

        return diff


class PhaseProgressRenderer:
    """Phase progress timeline renderer."""

    def __init__(self, glyphs: GlyphSet | None = None) -> None:
        self.glyphs = glyphs or GlyphSet()

    def render(self, phases: list[PhaseProgressData]) -> Panel:
        """Render phase progress timeline."""
        table = Table(box=SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("Phase", style="bold", width=20)
        table.add_column("Step", width=30)
        table.add_column("Status", width=12, justify="center")
        table.add_column("Progress", width=15)
        table.add_column("Message", style="dim")

        for phase in phases:
            status_text = self._status_text(phase.status)
            progress_bar = self._progress_bar(phase.progress_pct)

            table.add_row(
                phase.phase,
                phase.step,
                status_text,
                progress_bar,
                phase.message,
            )

        return Panel(
            table,
            title=f"{self.glyphs.bullet} Phase Progress Timeline",
            border_style="blue",
            box=ROUNDED,
            padding=(1, 1),
        )

    def _status_text(self, status: str) -> Text:
        styles = {
            "started": Text(f"{self.glyphs.arrow} RUNNING", style="bold yellow"),
            "completed": Text(f"{self.glyphs.check} DONE", style="bold green"),
            "failed": Text(f"{self.glyphs.cross} FAILED", style="bold red"),
        }
        return styles.get(status, Text(status, style="dim"))

    def _progress_bar(self, pct: float) -> Text:
        width = 12
        filled = int((pct / 100) * width)
        bar = "█" * filled + "░" * (width - filled)
        return Text(f"{bar} {pct:.0f}%", style="cyan")


class LiveMonitorRenderer:
    """Live SOC monitor renderer for real-time event display."""

    def __init__(self, glyphs: GlyphSet | None = None, max_events: int = 20) -> None:
        self.glyphs = glyphs or GlyphSet()
        self.max_events = max_events
        self._events: list[dict[str, Any]] = []

    def add_event(self, event_data: dict[str, Any]) -> None:
        """Add event to monitor."""
        self._events.append(event_data)
        if len(self._events) > self.max_events:
            self._events.pop(0)

    def render(self) -> Panel:
        """Render live monitor panel."""
        table = Table(box=SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("Time", style="dim", width=10)
        table.add_column("Type", style="bold", width=25)
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Details", style="white")

        for event in self._events[-self.max_events:]:
            timestamp = event.get("timestamp", "")[:19].replace("T", " ")
            event_type = event.get("event_type", "")
            severity = event.get("severity", "")
            details = self._format_details(event)

            sev_style = self._severity_style(severity)
            table.add_row(
                Text(timestamp, style="dim"),
                Text(event_type, style="cyan"),
                Text(severity, style=sev_style),
                Text(details, style="white"),
            )

        return Panel(
            table,
            title=f"{self.glyphs.block} Live SOC Monitor",
            border_style="green",
            box=HEAVY,
            padding=(1, 1),
        )

    def _severity_style(self, severity: str) -> Style:
        styles = {
            "CRITICAL": Style(color="red", bold=True),
            "HIGH": Style(color="orange3", bold=True),
            "MEDIUM": Style(color="yellow", bold=True),
            "LOW": Style(color="blue", bold=True),
            "INFO": Style(color="green"),
        }
        return styles.get(severity.upper(), Style())

    def _format_details(self, event: dict[str, Any]) -> str:
        """Format event details for display."""
        etype = event.get("event_type", "")
        if etype == "ScanFindingEvent":
            return f"{event.get('rule_id', '')}: {event.get('message', '')[:60]}"
        elif etype == "ProxyInterceptEvent":
            return f"{event.get('direction', '')} {event.get('method', '')} {'BLOCKED' if event.get('blocked') else 'ALLOWED'}"
        elif etype == "TaintStateChangedEvent":
            return f"{event.get('previous_state', '')} -> {event.get('new_state', '')} ({event.get('classification', '')})"
        elif etype == "RugPullDetectedEvent":
            return f"{event.get('diff_type', '')} in {event.get('server_name', '')}"
        elif etype == "PentestProofEvent":
            return f"{event.get('probe_id', '')} on {event.get('target_server', '')}"
        elif etype == "ShieldActionEvent":
            return f"{event.get('action', '')} {event.get('server_name', '')}"
        return str(event)[:80]


def render_finding_compact(finding: dict[str, Any], glyphs: GlyphSet | None = None) -> Text:
    """Render a finding in compact single-line format."""
    g = glyphs or GlyphSet()
    text = Text()
    severity = finding.get("severity", "UNKNOWN")
    sev_style = {
        "CRITICAL": Style(color="red", bold=True),
        "HIGH": Style(color="orange3", bold=True),
        "MEDIUM": Style(color="yellow", bold=True),
        "LOW": Style(color="blue", bold=True),
    }.get(severity, Style())
    text.append(f"{g.bullet} ", style="dim")
    text.append(f"[{severity}] ", style=sev_style)
    text.append(f"{finding.get('rule_id', '')}: ", style="bold")
    text.append(f"{finding.get('message', '')[:80]}", style="white")
    if finding.get("file_path"):
        text.append(f" ({finding['file_path']}:{finding.get('line', 0)})", style="dim")
    return text