"""Live SOC monitor with Rich Live display on stderr."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from rich.live import Live

from ..events import (
    Event,
    EventBus,
    PentestProofEvent,
    PhaseProgressEvent,
    ProxyInterceptEvent,
    RugPullDetectedEvent,
    ScanFindingEvent,
    ShieldActionEvent,
    TaintStateChangedEvent,
    get_event_bus,
)
from ..ui.console import get_console
from ..ui.renderers import LiveMonitorRenderer

if TYPE_CHECKING:
    from typing_extensions import Self

# Union type for all event types that have specific attributes
EventWithDetails = (
    ScanFindingEvent
    | ProxyInterceptEvent
    | TaintStateChangedEvent
    | RugPullDetectedEvent
    | PentestProofEvent
    | ShieldActionEvent
    | PhaseProgressEvent
)


@dataclass
class MonitorConfig:
    """Configuration for live monitor."""
    refresh_rate: float = 4.0  # Updates per second
    max_events: int = 20
    show_timestamp: bool = True
    filter_types: list[str] | None = None  # None = show all


class LiveMonitor:
    """Live SOC monitor using Rich Live on stderr."""

    def __init__(self, config: MonitorConfig | None = None) -> None:
        self.config = config or MonitorConfig()
        self.console = get_console(stderr=True)
        self.renderer = LiveMonitorRenderer(max_events=self.config.max_events)
        self._live: Live | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._bus: EventBus | None = None
        self._lock = threading.Lock()

    def start(self, event_bus: EventBus | None = None) -> None:
        """Start the live monitor."""
        with self._lock:
            if self._running:
                return

            self._bus = event_bus or get_event_bus()
            self._running = True

            # Subscribe to all event types
            event_types = [
                "ScanFindingEvent",
                "ProxyInterceptEvent",
                "TaintStateChangedEvent",
                "RugPullDetectedEvent",
                "PentestProofEvent",
                "ShieldActionEvent",
                "PhaseProgressEvent",
            ]

            for etype in event_types:
                if self.config.filter_types is None or etype in self.config.filter_types:
                    self._bus.subscribe(etype, self._on_event)

            # Start Rich Live display
            self._live = Live(
                self.renderer.render(),
                console=self.console.console,
                refresh_per_second=self.config.refresh_rate,
                transient=False,
            )
            self._live.start()

    def stop(self) -> None:
        """Stop the live monitor."""
        with self._lock:
            if not self._running:
                return

            self._running = False

            # Unsubscribe from events
            if self._bus:
                event_types = [
                    "ScanFindingEvent",
                    "ProxyInterceptEvent",
                    "TaintStateChangedEvent",
                    "RugPullDetectedEvent",
                    "PentestProofEvent",
                    "ShieldActionEvent",
                    "PhaseProgressEvent",
                ]
                for etype in event_types:
                    self._bus.unsubscribe(etype, self._on_event)

            # Stop Live display
            if self._live:
                self._live.stop()
                self._live = None

    def _on_event(self, event: Event) -> None:
        """Handle incoming event."""
        if not self._running:
            return

        # Convert event to dict for renderer
        event_dict = {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
        }

        # Add event-specific fields - use isinstance for type narrowing
        if isinstance(event, ScanFindingEvent):
            event_dict.update({
                "severity": event.severity,
                "rule_id": event.rule_id,
                "message": event.message,
            })
        elif isinstance(event, ProxyInterceptEvent):
            event_dict.update({
                "severity": "HIGH" if event.blocked else "INFO",
                "direction": event.direction,
                "method": event.method,
                "blocked": str(event.blocked),
            })
        elif isinstance(event, TaintStateChangedEvent):
            event_dict.update({
                "severity": "HIGH" if event.blocked else "MEDIUM",
                "previous_state": event.previous_state,
                "new_state": event.new_state,
                "classification": event.classification,
            })
        elif isinstance(event, RugPullDetectedEvent):
            event_dict.update({
                "severity": "CRITICAL",
                "diff_type": event.diff_type,
                "server_name": event.server_name,
            })
        elif isinstance(event, PentestProofEvent):
            event_dict.update({
                "severity": event.severity,
                "probe_id": event.probe_id,
                "target_server": event.target_server,
            })
        elif isinstance(event, ShieldActionEvent):
            event_dict.update({
                "severity": "INFO" if event.success else "HIGH",
                "action": event.action,
                "server_name": event.server_name,
            })
        elif isinstance(event, PhaseProgressEvent):
            event_dict.update({
                "severity": "INFO",
                "phase": event.phase,
                "step": event.step,
                "status": event.status,
            })

        self.renderer.add_event(event_dict)

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


class PhaseProgressTracker:
    """Track and display phase progress in live monitor."""

    def __init__(self, monitor: LiveMonitor | None = None) -> None:
        self.monitor = monitor
        self.phases: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start_phase(self, phase: str, step: str = "", message: str = "") -> None:
        """Mark phase as started."""
        with self._lock:
            self.phases[phase] = {
                "phase": phase,
                "step": step,
                "status": "started",
                "progress_pct": 0.0,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        self._emit_event()

    def update_phase(self, phase: str, step: str = "", progress_pct: float = 0.0, message: str = "") -> None:
        """Update phase progress."""
        with self._lock:
            if phase in self.phases:
                self.phases[phase].update({
                    "step": step,
                    "progress_pct": min(100.0, max(0.0, progress_pct)),
                    "message": message,
                })
        self._emit_event()

    def complete_phase(self, phase: str, message: str = "") -> None:
        """Mark phase as completed."""
        with self._lock:
            if phase in self.phases:
                self.phases[phase].update({
                    "status": "completed",
                    "progress_pct": 100.0,
                    "message": message,
                })
        self._emit_event()

    def fail_phase(self, phase: str, message: str = "") -> None:
        """Mark phase as failed."""
        with self._lock:
            if phase in self.phases:
                self.phases[phase].update({
                    "status": "failed",
                    "message": message,
                })
        self._emit_event()

    def _emit_event(self) -> None:
        """Emit phase progress events."""
        if not self.monitor or not self.monitor._bus:
            return

        from ..events import PhaseProgressEvent

        with self._lock:
            for phase_data in self.phases.values():
                event = PhaseProgressEvent(
                    phase=phase_data["phase"],
                    step=phase_data["step"],
                    status=phase_data["status"],
                    progress_pct=phase_data["progress_pct"],
                    message=phase_data["message"],
                )
                self.monitor._bus.publish(event)


def create_live_monitor(
    refresh_rate: float = 4.0,
    max_events: int = 20,
    filter_types: list[str] | None = None,
) -> LiveMonitor:
    """Factory function to create a configured live monitor."""
    config = MonitorConfig(
        refresh_rate=refresh_rate,
        max_events=max_events,
        filter_types=filter_types,
    )
    return LiveMonitor(config)