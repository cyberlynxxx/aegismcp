"""EventBus and typed event dataclasses for AegisMCP v4.0.0."""

from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, TextIO
from uuid import uuid4

if TYPE_CHECKING:
    from typing_extensions import Self


@dataclass
class Event:
    """Base event class with common fields."""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = ""

    def to_json(self) -> str:
        """Serialize event to JSON string."""
        return json.dumps(asdict(self), separators=(',', ':'), sort_keys=True)


@dataclass
class ScanFindingEvent(Event):
    """Event emitted when a security finding is discovered during scanning."""
    event_type: str = "ScanFindingEvent"
    rule_id: str = ""
    severity: str = ""
    message: str = ""
    file_path: str = ""
    line: int = 0
    column: int = 0
    tool_name: str = ""
    server_name: str = ""
    finding_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyInterceptEvent(Event):
    """Event emitted when the proxy intercepts a request/response."""
    event_type: str = "ProxyInterceptEvent"
    direction: str = ""  # "request" or "response"
    client_id: str = ""
    client_ip: str = ""
    server_name: str = ""
    method: str = ""
    session_id: str = ""  # For taint tracking
    blocked: bool = False
    rule_id: str = ""
    reason: str = ""
    payload_preview: str = ""


@dataclass
class TaintStateChangedEvent(Event):
    """Event emitted when taint state transitions."""
    event_type: str = "TaintStateChangedEvent"
    session_id: str = ""
    source: str = ""
    sink: str = ""
    previous_state: str = ""
    new_state: str = ""
    classification: str = ""
    strike_count: int = 0
    blocked: bool = False


@dataclass
class RugPullDetectedEvent(Event):
    """Event emitted when a rug-pull (supply chain attack) is detected."""
    event_type: str = "RugPullDetectedEvent"
    server_name: str = ""
    diff_type: str = ""  # tool_added, tool_removed, tool_changed, schema_drift, config_changed, stealth_unicode_injected
    old_hash: str = ""
    new_hash: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PentestProofEvent(Event):
    """Event emitted when a pentest probe succeeds."""
    event_type: str = "PentestProofEvent"
    probe_id: str = ""
    target_server: str = ""
    parameter_type: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = ""


@dataclass
class ShieldActionEvent(Event):
    """Event emitted when shield/unshield takes action."""
    event_type: str = "ShieldActionEvent"
    action: str = ""  # "wrap", "unwrap", "backup", "policy_update"
    config_path: str = ""
    server_name: str = ""
    success: bool = True
    message: str = ""


@dataclass
class PhaseProgressEvent(Event):
    """Event emitted for phase progress tracking."""
    event_type: str = "PhaseProgressEvent"
    phase: str = ""
    step: str = ""
    status: str = ""  # "started", "completed", "failed"
    message: str = ""
    progress_pct: float = 0.0


class JsonlEventSink:
    """JSON Lines event sink with immediate flush for --events-log."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self._file: TextIO | None = None
        self._lock = threading.Lock()

    def __enter__(self) -> Self:
        self._file = open(self.filepath, "a", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def write(self, event: Event) -> None:
        """Write event as a single JSON line with immediate flush."""
        with self._lock:
            if self._file:
                self._file.write(event.to_json() + "\n")
                self._file.flush()


class EventBus:
    """Thread-safe event bus with bounded ring buffer and resilient error handling."""

    def __init__(self, max_buffer_size: int = 1000) -> None:
        self._subscribers: dict[str, list[Callable[[Event], None]]] = {}
        self._lock = threading.RLock()
        self._buffer: deque[Event] = deque(maxlen=max_buffer_size)
        self._sinks: list[JsonlEventSink] = []

    def subscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        """Subscribe to an event type."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable[[Event], None]) -> bool:
        """Unsubscribe from an event type. Returns True if removed."""
        with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(callback)
                    if not self._subscribers[event_type]:
                        del self._subscribers[event_type]
                    return True
                except ValueError:
                    return False
            return False

    def publish(self, event: Event) -> None:
        """Publish an event to all subscribers and sinks."""
        # Add to ring buffer
        with self._lock:
            self._buffer.append(event)

        # Deliver to subscribers (outside lock to avoid deadlock)
        subscribers = []
        with self._lock:
            if event.event_type in self._subscribers:
                subscribers = list(self._subscribers[event.event_type])

        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # noqa: BLE001, S110
                # Resilient error handling - log but don't crash
                pass

        # Write to sinks
        for sink in self._sinks:
            try:
                sink.write(event)
            except Exception:  # noqa: BLE001, S110
                pass

    def add_sink(self, sink: JsonlEventSink) -> None:
        """Add a JSONL sink for event logging."""
        with self._lock:
            self._sinks.append(sink)

    def remove_sink(self, sink: JsonlEventSink) -> bool:
        """Remove a sink."""
        with self._lock:
            try:
                self._sinks.remove(sink)
                return True
            except ValueError:
                return False

    def get_recent(self, event_type: str | None = None, limit: int = 100) -> list[Event]:
        """Get recent events from buffer."""
        with self._lock:
            events = list(self._buffer)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def clear_buffer(self) -> None:
        """Clear the event buffer."""
        with self._lock:
            self._buffer.clear()


# Global event bus instance
_global_bus: EventBus | None = None
_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Get or create the global event bus."""
    global _global_bus
    with _bus_lock:
        if _global_bus is None:
            _global_bus = EventBus()
        return _global_bus


def set_event_bus(bus: EventBus) -> None:
    """Set the global event bus (for testing)."""
    global _global_bus
    with _bus_lock:
        _global_bus = bus