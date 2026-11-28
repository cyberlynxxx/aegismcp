"""Taint Firewall integration and event bus setup."""

from __future__ import annotations

from .events import ProxyInterceptEvent, TaintStateChangedEvent, get_event_bus
from .taint_firewall import TaintFirewall

# Global firewall
_firewall: TaintFirewall | None = None


def get_firewall() -> TaintFirewall:
    """Get global taint firewall."""
    global _firewall
    if _firewall is None:
        _firewall = TaintFirewall()
    return _firewall


def handle_taint_event(event: TaintStateChangedEvent) -> None:
    """Handle taint events from the event bus."""
    firewall = get_firewall()
    session_id = event.session_id

    # Update taint state - event.new_state is a string (e.g., "TAINTED")
    is_tainted = event.new_state == "TAINTED"
    updated_state = firewall.update_taint(session_id,
        is_tainted=is_tainted,
        classification=event.classification)

    # Convert updated state to string for event
    state_str = updated_state.name  # "CLEAN", "TAINTED", or "QUARANTINED"

    # Get strike count for the updated event
    session = firewall.get_session(session_id)
    strike_count = session.strikes if session else 0

    # Publish updated state - use string type to match Event dataclass
    updated_event = TaintStateChangedEvent(
        event_type="TaintStateChangedEvent",
        session_id=session_id,
        previous_state=event.previous_state,
        new_state=state_str,
        classification=event.classification,
        strike_count=strike_count
    )
    get_event_bus().publish(updated_event)


def initialize_taint_monitoring() -> None:
    """Initialize taint monitoring with the event bus."""
    bus = get_event_bus()
    bus.subscribe("TaintStateChangedEvent", handle_taint_event)  # type: ignore[arg-type]

    # Also subscribe to ProxyInterceptEvent to detect tainted data flows
    bus.subscribe("ProxyInterceptEvent", _handle_proxy_intercept)  # type: ignore[arg-type]


def _handle_proxy_intercept(event: ProxyInterceptEvent) -> None:
    """Handle proxy intercept events for taint detection."""
    firewall = get_firewall()

    # Check if this is a response with potentially sensitive data
    if event.direction == "response" and event.method in ["tools/call", "resources/read"]:
        # Extract relevant data from payload
        payload = event.payload_preview if event.payload_preview else ""

        # Analyze data flow for secret exfiltration
        is_tainted, classifications = firewall.analyze_data_flow(event.session_id, payload)

        # If secrets detected, mark session as tainted
        if is_tainted and classifications:
            # Create a taint event with classification
            taint_event = TaintStateChangedEvent(
                event_type="TaintStateChangedEvent",
                session_id=event.session_id,
                previous_state="CLEAN",  # Default to clean if no previous state
                new_state="TAINTED",
                classification=", ".join(classifications),  # Combine classifications
                strike_count=0  # Reset strike count for new taint detection
            )
            get_event_bus().publish(taint_event)