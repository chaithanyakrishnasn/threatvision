"""
Cross-layer event correlation engine.

Maintains a rolling 5-minute window of events per source IP.
Raises a correlation flag when the same source IP appears in two or more
distinct layers within the window.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


class CorrelationEngine:
    def __init__(self, window_minutes: int = 5) -> None:
        self.window_minutes = window_minutes
        # source_ip → list of (timestamp, event_id, layer)
        self.event_window: dict[str, list[tuple[datetime, str, str]]] = {}

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _parse_ts(self, event: dict) -> datetime:
        ts = event.get("timestamp")
        try:
            if isinstance(ts, str):
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if isinstance(ts, datetime):
                return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        except Exception:
            pass
        return self._now()

    def _prune(self, source_ip: str, cutoff: datetime) -> None:
        if source_ip in self.event_window:
            self.event_window[source_ip] = [
                entry for entry in self.event_window[source_ip]
                if entry[0] >= cutoff
            ]
            if not self.event_window[source_ip]:
                del self.event_window[source_ip]

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_event(self, event: dict) -> None:
        """Add an event to the rolling window, pruning stale entries."""
        source_ip = event.get("source_ip") or ""
        if not source_ip:
            return

        event_id = event.get("event_id") or ""
        layer = (event.get("layer") or event.get("event_type") or "unknown").lower()
        ts = self._parse_ts(event)
        cutoff = self._now() - timedelta(minutes=self.window_minutes)

        self._prune(source_ip, cutoff)

        if source_ip not in self.event_window:
            self.event_window[source_ip] = []
        self.event_window[source_ip].append((ts, event_id, layer))

    def check_correlation(self, event: dict) -> tuple[bool, list[str]]:
        """
        Check whether the event's source IP has appeared in at least one OTHER
        layer within the rolling window.

        Correlated = same source_ip seen in 2+ distinct layers (counting the
        current event as one of those layers).

        Returns:
            (is_correlated, correlated_event_ids)
        """
        source_ip = event.get("source_ip") or ""
        if not source_ip:
            return False, []

        cutoff = self._now() - timedelta(minutes=self.window_minutes)
        self._prune(source_ip, cutoff)

        entries = self.event_window.get(source_ip, [])
        if not entries:
            return False, []

        current_layer = (event.get("layer") or event.get("event_type") or "unknown").lower()
        current_id = event.get("event_id") or ""

        layers_seen: set[str] = set()
        correlated_ids: list[str] = []

        for _ts, eid, layer in entries:
            layers_seen.add(layer)
            if eid and eid != current_id:
                correlated_ids.append(eid)

        # Correlated if existing window already has 2+ layers, OR if the current
        # event introduces a layer not yet seen in the window
        is_correlated = len(layers_seen) >= 2 or (
            len(layers_seen) >= 1 and current_layer not in layers_seen
        )

        return is_correlated, correlated_ids

    def get_incident_cluster(self, source_ip: str) -> list[str]:
        """Return all event_ids for this source IP in the current window."""
        cutoff = self._now() - timedelta(minutes=self.window_minutes)
        self._prune(source_ip, cutoff)
        entries = self.event_window.get(source_ip, [])
        return [eid for _, eid, _ in entries if eid]


# Module-level singleton ───────────────────────────────────────────────────────

_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine
