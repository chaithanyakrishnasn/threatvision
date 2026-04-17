"""
Redis stream producer/consumer for ThreatVision event ingestion.

EventProducer  — XADD events to "threatvision:events" stream
EventConsumer  — XREADGROUP, classify, broadcast; DLQ on failure
ThroughputMonitor — rolling EPS stats logged every 10 s
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import deque
from typing import Callable, Optional

import redis.asyncio as aioredis
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)

STREAM_KEY  = "threatvision:events"
DLQ_KEY     = "threatvision:dlq"
CONSUMER_GROUP = "threatvision-consumers"
BATCH_SIZE  = 100   # messages per XREADGROUP call
BLOCK_MS    = 1000  # ms to block if stream is empty


# ── ThroughputMonitor ─────────────────────────────────────────────────────────

class ThroughputMonitor:
    """
    Rolling-window events-per-second tracker.
    Logs stats every `log_interval` seconds via structlog.
    """

    def __init__(self, log_interval: int = 10, window: int = 60) -> None:
        self._log_interval = log_interval
        self._window = window
        self._timestamps: deque[float] = deque()
        self._total = 0
        self._last_log = time.monotonic()
        self._errors = 0
        self._dlq = 0

    def record(self, count: int = 1) -> None:
        now = time.monotonic()
        for _ in range(count):
            self._timestamps.append(now)
        self._total += count
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        if now - self._last_log >= self._log_interval:
            self._emit()
            self._last_log = now

    def record_error(self) -> None:
        self._errors += 1

    def record_dlq(self) -> None:
        self._dlq += 1

    @property
    def current_eps(self) -> float:
        if not self._timestamps:
            return 0.0
        span = time.monotonic() - self._timestamps[0]
        return len(self._timestamps) / max(span, 0.001)

    def _emit(self) -> None:
        logger.info(
            "ingestion_throughput",
            eps=round(self.current_eps, 1),
            total=self._total,
            errors=self._errors,
            dlq=self._dlq,
        )

    def summary(self) -> dict:
        return {
            "eps": round(self.current_eps, 1),
            "total_processed": self._total,
            "errors": self._errors,
            "dlq_events": self._dlq,
        }


# ── EventProducer ─────────────────────────────────────────────────────────────

class EventProducer:
    """
    Non-blocking Redis stream producer.
    Uses pipelining for batch publishes to sustain 600+ events/sec.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self._url = redis_url or get_settings().redis_url
        self._client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        self._client = aioredis.from_url(
            self._url,
            decode_responses=True,
            max_connections=20,
        )
        # Verify connectivity
        await self._client.ping()
        logger.info("producer_connected", url=self._url)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _ensure(self) -> aioredis.Redis:
        if not self._client:
            await self.connect()
        return self._client  # type: ignore[return-value]

    async def publish_single(self, event: dict) -> str:
        """XADD one event. Returns the Redis message ID."""
        r = await self._ensure()
        payload = json.dumps(event, default=str)
        msg_id = await r.xadd(STREAM_KEY, {"data": payload})
        return msg_id

    async def publish_batch(self, events: list[dict]) -> int:
        """
        Pipeline-batch XADD for maximum throughput.
        Returns the number of events successfully published.
        """
        if not events:
            return 0
        r = await self._ensure()
        pipe = r.pipeline(transaction=False)
        for ev in events:
            pipe.xadd(STREAM_KEY, {"data": json.dumps(ev, default=str)})
        results = await pipe.execute(raise_on_error=False)
        ok = sum(1 for r in results if r and not isinstance(r, Exception))
        return ok

    async def stream_len(self) -> int:
        r = await self._ensure()
        return await r.xlen(STREAM_KEY)


# ── EventConsumer ─────────────────────────────────────────────────────────────

class EventConsumer:
    """
    Consumer-group reader that classifies events and broadcasts alerts.

    on_event  — called for every successfully normalized event
    on_alert  — called when the classifier marks an event as a threat
    """

    def __init__(
        self,
        consumer_name: Optional[str] = None,
        redis_url: Optional[str] = None,
        on_event: Optional[Callable] = None,
        on_alert: Optional[Callable] = None,
    ) -> None:
        self._url = redis_url or get_settings().redis_url
        self._consumer_name = consumer_name or f"consumer-{uuid.uuid4().hex[:8]}"
        self._client: Optional[aioredis.Redis] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self.on_event = on_event
        self.on_alert = on_alert
        self.monitor = ThroughputMonitor(log_interval=10)

    async def _get_client(self) -> aioredis.Redis:
        if not self._client:
            self._client = aioredis.from_url(
                self._url,
                decode_responses=True,
                max_connections=10,
            )
        return self._client

    async def _ensure_group(self) -> None:
        r = await self._get_client()
        try:
            await r.xgroup_create(STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True)
            logger.info("consumer_group_created", group=CONSUMER_GROUP, stream=STREAM_KEY)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def start(self) -> None:
        """Create consumer group (idempotent) and launch the read loop."""
        await self._ensure_group()
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="event-consumer")
        logger.info("consumer_started", name=self._consumer_name)

    async def stop(self) -> None:
        """Graceful shutdown — drain in-flight then cancel."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("consumer_stopped", name=self._consumer_name, **self.monitor.summary())

    async def _loop(self) -> None:
        from app.ingestion.normalizer import normalize_event
        from app.detection.threat_classifier import classify_event

        r = await self._get_client()
        logger.info("consumer_loop_running", stream=STREAM_KEY, group=CONSUMER_GROUP)

        while self._running:
            try:
                messages = await r.xreadgroup(
                    CONSUMER_GROUP,
                    self._consumer_name,
                    {STREAM_KEY: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )
                if not messages:
                    continue

                for _stream, entries in messages:
                    for msg_id, fields in entries:
                        await self._process_one(
                            r, msg_id, fields,
                            normalize_event, classify_event,
                        )

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("consumer_loop_error", error=str(exc))
                await asyncio.sleep(0.5)

    async def _process_one(
        self, r, msg_id: str, fields: dict,
        normalize_fn, classify_fn,
    ) -> None:
        try:
            raw = json.loads(fields.get("data", "{}"))
            normalized = normalize_fn(raw)
            if normalized is None:
                await r.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)
                return

            event_dict = normalized.model_dump()
            self.monitor.record()

            if self.on_event:
                await _maybe_await(self.on_event, event_dict)

            classification = classify_fn(event_dict)

            # ── Persist to PostgreSQL ─────────────────────────────────────────
            await _persist_classification(event_dict, classification)

            if classification.is_threat and self.on_alert:
                await _maybe_await(self.on_alert, {
                    "event": event_dict,
                    "classification": classification.to_dict(),
                })

            # ── Audit: log ingested events (HIGH/CRITICAL threats only, fire-and-forget)
            if classification.is_threat and not classification.is_false_positive:
                sev = classification.severity.upper()
                if sev in ("HIGH", "CRITICAL"):
                    from app.services.audit_service import fire_and_forget, log_event
                    fire_and_forget(log_event(
                        actor_type="system",
                        actor_id="ingestion_pipeline",
                        action="event_ingested",
                        target_type="threat_event",
                        target_id=event_dict.get("event_id") or msg_id,
                        result="success",
                        metadata={
                            "event_type": event_dict.get("event_type") or event_dict.get("layer"),
                            "source_ip": event_dict.get("source_ip"),
                            "dest_ip": event_dict.get("dest_ip"),
                            "threat_type": classification.threat_type,
                            "severity": classification.severity,
                            "confidence": classification.confidence,
                            "bytes_sent": int(event_dict.get("bytes_sent") or 0),
                            "msg_id": msg_id,
                        },
                    ))

            await r.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)

        except Exception as exc:
            logger.error("event_processing_error", msg_id=msg_id, error=str(exc))
            self.monitor.record_error()
            # Dead-letter queue
            try:
                await r.xadd(
                    DLQ_KEY,
                    {"msg_id": msg_id, "error": str(exc), "data": fields.get("data", "")},
                )
                self.monitor.record_dlq()
                await r.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)
            except Exception:
                pass  # DLQ write failure is non-fatal

    @property
    def stats(self) -> dict:
        return self.monitor.summary()


# ── DB persistence ────────────────────────────────────────────────────────────

async def _persist_classification(event: dict, classification) -> None:
    """
    Save every classified event as a ThreatEvent row.
    If it is a real threat (not benign/false_positive) with confidence > 0.3,
    also create an Incident row and broadcast via WebSocket.
    """
    from app.database import async_session_factory
    from app.models import ThreatEvent, Incident
    from app.websocket.manager import manager as ws_manager

    severity_lower = classification.severity.lower()
    mitre_technique_first = (
        classification.mitre_techniques[0].split(" - ")[0]
        if classification.mitre_techniques else None
    )
    mitre_tactic_first = (
        classification.mitre_tactics[0].split(" - ", 1)[-1]
        if classification.mitre_tactics else None
    )

    async with async_session_factory() as session:
        try:
            # Always create a ThreatEvent record
            threat_event = ThreatEvent(
                event_type=event.get("event_type") or "network",
                source=event.get("source"),
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
                hostname=event.get("hostname"),
                username=event.get("username"),
                process_name=event.get("process_name"),
                command_line=event.get("command_line"),
                severity=severity_lower,
                category=classification.threat_type,
                mitre_tactic=mitre_tactic_first,
                mitre_technique=mitre_technique_first,
                anomaly_score=classification.anomaly_score,
                is_anomaly=classification.is_anomaly,
                raw_log=event,
                enriched=True,
                # Classification output
                threat_type=classification.threat_type,
                confidence=classification.confidence,
                is_false_positive=classification.is_false_positive,
                explanation=classification.explanation,
                cross_layer_correlated=classification.cross_layer_correlated,
                rule_matches=classification.rule_matches,
                mitre_techniques=classification.mitre_techniques,
            )
            session.add(threat_event)

            # Create an Incident for real threats with meaningful confidence
            incident = None
            if classification.is_threat and classification.confidence > 0.3:
                incident = Incident(
                    title=f"{classification.threat_type.replace('_', ' ').title()} detected from {event.get('source_ip', 'unknown')}",
                    description=classification.explanation,
                    severity=severity_lower,
                    status="open",
                    source_ip=event.get("source_ip"),
                    dest_ip=event.get("dest_ip"),
                    mitre_tactics=classification.mitre_tactics,
                    mitre_techniques=classification.mitre_techniques,
                    confidence=classification.confidence,
                    raw_events=[event],
                    threat_type=classification.threat_type,
                    is_false_positive=classification.is_false_positive,
                    explanation=classification.explanation,
                    recommended_action=classification.recommended_action,
                    rule_matches=classification.rule_matches,
                    cross_layer_correlated=classification.cross_layer_correlated,
                    anomaly_score=classification.anomaly_score,
                    bytes_sent=event.get("bytes_sent") or 0,
                )
                session.add(incident)

            await session.commit()

            if incident:
                await session.refresh(incident)
                # Broadcast new threat via WebSocket
                await ws_manager.broadcast_event("new_threat", {
                    "id": str(incident.id),
                    "threat_type": classification.threat_type,
                    "severity": classification.severity,
                    "source_ip": event.get("source_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "confidence": classification.confidence,
                    "explanation": classification.explanation,
                    "mitre_techniques": classification.mitre_techniques,
                    "is_false_positive": classification.is_false_positive,
                    "timestamp": incident.created_at.isoformat(),
                })

                # ── Phase 5: Auto-create ticket for high-confidence CRITICAL/HIGH threats
                sev_upper = classification.severity.upper()
                if (
                    classification.confidence > 0.85
                    and sev_upper in ("HIGH", "CRITICAL")
                    and not classification.is_false_positive
                ):
                    try:
                        from app.services.ticket_service import ticket_service
                        async with async_session_factory() as ticket_session:
                            ticket = await ticket_service.create_ticket_from_incident(
                                ticket_session,
                                str(incident.id),
                                agent_confidence=classification.confidence,
                                agent_notes=classification.explanation or "",
                            )
                            await ticket_session.commit()
                            if ticket:
                                logger.info(
                                    "auto_ticket_created",
                                    ticket_id=str(ticket.id),
                                    incident_id=str(incident.id),
                                    severity=sev_upper,
                                    confidence=classification.confidence,
                                )
                    except Exception as ticket_exc:
                        logger.error("auto_ticket_error", error=str(ticket_exc))

        except Exception as exc:
            await session.rollback()
            logger.error("db_persist_error", error=str(exc))


# ── helpers ───────────────────────────────────────────────────────────────────

async def _maybe_await(fn: Callable, *args) -> None:
    """Call fn with args, awaiting if it returns a coroutine."""
    result = fn(*args)
    if asyncio.iscoroutine(result):
        await result


async def dlq_size(redis_url: Optional[str] = None) -> int:
    url = redis_url or get_settings().redis_url
    r = aioredis.from_url(url, decode_responses=True)
    try:
        return await r.xlen(DLQ_KEY)
    finally:
        await r.aclose()
