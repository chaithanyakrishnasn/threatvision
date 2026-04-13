"""
IngestionPipeline — top-level orchestrator.

Ties together:
  - Normalizer   (format detection + enrichment)
  - EventProducer (Redis XADD)
  - EventConsumer (Redis XREADGROUP + classify + broadcast)
  - ThroughputMonitor
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Optional

import structlog

from app.config import get_settings
from app.ingestion.normalizer import normalize_batch
from app.ingestion.redis_consumer import (
    EventConsumer, EventProducer, ThroughputMonitor, dlq_size
)
from app.websocket.manager import manager as ws_manager

logger = structlog.get_logger(__name__)


class IngestionPipeline:
    """
    Single entry-point for all ingestion operations.

    Usage:
        pipeline = IngestionPipeline()
        await pipeline.start()
        result = await pipeline.ingest_events(raw_logs)
        await pipeline.stop()
    """

    def __init__(self) -> None:
        self._producer: Optional[EventProducer] = None
        self._consumer: Optional[EventConsumer] = None
        self._monitor = ThroughputMonitor(log_interval=10)
        self._running = False
        self._started_at: Optional[float] = None
        self._metrics_task: Optional[asyncio.Task] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return

        self._producer = EventProducer()
        await self._producer.connect()

        self._consumer = EventConsumer(
            on_event=self._on_event,
            on_alert=self._on_alert,
        )
        await self._consumer.start()

        self._running = True
        self._started_at = time.monotonic()
        self._metrics_task = asyncio.create_task(self._metrics_broadcaster(), name="metrics-broadcast")
        logger.info("pipeline_started")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if hasattr(self, "_metrics_task") and self._metrics_task:
            self._metrics_task.cancel()
            try:
                await self._metrics_task
            except asyncio.CancelledError:
                pass
        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.close()
        logger.info("pipeline_stopped", uptime_s=round(time.monotonic() - (self._started_at or 0), 1))

    # ── Metrics broadcast ─────────────────────────────────────────────────────

    async def _metrics_broadcaster(self) -> None:
        """Broadcast dashboard metrics to all WS clients every 30 seconds."""
        from app.database import async_session_factory
        from app.models import ThreatEvent, Incident
        from sqlalchemy import select, func, and_
        from datetime import datetime, timezone, timedelta

        while self._running:
            try:
                await asyncio.sleep(30)
                if ws_manager.connection_count == 0:
                    continue

                now = datetime.now(timezone.utc)
                last_24h = now - timedelta(hours=24)

                async with async_session_factory() as session:
                    total_events = (await session.execute(
                        select(func.count(ThreatEvent.id))
                    )).scalar() or 0

                    active_threats = (await session.execute(
                        select(func.count(Incident.id)).where(
                            and_(
                                Incident.created_at >= last_24h,
                                Incident.severity.in_(["high", "critical"]),
                                Incident.is_false_positive == False,  # noqa: E712
                            )
                        )
                    )).scalar() or 0

                    critical_alerts = (await session.execute(
                        select(func.count(Incident.id)).where(
                            and_(
                                Incident.created_at >= last_24h,
                                Incident.severity == "critical",
                            )
                        )
                    )).scalar() or 0

                uptime = round(time.monotonic() - (self._started_at or time.monotonic()), 1)
                pipeline_stats = self._consumer.stats if self._consumer else {}

                await ws_manager.broadcast_event("metrics_update", {
                    "total_events": total_events,
                    "active_threats": active_threats,
                    "critical_alerts": critical_alerts,
                    "events_per_second": pipeline_stats.get("eps", 0.0),
                    "uptime_seconds": uptime,
                    "timestamp": now.isoformat(),
                })

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("metrics_broadcast_error", error=str(exc))

    # ── Internal callbacks ────────────────────────────────────────────────────

    async def _on_event(self, event: dict) -> None:
        self._monitor.record()
        # Broadcast raw event to WS clients
        if ws_manager.connection_count:
            await ws_manager.broadcast_event("live_event", {
                "event": event,
                "timestamp": event.get("timestamp"),
            })

    async def _on_alert(self, payload: dict) -> None:
        classification = payload.get("classification", {})
        if ws_manager.connection_count:
            await ws_manager.broadcast_event("threat_detected", {
                "event": payload.get("event", {}),
                "severity": classification.get("severity"),
                "confidence": classification.get("confidence"),
                "mitre_technique": classification.get("mitre_technique"),
            })

    # ── Ingestion ─────────────────────────────────────────────────────────────

    async def ingest_events(
        self,
        raw_logs: list[dict],
        log_format: str = "auto",
    ) -> dict:
        """
        Normalize raw_logs then publish to Redis stream.

        Returns a summary dict: {accepted, rejected, queued, format}.
        """
        if not self._producer:
            raise RuntimeError("Pipeline not started — call await pipeline.start() first")

        normalized = normalize_batch(raw_logs, fmt=log_format)
        rejected = len(raw_logs) - len(normalized)

        events_as_dicts = [ev.model_dump() for ev in normalized]
        queued = await self._producer.publish_batch(events_as_dicts)

        result = {
            "accepted": len(normalized),
            "rejected": rejected,
            "queued": queued,
            "format": log_format,
        }
        logger.info("ingest_events", **result)
        return result

    # ── Demo scenario ─────────────────────────────────────────────────────────

    async def run_demo_scenario(self) -> None:
        """
        Load demo_dataset.json and ingest it at ~50 events/sec,
        broadcasting progress over WebSocket.
        """
        dataset_path = os.path.join(
            os.path.dirname(__file__), "..", "data", "demo_dataset.json"
        )
        if not os.path.exists(dataset_path):
            from app.data.synthetic_generator import save_demo_dataset
            save_demo_dataset(filepath=dataset_path, count=500)

        with open(dataset_path) as fh:
            events: list[dict] = json.load(fh)

        logger.info("demo_scenario_start", total=len(events))
        await ws_manager.broadcast_event("demo_started", {"total": len(events)})

        BATCH = 10
        delay = BATCH / 50.0  # 50 eps → 0.2 s per batch of 10

        for i in range(0, len(events), BATCH):
            chunk = events[i : i + BATCH]
            await self._producer.publish_batch(chunk)  # type: ignore[union-attr]
            await ws_manager.broadcast_event("demo_progress", {
                "sent": min(i + BATCH, len(events)),
                "total": len(events),
            })
            await asyncio.sleep(delay)

        await ws_manager.broadcast_event("demo_complete", {"total": len(events)})
        logger.info("demo_scenario_complete", total=len(events))

    # ── Stress test ───────────────────────────────────────────────────────────

    async def run_stress_test(
        self,
        target_eps: int = 600,
        duration: int = 30,
    ) -> dict:
        """
        Publish synthetic events at `target_eps` for `duration` seconds.

        Returns throughput stats dict.
        """
        from app.data.synthetic_generator import generate_event_batch

        if not self._producer:
            raise RuntimeError("Pipeline not started")

        logger.info("stress_test_start", target_eps=target_eps, duration=duration)
        start = time.monotonic()
        total_sent = 0
        total_ok = 0
        batch_size = max(10, target_eps // 20)  # 20 batches/sec
        sleep_per_batch = batch_size / target_eps

        while (time.monotonic() - start) < duration:
            batch = generate_event_batch(count=batch_size, scenario_mix=True)
            ok = await self._producer.publish_batch(batch)
            total_sent += batch_size
            total_ok += ok
            await asyncio.sleep(sleep_per_batch)

        elapsed = time.monotonic() - start
        actual_eps = round(total_ok / elapsed, 1)
        qdepth = await self._producer.stream_len()

        result = {
            "target_eps": target_eps,
            "actual_eps": actual_eps,
            "total_sent": total_sent,
            "total_queued": total_ok,
            "duration_s": round(elapsed, 2),
            "queue_depth": qdepth,
        }
        logger.info("stress_test_complete", **result)
        await ws_manager.broadcast_event("stress_test_complete", result)
        return result

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def stats(self) -> dict:
        queue_depth = 0
        dlq = 0
        if self._producer:
            queue_depth = await self._producer.stream_len()
        try:
            dlq = await dlq_size()
        except Exception:
            pass

        consumer_stats = self._consumer.stats if self._consumer else {}
        return {
            "running": self._running,
            "queue_depth": queue_depth,
            "dlq_size": dlq,
            "uptime_s": round(time.monotonic() - (self._started_at or time.monotonic()), 1),
            **consumer_stats,
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_pipeline: Optional[IngestionPipeline] = None


def get_pipeline() -> IngestionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = IngestionPipeline()
    return _pipeline
