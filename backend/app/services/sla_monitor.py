"""
SLA Monitor — background task that checks SLA breaches every 60 seconds.
Started in app lifespan alongside the ingestion pipeline.
"""
from __future__ import annotations

import asyncio
import structlog

logger = structlog.get_logger(__name__)


class SLAMonitor:
    def __init__(self) -> None:
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._check_loop(), name="sla-monitor")
        logger.info("sla_monitor_started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("sla_monitor_stopped")

    async def _check_loop(self) -> None:
        from app.database import async_session_factory
        from app.services.ticket_service import ticket_service

        while self._running:
            try:
                await asyncio.sleep(60)
                if not self._running:
                    break
                async with async_session_factory() as session:
                    breached = await ticket_service.check_sla_breaches(session)
                    await session.commit()
                    if breached:
                        logger.warning("sla_monitor_breaches", count=len(breached))
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("sla_monitor_error", error=str(exc))
                await asyncio.sleep(5)  # brief back-off on error


sla_monitor = SLAMonitor()
