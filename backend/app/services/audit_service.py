"""
AuditService — central observability + compliance layer for ThreatVision.

Every actor action (agent decision, human ticket update, system classification,
API call) flows through log_event().  Each write:
  1. Fetches the previous row's hash (GENESIS for the very first entry)
  2. Computes SHA-256(actor_type|actor_id|action|target_id|result|timestamp + previous_hash)
  3. Inserts the AuditLog row
  4. Broadcasts "new_audit_log" via WebSocket

Hash chain serialisation uses an asyncio.Lock so concurrent callers cannot
race on the previous_hash lookup.  High-throughput callers (detection pipeline,
ingestion) schedule log_event() as a background asyncio.Task to keep the hot
path non-blocking.

Performance notes:
  - Only threats (not benign events) are logged from the detection pipeline
  - All ticket lifecycle actions, agent decisions, and API calls are logged
  - Background tasks are fire-and-forget; the lock prevents chain corruption
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# Serialises hash-chain updates across concurrent log_event() calls
_chain_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """Lazily create the lock inside a running event loop."""
    global _chain_lock
    if _chain_lock is None:
        _chain_lock = asyncio.Lock()
    return _chain_lock


# ── Hash chain helpers ────────────────────────────────────────────────────────

async def get_last_hash(session) -> str:
    """Return current_hash of the most-recent AuditLog row, or 'GENESIS'."""
    from sqlalchemy import select, desc
    from app.models.audit_log import AuditLog

    result = await session.execute(
        select(AuditLog.current_hash)
        .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row if row else "GENESIS"


def compute_hash(
    actor_type: str,
    actor_id: str,
    action: str,
    target_id: str,
    result: str,
    timestamp: datetime,
    previous_hash: str,
) -> str:
    """
    SHA-256 of the pipe-delimited canonical form.
    Fields: actor_type|actor_id|action|target_id|result|ISO-timestamp|previous_hash
    """
    canonical = "|".join([
        actor_type,
        actor_id,
        action,
        target_id or "",
        result,
        timestamp.isoformat(),
        previous_hash,
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def verify_chain() -> dict:
    """
    Walk every AuditLog row in insertion order and verify the hash chain.
    Returns {"valid": bool, "checked": int, "broken_at": id|None}.
    """
    from sqlalchemy import select, asc
    from app.database import async_session_factory
    from app.models.audit_log import AuditLog

    async with async_session_factory() as session:
        result = await session.execute(
            select(AuditLog).order_by(asc(AuditLog.created_at), asc(AuditLog.id))
        )
        rows = result.scalars().all()

    if not rows:
        return {"valid": True, "checked": 0, "broken_at": None, "total_rows": 0}

    expected_previous = "GENESIS"
    for row in rows:
        if row.previous_hash != expected_previous:
            return {
                "valid": False,
                "checked": rows.index(row),
                "broken_at": str(row.id),
                "reason": f"previous_hash mismatch: expected {expected_previous[:16]}… got {row.previous_hash[:16]}…",
                "total_rows": len(rows),
            }
        recomputed = compute_hash(
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            action=row.action,
            target_id=row.target_id or "",
            result=row.result,
            timestamp=row.timestamp,
            previous_hash=row.previous_hash,
        )
        if recomputed != row.current_hash:
            return {
                "valid": False,
                "checked": rows.index(row),
                "broken_at": str(row.id),
                "reason": f"current_hash mismatch on row {row.id}",
                "total_rows": len(rows),
            }
        expected_previous = row.current_hash

    return {"valid": True, "checked": len(rows), "broken_at": None, "total_rows": len(rows)}


# ── Core log_event ────────────────────────────────────────────────────────────

async def log_event(
    actor_type: str,
    actor_id: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    result: str = "success",
    reasoning: Optional[str] = None,
    confidence: Optional[float] = None,
    duration_ms: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> None:
    """
    Central audit write.  Acquires chain lock, computes hash, inserts row,
    broadcasts WebSocket event.

    This function is the single point of entry for ALL audit writes.
    Never call session.add(AuditLog(...)) directly — always use this.
    """
    from app.database import async_session_factory
    from app.models.audit_log import AuditLog

    lock = _get_lock()
    ts = datetime.now(timezone.utc)

    try:
        async with lock:
            async with async_session_factory() as session:
                previous_hash = await get_last_hash(session)
                current_hash = compute_hash(
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action=action,
                    target_id=target_id,
                    result=result,
                    timestamp=ts,
                    previous_hash=previous_hash,
                )
                log = AuditLog(
                    timestamp=ts,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action=action,
                    target_type=target_type or None,
                    target_id=target_id or None,
                    result=result,
                    reasoning=reasoning,
                    confidence=confidence,
                    duration_ms=duration_ms,
                    log_metadata=metadata,
                    previous_hash=previous_hash,
                    current_hash=current_hash,
                )
                session.add(log)
                await session.commit()
                await session.refresh(log)

        # Broadcast outside the lock so WebSocket latency doesn't block chain
        _broadcast_nowait(log.to_dict())

    except Exception as exc:
        # Non-fatal: audit failure must never crash the main operation
        logger.warning(
            "audit_log_write_failed",
            actor_type=actor_type,
            action=action,
            error=str(exc),
        )


def _broadcast_nowait(payload: dict) -> None:
    """Schedule a WebSocket broadcast without awaiting it."""
    async def _do() -> None:
        try:
            from app.websocket.manager import manager
            await manager.broadcast_event("new_audit_log", payload)
        except Exception:
            pass

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_do())
    except RuntimeError:
        pass  # No running event loop (test/seed context) — skip broadcast


# ── Convenience wrappers ──────────────────────────────────────────────────────

def fire_and_forget(coro) -> None:
    """
    Schedule an audit coroutine as a background task.
    Use this from high-throughput synchronous or async code to avoid blocking
    the caller (e.g. detection pipeline, ingestion consumer).
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        pass  # No running loop — skip (test/seed context)


# ── Module-level singleton ────────────────────────────────────────────────────

class AuditService:
    """
    Named singleton so callers can do:
        from app.services.audit_service import audit_service
        await audit_service.log_event(...)
    or use the module-level functions directly.
    """

    async def log_event(
        self,
        actor_type: str,
        actor_id: str,
        action: str,
        target_type: str = "",
        target_id: str = "",
        result: str = "success",
        reasoning: Optional[str] = None,
        confidence: Optional[float] = None,
        duration_ms: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        await log_event(
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            reasoning=reasoning,
            confidence=confidence,
            duration_ms=duration_ms,
            metadata=metadata,
        )

    async def verify_chain(self) -> dict:
        return await verify_chain()

    def fire_and_forget(self, coro) -> None:
        fire_and_forget(coro)


audit_service = AuditService()
