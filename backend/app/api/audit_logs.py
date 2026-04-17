"""
Audit Log API — query, search, and verify the immutable audit trail.

Endpoints (all under /api/v1/audit):
  GET  /logs            — paginated list with filters
  GET  /logs/search     — full-text search over reasoning + metadata
  GET  /verify          — hash-chain integrity check
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, and_, or_, cast, desc
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.audit_log import AuditLog

router = APIRouter()
logger = structlog.get_logger(__name__)


# ── GET /logs ─────────────────────────────────────────────────────────────────

@router.get("/logs")
async def list_audit_logs(
    actor_type: Optional[str] = Query(None, description="Filter: agent | human | system"),
    action: Optional[str] = Query(None, description="Filter by action name (exact match)"),
    result: Optional[str] = Query(None, description="Filter: success | failed | escalated"),
    actor_id: Optional[str] = Query(None, description="Filter by actor_id"),
    target_type: Optional[str] = Query(None, description="Filter by target_type"),
    time_from: Optional[datetime] = Query(None, description="ISO-8601 start time (inclusive)"),
    time_to: Optional[datetime] = Query(None, description="ISO-8601 end time (inclusive)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Return a paginated list of audit log entries.

    All filters are optional and combinable.
    Results are ordered newest-first.
    """
    conditions = []

    if actor_type:
        conditions.append(AuditLog.actor_type == actor_type)
    if action:
        conditions.append(AuditLog.action == action)
    if result:
        conditions.append(AuditLog.result == result)
    if actor_id:
        conditions.append(AuditLog.actor_id == actor_id)
    if target_type:
        conditions.append(AuditLog.target_type == target_type)
    if time_from:
        conditions.append(AuditLog.timestamp >= time_from)
    if time_to:
        conditions.append(AuditLog.timestamp <= time_to)

    q = select(AuditLog)
    if conditions:
        q = q.where(and_(*conditions))
    q = q.order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset)

    rows_result = await db.execute(q)
    rows = rows_result.scalars().all()

    # Total count for pagination
    from sqlalchemy import func
    count_q = select(func.count(AuditLog.id))
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [row.to_dict() for row in rows],
    }


# ── GET /logs/search  (must come before any /{id} wildcard) ──────────────────

@router.get("/logs/search")
async def search_audit_logs(
    q: str = Query(..., min_length=2, description="Search term for reasoning and metadata"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Full-text search over reasoning (TEXT) and metadata (JSONB).

    Matching strategy:
      - ILIKE on the `reasoning` column
      - JSONB cast-to-text ILIKE on the `metadata` column
    Both conditions are OR'd together.
    """
    from sqlalchemy import func, cast, Text
    pattern = f"%{q}%"

    search_q = (
        select(AuditLog)
        .where(
            or_(
                AuditLog.reasoning.ilike(pattern),
                cast(AuditLog.log_metadata, Text).ilike(pattern),
            )
        )
        .order_by(desc(AuditLog.timestamp))
        .limit(limit)
        .offset(offset)
    )

    rows_result = await db.execute(search_q)
    rows = rows_result.scalars().all()

    return {
        "query": q,
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "logs": [row.to_dict() for row in rows],
    }


# ── GET /verify ───────────────────────────────────────────────────────────────

@router.get("/verify")
async def verify_audit_chain() -> dict:
    """
    Walk the entire audit log chain and verify SHA-256 hash integrity.

    Returns:
      - valid (bool)      — True if no tampering detected
      - checked (int)     — number of rows verified
      - broken_at (uuid)  — first row whose hash fails (null if valid)
      - total_rows (int)  — total rows in the log
    """
    from app.services.audit_service import verify_chain
    result = await verify_chain()
    logger.info("audit_chain_verified", **result)
    return result
