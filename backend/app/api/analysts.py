"""
Analyst endpoints — CRUD, availability, stats, leaderboard.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.analyst import Analyst
from app.models.ticket import Ticket
from app.schemas.analyst import (
    AnalystCreate, AnalystUpdate, AnalystRead,
    AnalystLeaderboard, AnalystAvailabilityUpdate,
)
from app.schemas.ticket import TicketRead
from app.services.analyst_service import analyst_service
from app.websocket.manager import manager

router = APIRouter()


def _read(obj: Analyst) -> AnalystRead:
    return AnalystRead.from_orm_model(obj)


@router.get("", response_model=list[AnalystRead])
async def list_analysts(
    tier: Optional[int] = Query(None, ge=1, le=3),
    availability: Optional[str] = None,
    skill: Optional[str] = None,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
):
    analysts = await analyst_service.list_analysts(db, tier=tier, availability=availability, skill=skill, active_only=active_only)
    return [_read(a) for a in analysts]


@router.post("", response_model=AnalystRead, status_code=201)
async def create_analyst(
    payload: AnalystCreate,
    db: AsyncSession = Depends(get_db),
):
    analyst = await analyst_service.create_analyst(db, payload)
    result = _read(analyst)
    await manager.broadcast_event("analyst_update", result.model_dump(mode="json"))
    return result


@router.get("/leaderboard", response_model=list[AnalystLeaderboard])
async def get_leaderboard(db: AsyncSession = Depends(get_db)):
    return await analyst_service.get_leaderboard(db)


@router.get("/available", response_model=list[AnalystRead])
async def get_available(db: AsyncSession = Depends(get_db)):
    analysts = await analyst_service.get_available_analysts(db)
    return [_read(a) for a in analysts]


@router.get("/{analyst_id}", response_model=AnalystRead)
async def get_analyst(analyst_id: str, db: AsyncSession = Depends(get_db)):
    analyst = await analyst_service.get_analyst(db, analyst_id)
    if not analyst:
        raise HTTPException(404, "Analyst not found")
    return _read(analyst)


@router.put("/{analyst_id}", response_model=AnalystRead)
async def update_analyst(
    analyst_id: str,
    payload: AnalystUpdate,
    db: AsyncSession = Depends(get_db),
):
    analyst = await analyst_service.update_analyst(db, analyst_id, payload)
    if not analyst:
        raise HTTPException(404, "Analyst not found")
    result = _read(analyst)
    await manager.broadcast_event("analyst_update", result.model_dump(mode="json"))
    return result


@router.delete("/{analyst_id}", status_code=204)
async def deactivate_analyst(analyst_id: str, db: AsyncSession = Depends(get_db)):
    ok = await analyst_service.deactivate_analyst(db, analyst_id)
    if not ok:
        raise HTTPException(404, "Analyst not found")


@router.get("/{analyst_id}/tickets", response_model=list[TicketRead])
async def get_analyst_tickets(analyst_id: str, db: AsyncSession = Depends(get_db)):
    analyst = await analyst_service.get_analyst(db, analyst_id)
    if not analyst:
        raise HTTPException(404, "Analyst not found")
    result = await db.execute(
        select(Ticket)
        .where(Ticket.assigned_to == analyst.id)
        .order_by(Ticket.created_at.desc())
    )
    tickets = result.scalars().all()
    return [TicketRead.from_orm_model(t) for t in tickets]


@router.get("/{analyst_id}/stats")
async def get_analyst_stats(analyst_id: str, db: AsyncSession = Depends(get_db)):
    analyst = await analyst_service.get_analyst(db, analyst_id)
    if not analyst:
        raise HTTPException(404, "Analyst not found")
    await analyst_service.update_analyst_stats(db, analyst_id)
    await db.refresh(analyst)
    return {
        "analyst_id": str(analyst.id),
        "name": analyst.name,
        "tier": analyst.tier,
        "current_ticket_count": analyst.current_ticket_count,
        "max_tickets": analyst.max_tickets,
        "workload_percentage": round(analyst.current_ticket_count / max(analyst.max_tickets, 1) * 100, 1),
        "avg_resolution_hours": analyst.avg_resolution_hours,
        "total_resolved": analyst.total_resolved,
        "success_rate": analyst.success_rate,
        "availability": analyst.availability,
    }


@router.put("/{analyst_id}/availability", response_model=AnalystRead)
async def update_availability(
    analyst_id: str,
    payload: AnalystAvailabilityUpdate,
    db: AsyncSession = Depends(get_db),
):
    analyst = await analyst_service.set_availability(db, analyst_id, payload.availability)
    if not analyst:
        raise HTTPException(404, "Analyst not found")
    result = _read(analyst)
    await manager.broadcast_event("analyst_update", result.model_dump(mode="json"))
    return result
