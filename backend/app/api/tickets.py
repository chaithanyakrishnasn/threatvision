"""
Ticket endpoints — full lifecycle CRUD + actions.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.ticket import (
    TicketCreate, TicketUpdate, TicketRead, TicketStats,
    TicketActivityRead, TicketAssign, TicketResolve,
    TicketEscalate, TicketComment, TicketAcknowledge,
)
from app.services.ticket_service import ticket_service

router = APIRouter()


@router.get("", response_model=list[TicketRead])
async def list_tickets(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    ticket_type: Optional[str] = None,
    analyst_id: Optional[str] = None,
    sla_breached: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    tickets = await ticket_service.list_tickets(
        db,
        status=status,
        severity=severity,
        ticket_type=ticket_type,
        analyst_id=analyst_id,
        sla_breached=sla_breached,
        limit=limit,
        offset=offset,
    )
    return [TicketRead.from_orm_model(t) for t in tickets]


@router.post("", response_model=TicketRead, status_code=201)
async def create_ticket(
    payload: TicketCreate,
    db: AsyncSession = Depends(get_db),
):
    ticket = await ticket_service.create_ticket(db, payload, auto_assign=True)
    return TicketRead.from_orm_model(ticket)


@router.get("/stats", response_model=TicketStats)
async def get_stats(db: AsyncSession = Depends(get_db)):
    stats = await ticket_service.get_stats(db)
    return TicketStats(**stats)


@router.get("/sla-breaches", response_model=list[TicketRead])
async def get_sla_breaches(db: AsyncSession = Depends(get_db)):
    tickets = await ticket_service.list_tickets(db, sla_breached=True)
    return [TicketRead.from_orm_model(t) for t in tickets]


@router.get("/{ticket_id}", response_model=TicketRead)
async def get_ticket(ticket_id: str, db: AsyncSession = Depends(get_db)):
    ticket = await ticket_service.get_ticket_with_activities(db, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    return TicketRead.from_orm_model(ticket, activities=ticket.activities)


@router.put("/{ticket_id}", response_model=TicketRead)
async def update_ticket(
    ticket_id: str,
    payload: TicketUpdate,
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import select
    from app.models.ticket import Ticket
    result = await db.execute(select(Ticket).where(Ticket.id == ticket_id))
    ticket = result.scalar_one_or_none()
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(ticket, field, value)
    from datetime import datetime, timezone
    ticket.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(ticket)
    return TicketRead.from_orm_model(ticket)


@router.post("/{ticket_id}/assign", response_model=TicketRead)
async def assign_ticket(
    ticket_id: str,
    payload: TicketAssign,
    db: AsyncSession = Depends(get_db),
):
    ticket = await ticket_service.assign_ticket(db, ticket_id, payload.analyst_id)
    if not ticket:
        raise HTTPException(404, "Ticket or analyst not found")
    return TicketRead.from_orm_model(ticket)


@router.post("/{ticket_id}/acknowledge", response_model=TicketRead)
async def acknowledge_ticket(
    ticket_id: str,
    payload: TicketAcknowledge,
    db: AsyncSession = Depends(get_db),
):
    ticket = await ticket_service.acknowledge_ticket(db, ticket_id, payload.analyst_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    return TicketRead.from_orm_model(ticket)


@router.post("/{ticket_id}/resolve", response_model=TicketRead)
async def resolve_ticket(
    ticket_id: str,
    payload: TicketResolve,
    db: AsyncSession = Depends(get_db),
):
    ticket = await ticket_service.resolve_ticket(
        db,
        ticket_id,
        payload.analyst_id,
        payload.resolution_notes,
        payload.resolution_type,
    )
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    return TicketRead.from_orm_model(ticket)


@router.post("/{ticket_id}/escalate", response_model=TicketRead)
async def escalate_ticket(
    ticket_id: str,
    payload: TicketEscalate,
    db: AsyncSession = Depends(get_db),
):
    ticket = await ticket_service.escalate_ticket(db, ticket_id, payload.reason)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    return TicketRead.from_orm_model(ticket)


@router.post("/{ticket_id}/comment", response_model=TicketActivityRead)
async def add_comment(
    ticket_id: str,
    payload: TicketComment,
    db: AsyncSession = Depends(get_db),
):
    activity = await ticket_service.add_comment(
        db,
        ticket_id,
        payload.actor_type,
        payload.actor_id,
        payload.actor_name,
        payload.comment,
    )
    return TicketActivityRead.from_orm_model(activity)


@router.get("/{ticket_id}/activities", response_model=list[TicketActivityRead])
async def get_activities(ticket_id: str, db: AsyncSession = Depends(get_db)):
    ticket = await ticket_service.get_ticket_with_activities(db, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    return [TicketActivityRead.from_orm_model(a) for a in ticket.activities]


@router.post("/from-incident/{incident_id}", response_model=TicketRead, status_code=201)
async def create_from_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
):
    ticket = await ticket_service.create_ticket_from_incident(
        db, incident_id, agent_confidence=0.9, agent_notes="Created via API"
    )
    if not ticket:
        raise HTTPException(404, "Incident not found")
    return TicketRead.from_orm_model(ticket)
