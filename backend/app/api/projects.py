"""
Project endpoints — CRUD + security score + assigned analysts.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.models.ticket import Ticket
from app.models.analyst import Analyst
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectRead, SecurityScoreBreakdown
from app.schemas.ticket import TicketRead
from app.schemas.analyst import AnalystRead

router = APIRouter()


def _read(obj: Project) -> ProjectRead:
    return ProjectRead.from_orm_model(obj)


@router.get("", response_model=list[ProjectRead])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    return [_read(p) for p in result.scalars().all()]


@router.post("", response_model=ProjectRead, status_code=201)
async def create_project(payload: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(
        name=payload.name,
        description=payload.description,
        target_url=payload.target_url,
        target_ip=payload.target_ip,
        tech_stack=payload.tech_stack,
        risk_tier=payload.risk_tier,
        owner_name=payload.owner_name,
        assigned_analysts=payload.assigned_analysts,
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)
    return _read(project)


@router.get("/{project_id}", response_model=ProjectRead)
async def get_project(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    return _read(project)


@router.put("/{project_id}", response_model=ProjectRead)
async def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    from datetime import datetime, timezone
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(project, field, value)
    project.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(project)
    return _read(project)


@router.get("/{project_id}/tickets", response_model=list[TicketRead])
async def get_project_tickets(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    result = await db.execute(
        select(Ticket)
        .where(Ticket.incident_id.contains(project_id))
        .order_by(Ticket.created_at.desc())
    )
    tickets = result.scalars().all()
    return [TicketRead.from_orm_model(t) for t in tickets]


@router.get("/{project_id}/analysts", response_model=list[AnalystRead])
async def get_project_analysts(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    if not project.assigned_analysts:
        return []
    result = await db.execute(
        select(Analyst).where(Analyst.id.in_(project.assigned_analysts))
    )
    return [AnalystRead.from_orm_model(a) for a in result.scalars().all()]


@router.get("/{project_id}/security-score", response_model=SecurityScoreBreakdown)
async def get_security_score(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    # Count open critical/high tickets
    crit_result = await db.execute(
        select(func.count(Ticket.id)).where(
            Ticket.severity == "CRITICAL",
            Ticket.status.in_(["open", "acknowledged", "in_progress"]),
        )
    )
    open_critical = crit_result.scalar() or 0

    high_result = await db.execute(
        select(func.count(Ticket.id)).where(
            Ticket.severity == "HIGH",
            Ticket.status.in_(["open", "acknowledged", "in_progress"]),
        )
    )
    open_high = high_result.scalar() or 0

    breach_result = await db.execute(
        select(func.count(Ticket.id)).where(Ticket.sla_breached == True)
    )
    sla_breaches = breach_result.scalar() or 0

    from datetime import datetime, timezone, timedelta
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    resolved_result = await db.execute(
        select(func.count(Ticket.id)).where(
            Ticket.resolved_at >= week_ago
        )
    )
    resolved_week = resolved_result.scalar() or 0

    # Score: start at 100, deduct per issue
    score = 100
    score -= open_critical * 15
    score -= open_high * 8
    score -= sla_breaches * 5
    score = max(0, min(100, score))

    # Update project cached score
    project.security_score = score
    project.open_tickets = open_critical + open_high
    project.critical_tickets = open_critical
    from datetime import datetime, timezone
    project.updated_at = datetime.now(timezone.utc)

    return SecurityScoreBreakdown(
        overall_score=score,
        open_critical=open_critical,
        open_high=open_high,
        sla_breaches=sla_breaches,
        resolved_this_week=resolved_week,
        breakdown={
            "critical_penalty": open_critical * 15,
            "high_penalty": open_high * 8,
            "sla_breach_penalty": sla_breaches * 5,
        },
    )
