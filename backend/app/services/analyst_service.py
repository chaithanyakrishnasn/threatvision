"""
Analyst business logic:
  - CRUD with tier-based defaults
  - Smart ticket assignment algorithm
  - Stats recalculation
  - Leaderboard ranking
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analyst import Analyst
from app.models.ticket import Ticket
from app.schemas.analyst import AnalystCreate, AnalystUpdate, AnalystLeaderboard, AnalystRead

logger = structlog.get_logger(__name__)

# Default max_tickets by tier
TIER_MAX_TICKETS = {1: 5, 2: 8, 3: 12}

# Skills considered "related" to each ticket_type (for partial scoring)
RELATED_SKILLS: dict[str, list[str]] = {
    "web":     ["api", "cloud"],
    "network": ["malware", "forensics"],
    "llm":     ["web", "api", "cloud"],
    "cloud":   ["network", "api"],
    "api":     ["web", "llm"],
    "malware": ["forensics", "network"],
    "other":   [],
}

# Preferred analyst tier per severity
SEVERITY_TIER_PREF = {
    "CRITICAL": 3,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
}


class AnalystService:

    async def create_analyst(self, db: AsyncSession, data: AnalystCreate) -> Analyst:
        max_tickets = data.max_tickets or TIER_MAX_TICKETS.get(data.tier, 5)
        analyst = Analyst(
            name=data.name,
            email=data.email,
            tier=data.tier,
            skills=data.skills,
            availability=data.availability,
            max_tickets=max_tickets,
        )
        db.add(analyst)
        await db.flush()
        await db.refresh(analyst)
        logger.info("analyst_created", analyst_id=str(analyst.id), name=analyst.name)
        return analyst

    async def get_analyst(self, db: AsyncSession, analyst_id: str) -> Optional[Analyst]:
        result = await db.execute(
            select(Analyst).where(Analyst.id == analyst_id, Analyst.is_active == True)
        )
        return result.scalar_one_or_none()

    async def list_analysts(
        self,
        db: AsyncSession,
        tier: Optional[int] = None,
        availability: Optional[str] = None,
        skill: Optional[str] = None,
        active_only: bool = True,
    ) -> list[Analyst]:
        q = select(Analyst)
        if active_only:
            q = q.where(Analyst.is_active == True)
        if tier is not None:
            q = q.where(Analyst.tier == tier)
        if availability:
            q = q.where(Analyst.availability == availability)
        q = q.order_by(Analyst.tier.desc(), Analyst.name)
        result = await db.execute(q)
        analysts = result.scalars().all()
        if skill:
            analysts = [a for a in analysts if skill in (a.skills or [])]
        return list(analysts)

    async def update_analyst(
        self, db: AsyncSession, analyst_id: str, data: AnalystUpdate
    ) -> Optional[Analyst]:
        analyst = await self.get_analyst(db, analyst_id)
        if not analyst:
            return None
        for field, value in data.model_dump(exclude_none=True).items():
            setattr(analyst, field, value)
        analyst.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(analyst)
        return analyst

    async def deactivate_analyst(self, db: AsyncSession, analyst_id: str) -> bool:
        analyst = await self.get_analyst(db, analyst_id)
        if not analyst:
            return False
        analyst.is_active = False
        analyst.availability = "offline"
        analyst.updated_at = datetime.now(timezone.utc)
        await db.flush()
        return True

    async def set_availability(
        self, db: AsyncSession, analyst_id: str, availability: str
    ) -> Optional[Analyst]:
        analyst = await self.get_analyst(db, analyst_id)
        if not analyst:
            return None
        analyst.availability = availability
        analyst.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(analyst)
        return analyst

    async def get_best_analyst_for_ticket(
        self,
        db: AsyncSession,
        severity: str,
        ticket_type: str,
    ) -> Optional[Analyst]:
        """
        Smart assignment:
        1. Filter online analysts below their ticket cap
        2. Prefer analysts whose skills match the ticket_type
        3. Score by skill match, tier fit, workload, success rate
        4. Return highest scorer
        """
        result = await db.execute(
            select(Analyst).where(
                Analyst.is_active == True,
                Analyst.availability == "online",
            )
        )
        all_analysts = result.scalars().all()

        # Filter: below capacity
        candidates = [a for a in all_analysts if a.current_ticket_count < a.max_tickets]
        if not candidates:
            logger.warning("no_available_analysts", severity=severity, ticket_type=ticket_type)
            return None

        preferred_tier = SEVERITY_TIER_PREF.get(severity.upper(), 2)
        related = RELATED_SKILLS.get(ticket_type, [])

        def score(analyst: Analyst) -> float:
            s = 0.0
            skills = analyst.skills or []
            # Skill match
            if ticket_type in skills:
                s += 10.0
            elif any(r in skills for r in related):
                s += 5.0
            # Tier fit
            if analyst.tier == preferred_tier:
                s += 8.0
            elif analyst.tier > preferred_tier:
                s += 4.0  # overqualified, still fine
            else:
                s += 1.0  # underqualified, last resort
            # Workload (lower = better)
            workload_ratio = analyst.current_ticket_count / max(analyst.max_tickets, 1)
            s += (1.0 - workload_ratio) * 5.0
            # Historical success rate
            s += analyst.success_rate * 3.0
            return s

        best = max(candidates, key=score)
        logger.info(
            "analyst_selected",
            analyst=best.name,
            tier=best.tier,
            score=score(best),
        )
        return best

    async def update_analyst_stats(self, db: AsyncSession, analyst_id: str) -> None:
        """Recompute cached stats from live ticket data."""
        analyst = await db.get(Analyst, analyst_id)
        if not analyst:
            return

        # current_ticket_count
        active_statuses = ["open", "acknowledged", "in_progress", "patch_attempted", "escalated"]
        count_result = await db.execute(
            select(func.count(Ticket.id)).where(
                Ticket.assigned_to == analyst.id,
                Ticket.status.in_(active_statuses),
            )
        )
        analyst.current_ticket_count = count_result.scalar() or 0

        # total_resolved and avg_resolution_hours
        resolved_result = await db.execute(
            select(Ticket).where(
                Ticket.assigned_to == analyst.id,
                Ticket.status.in_(["resolved", "closed", "verified"]),
                Ticket.resolved_at.isnot(None),
            )
        )
        resolved_tickets = resolved_result.scalars().all()
        analyst.total_resolved = len(resolved_tickets)

        if resolved_tickets:
            durations = []
            for t in resolved_tickets:
                if t.created_at and t.resolved_at:
                    created = t.created_at
                    resolved = t.resolved_at
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if resolved.tzinfo is None:
                        resolved = resolved.replace(tzinfo=timezone.utc)
                    hours = (resolved - created).total_seconds() / 3600
                    durations.append(hours)
            analyst.avg_resolution_hours = sum(durations) / len(durations) if durations else 0.0

        # success_rate: non-false-positive resolutions / total resolved
        if analyst.total_resolved > 0:
            good_result = await db.execute(
                select(func.count(Ticket.id)).where(
                    Ticket.assigned_to == analyst.id,
                    Ticket.status.in_(["resolved", "closed", "verified"]),
                    Ticket.resolution_type != "false_positive",
                )
            )
            good_count = good_result.scalar() or 0
            analyst.success_rate = good_count / analyst.total_resolved
        else:
            analyst.success_rate = 1.0

        analyst.updated_at = datetime.now(timezone.utc)
        await db.flush()

    async def get_leaderboard(self, db: AsyncSession) -> list[AnalystLeaderboard]:
        """Rank analysts by: tickets resolved this week + SLA compliance."""
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)

        result = await db.execute(
            select(Analyst).where(Analyst.is_active == True).order_by(
                Analyst.total_resolved.desc(), Analyst.success_rate.desc()
            )
        )
        analysts = result.scalars().all()

        board = []
        for rank, analyst in enumerate(analysts, start=1):
            # Tickets resolved this week
            week_result = await db.execute(
                select(func.count(Ticket.id)).where(
                    Ticket.assigned_to == analyst.id,
                    Ticket.resolved_at >= week_ago,
                )
            )
            tickets_week = week_result.scalar() or 0

            # Avg resolution hours this week
            week_tickets_result = await db.execute(
                select(Ticket).where(
                    Ticket.assigned_to == analyst.id,
                    Ticket.resolved_at >= week_ago,
                    Ticket.resolved_at.isnot(None),
                )
            )
            week_tickets = week_tickets_result.scalars().all()
            avg_hours = 0.0
            if week_tickets:
                durations = []
                for t in week_tickets:
                    if t.created_at and t.resolved_at:
                        created = t.created_at.replace(tzinfo=timezone.utc) if t.created_at.tzinfo is None else t.created_at
                        resolved = t.resolved_at.replace(tzinfo=timezone.utc) if t.resolved_at.tzinfo is None else t.resolved_at
                        durations.append((resolved - created).total_seconds() / 3600)
                avg_hours = sum(durations) / len(durations) if durations else 0.0

            # SLA compliance this week
            total_week_result = await db.execute(
                select(func.count(Ticket.id)).where(
                    Ticket.assigned_to == analyst.id,
                    Ticket.created_at >= week_ago,
                )
            )
            total_week = total_week_result.scalar() or 0
            breached_week_result = await db.execute(
                select(func.count(Ticket.id)).where(
                    Ticket.assigned_to == analyst.id,
                    Ticket.created_at >= week_ago,
                    Ticket.sla_breached == True,
                )
            )
            breached_week = breached_week_result.scalar() or 0
            sla_rate = 1.0 - (breached_week / total_week) if total_week > 0 else 1.0

            board.append(AnalystLeaderboard(
                analyst=AnalystRead.from_orm_model(analyst),
                rank=rank,
                tickets_this_week=tickets_week,
                avg_resolution_hours_this_week=round(avg_hours, 2),
                sla_compliance_rate=round(sla_rate, 3),
            ))

        return board

    async def check_overloaded_analysts(self, db: AsyncSession) -> list[str]:
        result = await db.execute(
            select(Analyst.id).where(
                Analyst.is_active == True,
                Analyst.current_ticket_count >= Analyst.max_tickets,
            )
        )
        return [str(row[0]) for row in result.fetchall()]

    async def get_available_analysts(self, db: AsyncSession) -> list[Analyst]:
        result = await db.execute(
            select(Analyst).where(
                Analyst.is_active == True,
                Analyst.availability == "online",
            ).order_by(Analyst.tier.desc())
        )
        all_online = result.scalars().all()
        return [a for a in all_online if a.current_ticket_count < a.max_tickets]


analyst_service = AnalystService()
