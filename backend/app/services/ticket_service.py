"""
Ticket business logic:
  - Create / assign / acknowledge / escalate / resolve
  - SLA deadline calculation
  - Auto-assignment via AnalystService
  - WebSocket broadcast on every state change
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.ticket import Ticket
from app.models.ticket_activity import TicketActivity
from app.models.analyst import Analyst
from app.schemas.ticket import TicketCreate, TicketUpdate

logger = structlog.get_logger(__name__)

# SLA hours by severity
SLA_HOURS: dict[str, float] = {
    "CRITICAL": 0.25,   # 15 minutes
    "HIGH":     1.0,    # 1 hour
    "MEDIUM":   4.0,    # 4 hours
    "LOW":      24.0,   # 24 hours
}


def _calc_sla_deadline(severity: str) -> datetime:
    hours = SLA_HOURS.get(severity.upper(), 4.0)
    return datetime.now(timezone.utc) + timedelta(hours=hours)


async def _broadcast(event_type: str, payload: dict) -> None:
    from app.websocket.manager import manager
    try:
        await manager.broadcast_event(event_type, payload)
    except Exception as exc:
        logger.warning("ws_broadcast_failed", event=event_type, error=str(exc))


def _activity(
    ticket_id,
    actor_type: str,
    actor_id: str,
    actor_name: str,
    action: str,
    old_value: Optional[str] = None,
    new_value: Optional[str] = None,
    comment: Optional[str] = None,
) -> TicketActivity:
    return TicketActivity(
        ticket_id=ticket_id,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_name=actor_name,
        action=action,
        old_value=old_value,
        new_value=new_value,
        comment=comment,
    )


class TicketService:

    async def create_ticket(
        self,
        db: AsyncSession,
        data: TicketCreate,
        auto_assign: bool = True,
    ) -> Ticket:
        from app.services.analyst_service import analyst_service

        ticket = Ticket(
            title=data.title,
            description=data.description,
            severity=data.severity.upper(),
            status="open",
            ticket_type=data.ticket_type.lower(),
            source_type=data.source_type,
            source_event_id=data.source_event_id,
            incident_id=data.incident_id,
            agent_confidence=data.agent_confidence,
            agent_notes=data.agent_notes,
            sla_deadline=_calc_sla_deadline(data.severity),
            agent_attempts=1 if data.source_type == "agent_detected" else 0,
        )
        db.add(ticket)
        await db.flush()  # get ticket.id and ticket.ticket_number

        # Creation activity
        db.add(_activity(
            ticket.id, "system", "system", "SentinelAI",
            "created",
            new_value=ticket.status,
            comment=f"Ticket created from {ticket.source_type}",
        ))

        # Auto-assign
        if auto_assign:
            analyst = await analyst_service.get_best_analyst_for_ticket(
                db, data.severity, data.ticket_type
            )
            if analyst:
                await self._do_assign(db, ticket, analyst, assigned_by="system")

        await db.flush()
        await db.refresh(ticket)

        await _broadcast("ticket_created", {
            "id": str(ticket.id),
            "ticket_number": ticket.ticket_number,
            "title": ticket.title,
            "severity": ticket.severity,
            "status": ticket.status,
            "assigned_analyst_name": ticket.assigned_analyst_name,
        })

        # Audit — fire-and-forget so it never delays ticket creation
        from app.services.audit_service import fire_and_forget, log_event
        fire_and_forget(log_event(
            actor_type="system",
            actor_id=data.source_type or "system",
            action="ticket_created",
            target_type="ticket",
            target_id=str(ticket.id),
            result="success",
            metadata={
                "ticket_number": ticket.ticket_number,
                "title": ticket.title[:200],
                "severity": ticket.severity,
                "ticket_type": ticket.ticket_type,
                "source_type": ticket.source_type,
                "assigned_to": ticket.assigned_analyst_name,
            },
        ))

        logger.info("ticket_created", ticket_id=str(ticket.id), num=ticket.ticket_number)
        return ticket

    async def create_ticket_from_incident(
        self,
        db: AsyncSession,
        incident_id: str,
        agent_confidence: float,
        agent_notes: str,
    ) -> Optional[Ticket]:
        from app.models.incident import Incident

        result = await db.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        incident = result.scalar_one_or_none()
        if not incident:
            logger.warning("incident_not_found", incident_id=incident_id)
            return None

        # Map severity (incident uses lowercase, ticket uses uppercase)
        severity = (incident.severity or "medium").upper()
        threat_type = (incident.threat_type or "other").replace("_", " ")

        data = TicketCreate(
            title=f"[Agent] {threat_type.title()} — {incident.title[:120]}",
            description=(
                f"**Incident:** {incident.title}\n\n"
                f"**AI Analysis:** {incident.explanation or incident.description or 'N/A'}\n\n"
                f"**Recommended Action:** {incident.recommended_action or 'Investigate'}\n\n"
                f"**MITRE Techniques:** {', '.join(incident.mitre_techniques or [])}"
            ),
            severity=severity,
            ticket_type=self._map_threat_type_to_ticket_type(incident.threat_type),
            source_type="agent_detected",
            incident_id=str(incident.id),
            agent_confidence=agent_confidence,
            agent_notes=agent_notes,
        )
        return await self.create_ticket(db, data, auto_assign=True)

    def _map_threat_type_to_ticket_type(self, threat_type: Optional[str]) -> str:
        mapping = {
            "sql_injection": "web",
            "xss": "web",
            "brute_force": "web",
            "credential_stuffing": "web",
            "c2_communication": "network",
            "lateral_movement": "network",
            "port_scan": "network",
            "data_exfiltration": "network",
            "llm_prompt_injection": "llm",
            "llm_abuse": "llm",
            "privilege_escalation": "cloud",
            "api_abuse": "api",
            "malware": "malware",
        }
        if not threat_type:
            return "other"
        return mapping.get(threat_type.lower(), "other")

    async def _do_assign(
        self,
        db: AsyncSession,
        ticket: Ticket,
        analyst: Analyst,
        assigned_by: str = "system",
    ) -> None:
        ticket.assigned_to = analyst.id
        ticket.assigned_at = datetime.now(timezone.utc)
        if ticket.status == "open":
            ticket.status = "acknowledged"
        analyst.current_ticket_count += 1
        analyst.updated_at = datetime.now(timezone.utc)

        db.add(_activity(
            ticket.id, "system", assigned_by, "SentinelAI",
            "assigned",
            new_value=analyst.name,
            comment=f"Auto-assigned to {analyst.name} (Tier {analyst.tier})",
        ))

    async def assign_ticket(
        self,
        db: AsyncSession,
        ticket_id: str,
        analyst_id: str,
        assigned_by: str = "system",
    ) -> Optional[Ticket]:
        ticket = await db.get(Ticket, ticket_id)
        if not ticket:
            return None
        analyst = await db.get(Analyst, analyst_id)
        if not analyst:
            return None

        # Decrement previous analyst if reassigning
        if ticket.assigned_to and ticket.assigned_to != analyst.id:
            prev = await db.get(Analyst, ticket.assigned_to)
            if prev and prev.current_ticket_count > 0:
                prev.current_ticket_count -= 1
                prev.updated_at = datetime.now(timezone.utc)

        await self._do_assign(db, ticket, analyst, assigned_by)
        await db.flush()
        await db.refresh(ticket)

        await _broadcast("ticket_assigned", {
            "ticket_id": str(ticket.id),
            "ticket_number": f"TICK-{ticket.ticket_number:04d}",
            "analyst_name": analyst.name,
            "severity": ticket.severity,
        })

        from app.services.audit_service import fire_and_forget, log_event
        fire_and_forget(log_event(
            actor_type="human",
            actor_id=assigned_by,
            action="ticket_assigned",
            target_type="ticket",
            target_id=str(ticket.id),
            result="success",
            metadata={
                "ticket_number": f"TICK-{ticket.ticket_number:04d}",
                "analyst_name": analyst.name,
                "severity": ticket.severity,
            },
        ))
        return ticket

    async def acknowledge_ticket(
        self, db: AsyncSession, ticket_id: str, analyst_id: str
    ) -> Optional[Ticket]:
        ticket = await db.get(Ticket, ticket_id)
        if not ticket:
            return None
        old_status = ticket.status
        ticket.acknowledged_at = datetime.now(timezone.utc)
        ticket.status = "acknowledged"
        ticket.updated_at = datetime.now(timezone.utc)

        analyst = await db.get(Analyst, analyst_id)
        analyst_name = analyst.name if analyst else analyst_id

        db.add(_activity(
            ticket.id, "analyst", analyst_id, analyst_name,
            "acknowledged",
            old_value=old_status,
            new_value="acknowledged",
        ))
        await db.flush()
        await db.refresh(ticket)
        return ticket

    async def resolve_ticket(
        self,
        db: AsyncSession,
        ticket_id: str,
        analyst_id: str,
        resolution_notes: str,
        resolution_type: str,
    ) -> Optional[Ticket]:
        ticket = await db.get(Ticket, ticket_id)
        if not ticket:
            return None

        old_status = ticket.status
        ticket.resolved_at = datetime.now(timezone.utc)
        ticket.status = "resolved"
        ticket.resolution_notes = resolution_notes
        ticket.resolution_type = resolution_type
        ticket.updated_at = datetime.now(timezone.utc)

        # Decrement analyst workload
        if ticket.assigned_to:
            analyst = await db.get(Analyst, ticket.assigned_to)
            if analyst and analyst.current_ticket_count > 0:
                analyst.current_ticket_count -= 1
                analyst.updated_at = datetime.now(timezone.utc)

        analyst_obj = await db.get(Analyst, analyst_id)
        analyst_name = analyst_obj.name if analyst_obj else analyst_id

        db.add(_activity(
            ticket.id, "analyst", analyst_id, analyst_name,
            "resolved",
            old_value=old_status,
            new_value="resolved",
            comment=f"Resolution: {resolution_type} — {resolution_notes[:200]}",
        ))

        await db.flush()

        # Update analyst stats
        from app.services.analyst_service import analyst_service
        if ticket.assigned_to:
            await analyst_service.update_analyst_stats(db, str(ticket.assigned_to))

        await db.refresh(ticket)

        await _broadcast("ticket_resolved", {
            "ticket_id": str(ticket.id),
            "ticket_number": f"TICK-{ticket.ticket_number:04d}",
            "analyst_name": analyst_name,
            "resolution_type": resolution_type,
        })

        from app.services.audit_service import fire_and_forget, log_event
        fire_and_forget(log_event(
            actor_type="human",
            actor_id=analyst_id,
            action="ticket_resolved",
            target_type="ticket",
            target_id=str(ticket.id),
            result="success",
            reasoning=resolution_notes[:2000] if resolution_notes else None,
            metadata={
                "ticket_number": f"TICK-{ticket.ticket_number:04d}",
                "analyst_name": analyst_name,
                "resolution_type": resolution_type,
                "severity": ticket.severity,
            },
        ))
        return ticket

    async def escalate_ticket(
        self,
        db: AsyncSession,
        ticket_id: str,
        reason: str,
    ) -> Optional[Ticket]:
        from app.services.analyst_service import analyst_service

        ticket = await db.get(Ticket, ticket_id)
        if not ticket:
            return None

        # Remember who escalated from
        from_analyst_id = ticket.assigned_to
        from_analyst_name = "Unassigned"
        if from_analyst_id:
            from_analyst = await db.get(Analyst, from_analyst_id)
            if from_analyst:
                from_analyst_name = from_analyst.name
                if from_analyst.current_ticket_count > 0:
                    from_analyst.current_ticket_count -= 1
                    from_analyst.updated_at = datetime.now(timezone.utc)

        ticket.escalated_from = from_analyst_id
        ticket.escalation_reason = reason
        ticket.escalation_count += 1
        ticket.updated_at = datetime.now(timezone.utc)

        # Find a higher-tier analyst (exclude current)
        result = await db.execute(
            select(Analyst).where(
                Analyst.is_active == True,
                Analyst.availability == "online",
                Analyst.id != from_analyst_id,
            ).order_by(Analyst.tier.desc(), Analyst.current_ticket_count)
        )
        candidates = result.scalars().all()
        next_analyst = next(
            (a for a in candidates if a.current_ticket_count < a.max_tickets), None
        )

        to_analyst_name = "unassigned"
        if next_analyst:
            await self._do_assign(db, ticket, next_analyst, assigned_by="escalation")
            to_analyst_name = next_analyst.name

        # If escalated 3+ times, mark as escalated (requires management attention)
        if ticket.escalation_count >= 3:
            ticket.status = "escalated"

        db.add(_activity(
            ticket.id, "system", "system", "SentinelAI",
            "escalated",
            old_value=from_analyst_name,
            new_value=to_analyst_name,
            comment=f"Escalation #{ticket.escalation_count}: {reason}",
        ))

        await db.flush()
        await db.refresh(ticket)

        await _broadcast("ticket_escalated", {
            "ticket_id": str(ticket.id),
            "ticket_number": f"TICK-{ticket.ticket_number:04d}",
            "from_analyst": from_analyst_name,
            "to_analyst": to_analyst_name,
            "reason": reason,
        })

        from app.services.audit_service import fire_and_forget, log_event
        fire_and_forget(log_event(
            actor_type="system",
            actor_id="ticket_service",
            action="ticket_escalated",
            target_type="ticket",
            target_id=str(ticket.id),
            result="escalated",
            reasoning=reason,
            metadata={
                "ticket_number": f"TICK-{ticket.ticket_number:04d}",
                "from_analyst": from_analyst_name,
                "to_analyst": to_analyst_name,
                "escalation_count": ticket.escalation_count,
                "severity": ticket.severity,
            },
        ))
        return ticket

    async def add_comment(
        self,
        db: AsyncSession,
        ticket_id: str,
        actor_type: str,
        actor_id: str,
        actor_name: str,
        comment: str,
    ) -> TicketActivity:
        activity = _activity(
            ticket_id=uuid.UUID(ticket_id) if isinstance(ticket_id, str) else ticket_id,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            action="comment_added",
            comment=comment,
        )
        db.add(activity)
        await db.flush()
        await db.refresh(activity)
        return activity

    async def check_sla_breaches(self, db: AsyncSession) -> list[Ticket]:
        """Mark tickets past their SLA deadline; auto-escalate CRITICAL ones."""
        now = datetime.now(timezone.utc)
        open_statuses = ["open", "acknowledged", "in_progress", "patch_attempted"]

        result = await db.execute(
            select(Ticket).where(
                Ticket.sla_deadline < now,
                Ticket.sla_breached == False,
                Ticket.status.in_(open_statuses),
            )
        )
        breached = result.scalars().all()

        for ticket in breached:
            ticket.sla_breached = True
            ticket.updated_at = datetime.now(timezone.utc)

            db.add(_activity(
                ticket.id, "system", "system", "SentinelAI",
                "status_changed",
                old_value="sla_ok",
                new_value="sla_breached",
                comment="SLA deadline exceeded",
            ))

            await _broadcast("sla_breach", {
                "ticket_id": str(ticket.id),
                "ticket_number": f"TICK-{ticket.ticket_number:04d}",
                "severity": ticket.severity,
                "analyst": ticket.assigned_analyst_name or "unassigned",
            })

            # Auto-escalate CRITICAL breached tickets
            if ticket.severity == "CRITICAL":
                await self.escalate_ticket(db, str(ticket.id), "SLA breached on CRITICAL ticket")

        if breached:
            await db.flush()
            logger.warning("sla_breaches_detected", count=len(breached))

        return list(breached)

    async def get_ticket_with_activities(
        self, db: AsyncSession, ticket_id: str
    ) -> Optional[Ticket]:
        result = await db.execute(
            select(Ticket)
            .where(Ticket.id == ticket_id)
            .options(selectinload(Ticket.activities))
        )
        return result.scalar_one_or_none()

    async def list_tickets(
        self,
        db: AsyncSession,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        ticket_type: Optional[str] = None,
        analyst_id: Optional[str] = None,
        sla_breached: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Ticket]:
        q = select(Ticket).order_by(Ticket.created_at.desc())
        if status:
            q = q.where(Ticket.status == status)
        if severity:
            q = q.where(Ticket.severity == severity.upper())
        if ticket_type:
            q = q.where(Ticket.ticket_type == ticket_type.lower())
        if analyst_id:
            q = q.where(Ticket.assigned_to == analyst_id)
        if sla_breached is not None:
            q = q.where(Ticket.sla_breached == sla_breached)
        q = q.limit(limit).offset(offset)
        result = await db.execute(q)
        return list(result.scalars().all())

    async def get_stats(self, db: AsyncSession) -> dict:
        total_result = await db.execute(select(func.count(Ticket.id)))
        total = total_result.scalar() or 0

        statuses = ["open", "acknowledged", "in_progress", "resolved", "closed", "escalated"]
        by_status = {}
        for s in statuses:
            r = await db.execute(
                select(func.count(Ticket.id)).where(Ticket.status == s)
            )
            by_status[s] = r.scalar() or 0

        breached_result = await db.execute(
            select(func.count(Ticket.id)).where(Ticket.sla_breached == True)
        )
        sla_breached = breached_result.scalar() or 0

        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        by_severity = {}
        for sev in severities:
            r = await db.execute(
                select(func.count(Ticket.id)).where(Ticket.severity == sev)
            )
            by_severity[sev] = r.scalar() or 0

        types_result = await db.execute(
            select(Ticket.ticket_type, func.count(Ticket.id)).group_by(Ticket.ticket_type)
        )
        by_type = {row[0]: row[1] for row in types_result.fetchall()}

        return {
            "total": total,
            "open": by_status.get("open", 0),
            "acknowledged": by_status.get("acknowledged", 0),
            "in_progress": by_status.get("in_progress", 0),
            "resolved": by_status.get("resolved", 0),
            "closed": by_status.get("closed", 0),
            "sla_breached": sla_breached,
            "by_severity": by_severity,
            "by_type": by_type,
        }


ticket_service = TicketService()
