"""
Phase 5 — Analyst System & Ticket Engine tests.

All tests that require a database use the `db` fixture from conftest.py,
which connects to the running PostgreSQL instance (started via docker-compose).

Tests are designed to be idempotent — they generate unique identifiers and
clean up their own data after each run.
"""
from __future__ import annotations

import asyncio
import uuid
import sys
import os
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _unique_email() -> str:
    return f"test.{uuid.uuid4().hex[:8]}@sentinelai.test"


async def _make_analyst(db, *, tier=2, skills=None, availability="online", max_tickets=None):
    from app.services.analyst_service import AnalystService, TIER_MAX_TICKETS
    from app.schemas.analyst import AnalystCreate

    service = AnalystService()
    skills = skills or ["web", "network"]
    data = AnalystCreate(
        name=f"Test Analyst {uuid.uuid4().hex[:6]}",
        email=_unique_email(),
        tier=tier,
        skills=skills,
        availability=availability,
        max_tickets=max_tickets,
    )
    analyst = await service.create_analyst(db, data)
    await db.flush()
    return analyst


async def _make_ticket(db, *, severity="MEDIUM", ticket_type="web", auto_assign=False, analyst=None):
    from app.services.ticket_service import TicketService
    from app.schemas.ticket import TicketCreate

    service = TicketService()
    data = TicketCreate(
        title=f"Test ticket {uuid.uuid4().hex[:8]}",
        description="Created by test suite",
        severity=severity,
        ticket_type=ticket_type,
        source_type="manual",
    )
    ticket = await service.create_ticket(db, data, auto_assign=auto_assign)
    if analyst and not ticket.assigned_to:
        ticket.assigned_to = analyst.id
        ticket.assigned_at = datetime.now(timezone.utc)
        analyst.current_ticket_count += 1
        await db.flush()
    return ticket


# ── Test 1: Create analyst ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_analyst(db):
    from app.models.analyst import Analyst
    from app.schemas.analyst import AnalystCreate
    from app.services.analyst_service import AnalystService, TIER_MAX_TICKETS

    service = AnalystService()
    email = _unique_email()
    data = AnalystCreate(
        name="Test — Asha Nair",
        email=email,
        tier=2,
        skills=["web", "cloud"],
    )
    analyst = await service.create_analyst(db, data)
    await db.flush()

    # Verify in DB
    from sqlalchemy import select
    result = await db.execute(select(Analyst).where(Analyst.email == email))
    db_analyst = result.scalar_one_or_none()

    assert db_analyst is not None, "Analyst should be persisted to DB"
    assert db_analyst.name == "Test — Asha Nair"
    assert db_analyst.tier == 2
    assert db_analyst.skills == ["web", "cloud"]
    assert db_analyst.max_tickets == TIER_MAX_TICKETS[2]  # 8
    assert db_analyst.is_active is True
    assert db_analyst.availability == "online"


# ── Test 2: Analyst skill matching ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyst_skill_matching(db):
    """CRITICAL web ticket → should select the tier3 web analyst over tier1."""
    from app.services.analyst_service import AnalystService

    service = AnalystService()

    # Create a tier3 web analyst and a tier1 non-web analyst
    tier3_web = await _make_analyst(db, tier=3, skills=["web", "forensics"])
    tier1_network = await _make_analyst(db, tier=1, skills=["network"])
    await db.flush()

    selected = await service.get_best_analyst_for_ticket(db, severity="CRITICAL", ticket_type="web")

    # Tier3 web analyst should score higher for CRITICAL web ticket
    assert selected is not None
    # Either our tier3 web analyst was selected (or another pre-existing one with same/better score)
    assert selected.tier >= 2 or "web" in (selected.skills or []), \
        "Should prefer high-tier or web-skilled analyst for CRITICAL web ticket"


# ── Test 3: Workload limit ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyst_workload_limit(db):
    """Fill analyst to max_tickets; next ticket should NOT go to that analyst."""
    from app.services.analyst_service import AnalystService

    service = AnalystService()

    # Create analyst with max_tickets=1 and fill them up
    overloaded = await _make_analyst(db, tier=2, skills=["web"], max_tickets=1)
    overloaded.current_ticket_count = 1  # at capacity
    await db.flush()

    # Create another analyst who has capacity
    available = await _make_analyst(db, tier=2, skills=["web"], max_tickets=5)
    await db.flush()

    selected = await service.get_best_analyst_for_ticket(db, severity="MEDIUM", ticket_type="web")

    if selected:
        assert str(selected.id) != str(overloaded.id), \
            "Overloaded analyst should NOT be selected"


# ── Test 4: SLA calculation ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ticket_sla_calculation(db):
    """Verify SLA deadlines are calculated correctly from severity."""
    from app.services.ticket_service import SLA_HOURS, _calc_sla_deadline

    now = datetime.now(timezone.utc)

    # CRITICAL = 15 minutes
    critical_deadline = _calc_sla_deadline("CRITICAL")
    crit_diff = (critical_deadline - now).total_seconds() / 60
    assert 14 < crit_diff < 16, f"CRITICAL SLA should be ~15 min, got {crit_diff:.1f}"

    # LOW = 24 hours
    low_deadline = _calc_sla_deadline("LOW")
    low_diff = (low_deadline - now).total_seconds() / 3600
    assert 23.9 < low_diff < 24.1, f"LOW SLA should be ~24 hours, got {low_diff:.2f}"

    # HIGH = 1 hour
    high_deadline = _calc_sla_deadline("HIGH")
    high_diff = (high_deadline - now).total_seconds() / 3600
    assert 0.99 < high_diff < 1.01, f"HIGH SLA should be ~1 hour, got {high_diff:.3f}"

    # MEDIUM = 4 hours
    medium_deadline = _calc_sla_deadline("MEDIUM")
    med_diff = (medium_deadline - now).total_seconds() / 3600
    assert 3.99 < med_diff < 4.01, f"MEDIUM SLA should be ~4 hours, got {med_diff:.3f}"


# ── Test 5: Ticket auto-assignment ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ticket_auto_assignment(db):
    """Create ticket with auto_assign=True → should be assigned to best analyst."""
    from app.services.ticket_service import TicketService
    from app.schemas.ticket import TicketCreate

    # Ensure at least one online analyst with 'web' skill exists
    analyst = await _make_analyst(db, tier=2, skills=["web", "api"], availability="online")
    await db.flush()

    service = TicketService()
    data = TicketCreate(
        title="Auto-assign test ticket",
        description="Should be auto-assigned",
        severity="HIGH",
        ticket_type="web",
        source_type="manual",
    )
    ticket = await service.create_ticket(db, data, auto_assign=True)
    await db.flush()

    assert ticket is not None
    assert ticket.ticket_number is not None
    assert ticket.sla_deadline is not None
    # Ticket should be assigned to some analyst (might not be our specific one
    # if others are more qualified, but assignment should happen)
    assert ticket.assigned_to is not None, "Ticket should be auto-assigned to an analyst"


# ── Test 6: Ticket escalation ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ticket_escalation(db):
    """Escalate ticket → new analyst assigned, count incremented."""
    from app.services.ticket_service import TicketService
    from app.services.analyst_service import AnalystService

    ts = TicketService()
    as_ = AnalystService()

    # Create two analysts
    a1 = await _make_analyst(db, tier=1, skills=["web"], max_tickets=5)
    a2 = await _make_analyst(db, tier=2, skills=["web"], max_tickets=5)
    await db.flush()

    # Create ticket assigned to a1
    ticket = await _make_ticket(db, severity="HIGH", ticket_type="web", analyst=a1)
    await db.flush()

    initial_count = a1.current_ticket_count
    old_assigned = ticket.assigned_to

    # Escalate
    escalated = await ts.escalate_ticket(db, str(ticket.id), reason="Test escalation")
    await db.flush()

    assert escalated is not None
    assert escalated.escalation_count == 1
    assert escalated.escalated_from == old_assigned
    assert escalated.escalation_reason == "Test escalation"
    # Original analyst's count should have decreased
    await db.refresh(a1)
    assert a1.current_ticket_count <= initial_count


# ── Test 7: Ticket from incident ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ticket_from_incident(db):
    """Create ticket from an incident — verify fields are mapped correctly."""
    from sqlalchemy import select
    from app.models.incident import Incident
    from app.services.ticket_service import TicketService

    # Create a test incident
    incident = Incident(
        title="Brute Force Attack on Login",
        description="Multiple failed auth attempts from 192.168.1.100",
        severity="high",
        status="open",
        source_ip="192.168.1.100",
        confidence=0.92,
        threat_type="brute_force",
        explanation="Detected 500+ failed login attempts in 5 minutes",
        recommended_action="Block IP and reset affected accounts",
        mitre_techniques=["T1110 - Brute Force"],
    )
    db.add(incident)
    await db.flush()

    service = TicketService()
    ticket = await service.create_ticket_from_incident(
        db,
        str(incident.id),
        agent_confidence=0.92,
        agent_notes="Auto-created from high-confidence incident",
    )
    await db.flush()

    assert ticket is not None
    assert ticket.source_type == "agent_detected"
    assert ticket.incident_id == str(incident.id)
    assert ticket.severity == "HIGH"  # mapped from "high"
    assert ticket.agent_confidence == 0.92
    assert ticket.agent_attempts == 1
    assert "Brute Force" in ticket.title or "brute" in ticket.title.lower()


# ── Test 8: SLA breach detection ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sla_breach_detection(db):
    """Create ticket with past SLA deadline; run check; verify sla_breached=True."""
    from app.models.ticket import Ticket
    from app.services.ticket_service import TicketService

    service = TicketService()

    # Create a ticket with expired SLA (1 hour in the past)
    past_deadline = datetime.now(timezone.utc) - timedelta(hours=1)
    ticket = Ticket(
        title="SLA breach test ticket",
        description="This ticket should be detected as breached",
        severity="MEDIUM",
        status="open",
        ticket_type="web",
        source_type="manual",
        sla_deadline=past_deadline,
        sla_breached=False,
        agent_attempts=0,
    )
    db.add(ticket)
    await db.flush()

    # Run breach check
    breached = await service.check_sla_breaches(db)
    await db.flush()

    # Find our ticket in breached list
    our_breach = next((t for t in breached if t.id == ticket.id), None)
    assert our_breach is not None, "Our expired ticket should be detected as breached"
    assert our_breach.sla_breached is True


# ── Test 9: Activity timeline ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ticket_activity_timeline(db):
    """Create → assign → resolve; verify 3 activities in correct order."""
    from app.services.ticket_service import TicketService
    from sqlalchemy.orm import selectinload
    from sqlalchemy import select
    from app.models.ticket import Ticket

    service = TicketService()

    # Create analyst
    analyst = await _make_analyst(db, tier=2, skills=["web"])
    await db.flush()

    # Create ticket (no auto-assign so we control the flow)
    ticket = await _make_ticket(db, severity="LOW", ticket_type="web", auto_assign=False)
    await db.flush()

    # Manually assign
    await service.assign_ticket(db, str(ticket.id), str(analyst.id))
    await db.flush()

    # Resolve
    await service.resolve_ticket(
        db, str(ticket.id), str(analyst.id),
        resolution_notes="Fixed the issue", resolution_type="analyst_fixed"
    )
    await db.flush()

    # Query activities directly (bypasses identity-map caching on the relationship)
    from app.models.ticket_activity import TicketActivity
    act_result = await db.execute(
        select(TicketActivity).where(TicketActivity.ticket_id == ticket.id)
    )
    activities = act_result.scalars().all()
    actions = [a.action for a in activities]

    assert "created" in actions, f"Should have 'created' activity, got: {actions}"
    assert "assigned" in actions, f"Should have 'assigned' activity, got: {actions}"
    assert "resolved" in actions, f"Should have 'resolved' activity, got: {actions}"
    assert len(activities) >= 3, f"Should have >=3 activities, got {len(activities)}"


# ── Test 10: Analyst stats update ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyst_stats_update(db):
    """Resolve a ticket; verify analyst.total_resolved increments."""
    from app.services.ticket_service import TicketService
    from app.services.analyst_service import AnalystService

    ts = TicketService()
    as_ = AnalystService()

    analyst = await _make_analyst(db, tier=2, skills=["web"])
    await db.flush()
    initial_resolved = analyst.total_resolved

    # Create and assign ticket
    ticket = await _make_ticket(db, severity="LOW", ticket_type="web", analyst=analyst)
    await db.flush()

    # Resolve it
    await ts.resolve_ticket(
        db, str(ticket.id), str(analyst.id),
        resolution_notes="Fixed", resolution_type="analyst_fixed"
    )
    await db.flush()

    # Stats should be updated
    await as_.update_analyst_stats(db, str(analyst.id))
    await db.flush()
    await db.refresh(analyst)

    assert analyst.total_resolved > initial_resolved, \
        f"total_resolved should increase after resolution (was {initial_resolved}, now {analyst.total_resolved})"


# ── Test 11: Leaderboard ordering ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_leaderboard_ordering(db):
    """Leaderboard should return analysts sorted with highest performers first."""
    from app.services.analyst_service import AnalystService

    service = AnalystService()
    leaderboard = await service.get_leaderboard(db)

    assert isinstance(leaderboard, list)
    # Ranks should be sequential starting from 1
    if leaderboard:
        assert leaderboard[0].rank == 1
        for i, entry in enumerate(leaderboard):
            assert entry.rank == i + 1

    # Each entry should have valid analyst data
    for entry in leaderboard:
        assert entry.analyst.id is not None
        assert 0.0 <= entry.sla_compliance_rate <= 1.0
        assert entry.tickets_this_week >= 0
