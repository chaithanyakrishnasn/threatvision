"""
Seed Phase 5 demo data:
  - 5 analysts with realistic profiles
  - 1 demo project
  - 8 demo tickets with activity timelines
"""
from __future__ import annotations

import asyncio
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

DEMO_ANALYSTS = [
    {
        "name": "Analyst 1 — Arjun Mehta",
        "email": "arjun.mehta@sentinelai.dev",
        "tier": 3,
        "skills": ["web", "network", "forensics", "malware"],
        "availability": "online",
    },
    {
        "name": "Analyst 2 — Priya Sharma",
        "email": "priya.sharma@sentinelai.dev",
        "tier": 2,
        "skills": ["web", "llm", "api", "cloud"],
        "availability": "online",
    },
    {
        "name": "Analyst 3 — Ravi Krishnan",
        "email": "ravi.krishnan@sentinelai.dev",
        "tier": 2,
        "skills": ["network", "cloud", "malware"],
        "availability": "busy",
    },
    {
        "name": "Analyst 4 — Sneha Patel",
        "email": "sneha.patel@sentinelai.dev",
        "tier": 1,
        "skills": ["web", "api"],
        "availability": "online",
    },
    {
        "name": "Analyst 5 — Kiran Das",
        "email": "kiran.das@sentinelai.dev",
        "tier": 1,
        "skills": ["network", "llm"],
        "availability": "offline",
    },
]


async def seed() -> None:
    from app.database import async_session_factory
    from app.models.analyst import Analyst
    from app.models.ticket import Ticket
    from app.models.ticket_activity import TicketActivity
    from app.models.project import Project
    from app.services.analyst_service import TIER_MAX_TICKETS
    from sqlalchemy import select

    async with async_session_factory() as session:
        # ── Analysts ─────────────────────────────────────────────────────────
        analyst_objs: dict[str, Analyst] = {}
        for data in DEMO_ANALYSTS:
            existing = await session.execute(
                select(Analyst).where(Analyst.email == data["email"])
            )
            analyst = existing.scalar_one_or_none()
            if analyst:
                print(f"  ↩ Analyst already exists: {data['name']}")
                analyst_objs[data["name"]] = analyst
                continue

            tier = data["tier"]
            analyst = Analyst(
                name=data["name"],
                email=data["email"],
                tier=tier,
                skills=data["skills"],
                availability=data["availability"],
                max_tickets=TIER_MAX_TICKETS[tier],
                total_resolved=_demo_resolved(tier),
                avg_resolution_hours=_demo_avg_hours(tier),
                success_rate=_demo_success_rate(tier),
            )
            session.add(analyst)
            await session.flush()
            await session.refresh(analyst)
            analyst_objs[data["name"]] = analyst
            print(f"  ✓ Created analyst: {data['name']} (Tier {tier})")

        await session.commit()

        # ── Re-fetch analysts after commit ────────────────────────────────────
        for key in list(analyst_objs.keys()):
            await session.refresh(analyst_objs[key])

        arjun = analyst_objs["Analyst 1 — Arjun Mehta"]
        priya = analyst_objs["Analyst 2 — Priya Sharma"]
        ravi  = analyst_objs["Analyst 3 — Ravi Krishnan"]
        sneha = analyst_objs["Analyst 4 — Sneha Patel"]

        # ── Demo Project ──────────────────────────────────────────────────────
        existing_proj = await session.execute(
            select(Project).where(Project.name == "SentinelAI Demo Platform")
        )
        project = existing_proj.scalar_one_or_none()
        if not project:
            project = Project(
                name="SentinelAI Demo Platform",
                description="Flagship SaaS platform — Python/FastAPI backend with Next.js frontend",
                target_url="https://demo.sentinelai.dev",
                target_ip="10.0.1.0/24",
                tech_stack=["Python", "FastAPI", "PostgreSQL", "Redis", "Next.js", "TypeScript"],
                risk_tier="critical",
                owner_name="Platform Team",
                assigned_analysts=[str(arjun.id), str(priya.id), str(ravi.id)],
                security_score=72,
            )
            session.add(project)
            await session.flush()
            print(f"  ✓ Created project: {project.name}")
        else:
            print(f"  ↩ Project already exists: {project.name}")

        await session.commit()

        # ── Demo Tickets ──────────────────────────────────────────────────────
        now = datetime.now(timezone.utc)

        tickets_data = [
            # 2 CRITICAL → Arjun (tier3, web+network skills)
            dict(
                title="SQL Injection in /api/v1/auth/login endpoint",
                description="Agent detected time-based SQL injection. Attacker can extract full user table.",
                severity="CRITICAL",
                ticket_type="web",
                status="in_progress",
                analyst=arjun,
                source_type="agent_detected",
                agent_confidence=0.97,
                agent_notes='{"technique": "time-based blind SQLi", "payload": "1\' AND SLEEP(5)--"}',
                sla_hours_ago=0.1,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Ticket created from agent_detected"),
                    ("system", "system", "SentinelAI", "assigned", None, arjun.name, f"Auto-assigned to {arjun.name} (Tier 3)"),
                    ("analyst", str(arjun.id), arjun.name, "acknowledged", "open", "acknowledged", "Reviewing SQLi payload — confirmed exploitable"),
                ],
            ),
            dict(
                title="C2 Beacon to 185.220.101.42:4444 — Possible Cobalt Strike",
                description="Endpoint processes making outbound connections on non-standard port to known C2 IP.",
                severity="CRITICAL",
                ticket_type="network",
                status="patch_attempted",
                analyst=arjun,
                source_type="agent_detected",
                agent_confidence=0.93,
                agent_notes='{"c2_ip": "185.220.101.42", "port": 4444, "protocol": "TCP"}',
                sla_hours_ago=0.05,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Ticket created from agent_detected"),
                    ("system", "system", "SentinelAI", "assigned", None, arjun.name, "Auto-assigned to Arjun Mehta (Tier 3)"),
                    ("analyst", str(arjun.id), arjun.name, "comment_added", None, None, "Isolating affected host. Network block applied to 185.220.101.42/32"),
                ],
            ),
            # 2 HIGH → Priya (tier2, web+llm skills)
            dict(
                title="LLM Prompt Injection in AI Chat Feature",
                description="User can inject system-level instructions via crafted prompts, bypassing content filters.",
                severity="HIGH",
                ticket_type="llm",
                status="in_progress",
                analyst=priya,
                source_type="agent_detected",
                agent_confidence=0.88,
                agent_notes='{"vector": "system_prompt_override", "model": "claude-3-haiku"}',
                sla_hours_ago=0,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Agent detected prompt injection attempt"),
                    ("system", "system", "SentinelAI", "assigned", None, priya.name, "Auto-assigned to Priya Sharma"),
                    ("analyst", str(priya.id), priya.name, "acknowledged", "open", "in_progress", "Testing additional injection vectors"),
                ],
            ),
            dict(
                title="API Rate Limit Bypass — Credential Stuffing Attempt",
                description="Attacker rotating IPs to bypass rate limits. 50k login attempts in 2 hours.",
                severity="HIGH",
                ticket_type="api",
                status="acknowledged",
                analyst=priya,
                source_type="agent_detected",
                agent_confidence=0.91,
                agent_notes='{"attempts": 50000, "unique_ips": 847, "duration_hours": 2}',
                sla_hours_ago=0,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Pattern detected: credential stuffing via API"),
                    ("system", "system", "SentinelAI", "assigned", None, priya.name, "Assigned to Priya Sharma"),
                    ("analyst", str(priya.id), priya.name, "acknowledged", "open", "acknowledged", "WAF rules updated, monitoring"),
                ],
            ),
            # 2 MEDIUM (1 acknowledged, 1 in_progress)
            dict(
                title="Outdated TLS 1.0 on Payment Gateway",
                description="Payment endpoint accepting TLS 1.0 connections — PCI DSS non-compliant.",
                severity="MEDIUM",
                ticket_type="web",
                status="acknowledged",
                analyst=sneha,
                source_type="manual",
                agent_confidence=None,
                agent_notes=None,
                sla_hours_ago=0,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Manual ticket created by security team"),
                    ("system", "system", "SentinelAI", "assigned", None, sneha.name, "Assigned to Sneha Patel"),
                ],
            ),
            dict(
                title="Unpatched Log4j in Internal Reporting Service",
                description="Internal Java service running Log4j 2.14.0 — CVE-2021-44228 applies.",
                severity="MEDIUM",
                ticket_type="network",
                status="in_progress",
                analyst=ravi,
                source_type="manual",
                agent_confidence=None,
                agent_notes=None,
                sla_hours_ago=0,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Vulnerability scan flagged Log4j 2.14.0"),
                    ("system", "system", "SentinelAI", "assigned", None, ravi.name, "Assigned to Ravi Krishnan"),
                    ("analyst", str(ravi.id), ravi.name, "comment_added", None, None, "Patch tested in staging — ready for prod deployment"),
                ],
            ),
            # 1 LOW (resolved)
            dict(
                title="Missing Security Headers on Marketing Pages",
                description="X-Frame-Options and CSP headers absent on /blog and /pricing pages.",
                severity="LOW",
                ticket_type="web",
                status="resolved",
                analyst=sneha,
                source_type="manual",
                agent_confidence=None,
                agent_notes=None,
                sla_hours_ago=20,
                resolved=True,
                resolution_notes="Added X-Frame-Options: DENY and Content-Security-Policy headers via nginx config. Deployed to prod.",
                resolution_type="analyst_fixed",
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Header scan identified missing CSP"),
                    ("system", "system", "SentinelAI", "assigned", None, sneha.name, "Assigned to Sneha Patel"),
                    ("analyst", str(sneha.id), sneha.name, "resolved", "in_progress", "resolved", "Headers added via nginx — verified in prod"),
                ],
            ),
            # 1 SLA-breached (for demo)
            dict(
                title="Exposed .env File on Public S3 Bucket",
                description="Production .env file containing DB credentials found on public S3 bucket via URL scan.",
                severity="CRITICAL",
                ticket_type="cloud",
                status="open",
                analyst=None,
                source_type="agent_detected",
                agent_confidence=0.99,
                agent_notes='{"bucket": "prod-config-backup", "file": ".env", "exposed_since": "72h"}',
                sla_hours_ago=2,  # 2 hours past SLA (CRITICAL = 15 min SLA)
                sla_breached=True,
                activities=[
                    ("system", "system", "SentinelAI", "created", None, "open", "Agent found exposed .env in S3 bucket"),
                    ("system", "system", "SentinelAI", "status_changed", "sla_ok", "sla_breached", "SLA deadline exceeded"),
                ],
            ),
        ]

        for tdata in tickets_data:
            analyst = tdata.get("analyst")
            sla_hours_ago = tdata.get("sla_hours_ago", 0)
            is_breached = tdata.get("sla_breached", False)
            is_resolved = tdata.get("resolved", False)

            # Calculate SLA deadline
            from app.services.ticket_service import SLA_HOURS
            sla_hours = SLA_HOURS.get(tdata["severity"].upper(), 4.0)
            if is_breached:
                sla_deadline = now - timedelta(hours=sla_hours_ago)
            else:
                sla_deadline = now + timedelta(hours=sla_hours)

            ticket = Ticket(
                title=tdata["title"],
                description=tdata["description"],
                severity=tdata["severity"].upper(),
                status=tdata["status"],
                ticket_type=tdata["ticket_type"].lower(),
                source_type=tdata["source_type"],
                agent_confidence=tdata.get("agent_confidence"),
                agent_notes=tdata.get("agent_notes"),
                agent_attempts=1 if tdata["source_type"] == "agent_detected" else 0,
                sla_deadline=sla_deadline,
                sla_breached=is_breached,
                assigned_to=analyst.id if analyst else None,
                assigned_at=now - timedelta(minutes=30) if analyst else None,
            )

            if is_resolved:
                ticket.resolved_at = now - timedelta(hours=1)
                ticket.resolution_notes = tdata.get("resolution_notes")
                ticket.resolution_type = tdata.get("resolution_type")

            session.add(ticket)
            await session.flush()

            # Activities
            for act_data in tdata.get("activities", []):
                actor_type, actor_id, actor_name, action = act_data[:4]
                old_val = act_data[4] if len(act_data) > 4 else None
                new_val = act_data[5] if len(act_data) > 5 else None
                comment = act_data[6] if len(act_data) > 6 else None

                activity = TicketActivity(
                    ticket_id=ticket.id,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    actor_name=actor_name,
                    action=action,
                    old_value=old_val,
                    new_value=new_val,
                    comment=comment,
                )
                session.add(activity)

            # Update analyst ticket count
            if analyst and tdata["status"] in ["open", "acknowledged", "in_progress", "patch_attempted"]:
                analyst.current_ticket_count += 1

            print(f"  ✓ Created ticket [{tdata['severity']}]: {tdata['title'][:60]}")

        await session.commit()
        print("\n✅ Phase 5 seed data complete!")
        print(f"   Analysts : {len(DEMO_ANALYSTS)}")
        print(f"   Tickets  : {len(tickets_data)}")
        print(f"   Project  : 1 (SentinelAI Demo Platform)")


def _demo_resolved(tier: int) -> int:
    return {1: 12, 2: 47, 3: 134}[tier]


def _demo_avg_hours(tier: int) -> float:
    return {1: 6.2, 2: 3.1, 3: 0.8}[tier]


def _demo_success_rate(tier: int) -> float:
    return {1: 0.88, 2: 0.94, 3: 0.98}[tier]


if __name__ == "__main__":
    asyncio.run(seed())
