"""
One-time DB seed: generates 50 events, classifies each, saves ThreatEvent +
Incident rows to PostgreSQL.

Run from the backend directory:
    python3 -m app.data.seed_db
"""
from __future__ import annotations

import asyncio
import sys
import os
import random
from datetime import datetime, timezone, timedelta


def get_spread_timestamp() -> datetime:
    """
    Spread events across the last 60 minutes with realistic clustering:
    - 60% of events in last 20 minutes (recent activity)
    - 30% in 20-40 minutes ago
    - 10% in 40-60 minutes ago
    - Small random jitter so no two events have identical timestamps
    """
    now = datetime.now(timezone.utc)

    rand = random.random()
    if rand < 0.60:
        minutes_ago = random.uniform(0, 20)
    elif rand < 0.90:
        minutes_ago = random.uniform(20, 40)
    else:
        minutes_ago = random.uniform(40, 60)

    jitter_seconds = random.uniform(0, 30)
    return now - timedelta(minutes=minutes_ago, seconds=jitter_seconds)

# Ensure the project root is on sys.path when run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


async def _wait_for_db(retries: int = 10) -> None:
    """Retry DB connection up to `retries` times with 2 s delays."""
    import asyncpg
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
    from app.config import get_settings
    raw_url = get_settings().postgres_url.replace("postgresql+asyncpg://", "postgresql://")

    for attempt in range(1, retries + 1):
        try:
            conn = await asyncpg.connect(raw_url)
            await conn.close()
            print("✅ DB connection verified")
            return
        except Exception as exc:
            print(f"⏳ DB not ready ({attempt}/{retries}): {exc}")
            if attempt < retries:
                await asyncio.sleep(2)
    raise RuntimeError("Could not connect to database after retries")


async def seed() -> None:
    await _wait_for_db()

    from app.database import engine, async_session_factory
    from app.models import Base, ThreatEvent, Incident
    from app.data.synthetic_generator import generate_event_batch
    from app.detection.threat_classifier import classify_event
    from app.ingestion.normalizer import normalize_event

    print("Resetting database schema (drop_all + create_all) …")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    print("Generating 50 synthetic events …")
    raw_events = generate_event_batch(count=50, scenario_mix=True)

    saved_events = 0
    saved_incidents = 0

    async with async_session_factory() as session:
        for raw in raw_events:
            # Normalise (may return None for malformed events)
            normalized = normalize_event(raw)
            if normalized is None:
                continue
            event_dict = normalized.model_dump()

            classification = classify_event(event_dict)
            severity_lower = classification.severity.lower()
            mitre_technique_first = (
                classification.mitre_techniques[0].split(" - ")[0]
                if classification.mitre_techniques else None
            )
            mitre_tactic_first = (
                classification.mitre_tactics[0].split(" - ", 1)[-1]
                if classification.mitre_tactics else None
            )

            spread_ts = get_spread_timestamp()
            te = ThreatEvent(
                event_type=event_dict.get("event_type") or "network",
                source=event_dict.get("source"),
                source_ip=event_dict.get("source_ip"),
                dest_ip=event_dict.get("dest_ip"),
                hostname=event_dict.get("hostname"),
                username=event_dict.get("username"),
                severity=severity_lower,
                category=classification.threat_type,
                mitre_tactic=mitre_tactic_first,
                mitre_technique=mitre_technique_first,
                anomaly_score=classification.anomaly_score,
                is_anomaly=classification.is_anomaly,
                raw_log=event_dict,
                enriched=True,
                threat_type=classification.threat_type,
                confidence=classification.confidence,
                is_false_positive=classification.is_false_positive,
                explanation=classification.explanation,
                cross_layer_correlated=classification.cross_layer_correlated,
                rule_matches=classification.rule_matches,
                mitre_techniques=classification.mitre_techniques,
                created_at=spread_ts,
                updated_at=spread_ts,
            )
            session.add(te)
            saved_events += 1

            if classification.is_threat and classification.confidence > 0.3:
                inc = Incident(
                    title=f"{classification.threat_type.replace('_', ' ').title()} detected from {event_dict.get('source_ip', 'unknown')}",
                    description=classification.explanation,
                    severity=severity_lower,
                    status="open",
                    source_ip=event_dict.get("source_ip"),
                    dest_ip=event_dict.get("dest_ip"),
                    mitre_tactics=classification.mitre_tactics,
                    mitre_techniques=classification.mitre_techniques,
                    confidence=classification.confidence,
                    raw_events=[event_dict],
                    threat_type=classification.threat_type,
                    is_false_positive=classification.is_false_positive,
                    explanation=classification.explanation,
                    recommended_action=classification.recommended_action,
                    rule_matches=classification.rule_matches,
                    cross_layer_correlated=classification.cross_layer_correlated,
                    anomaly_score=classification.anomaly_score,
                )
                session.add(inc)
                saved_incidents += 1

        await session.commit()

    print(f"Seed complete: {saved_events} ThreatEvent rows, {saved_incidents} Incident rows saved.")


if __name__ == "__main__":
    asyncio.run(seed())
