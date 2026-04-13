from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from datetime import datetime, timezone, timedelta
from app.database import get_db
from app.models import Incident, Alert, ThreatEvent, SimulationRun
from app.websocket.manager import manager
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/metrics")
async def get_dashboard_metrics(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    # ── Flat metrics (what the frontend dashboard cards use) ──────────────────

    # Total events ever recorded
    total_events: int = (await db.execute(
        select(func.count(ThreatEvent.id))
    )).scalar() or 0

    # Active threats: non-benign incidents with HIGH or CRITICAL severity in last 24h
    active_threats: int = (await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.created_at >= last_24h,
                Incident.severity.in_(["high", "critical"]),
                Incident.is_false_positive == False,  # noqa: E712
            )
        )
    )).scalar() or 0

    # Critical alerts: CRITICAL severity incidents in last 24h
    critical_alerts: int = (await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.created_at >= last_24h,
                Incident.severity == "critical",
            )
        )
    )).scalar() or 0

    # False positives: events marked is_false_positive in last 24h
    false_positives: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(
            and_(
                ThreatEvent.created_at >= last_24h,
                ThreatEvent.is_false_positive == True,  # noqa: E712
            )
        )
    )).scalar() or 0

    # Detection rate: (non-benign events / total events) * 100 in last 24h
    total_24h: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.created_at >= last_24h)
    )).scalar() or 0

    non_benign_24h: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(
            and_(
                ThreatEvent.created_at >= last_24h,
                ThreatEvent.threat_type.isnot(None),
                ThreatEvent.threat_type.notin_(["benign", "false_positive"]),
            )
        )
    )).scalar() or 0

    detection_rate: float = round((non_benign_24h / total_24h) * 100, 1) if total_24h > 0 else 0.0

    # Average confidence of non-benign events (all time, not just 24h)
    avg_conf_result = await db.execute(
        select(func.avg(ThreatEvent.confidence)).where(
            and_(
                ThreatEvent.threat_type.isnot(None),
                ThreatEvent.threat_type.notin_(["benign", "false_positive"]),
                ThreatEvent.confidence.isnot(None),
            )
        )
    )
    avg_confidence: float = round(float(avg_conf_result.scalar() or 0.0), 3)

    # Events per second + uptime from the live ingestion pipeline
    events_per_second: float = 0.0
    uptime_seconds: float = 0.0
    try:
        from app.ingestion.pipeline import get_pipeline
        pipeline = get_pipeline()
        pipeline_stats = await pipeline.stats()
        events_per_second = float(pipeline_stats.get("eps", 0.0))
        uptime_seconds = float(pipeline_stats.get("uptime_s", 0.0))
    except Exception:
        pass

    # ── Rich detail data (used by other dashboard sections) ───────────────────

    # Severity breakdown
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        r = await db.execute(select(func.count()).where(Incident.severity == sev))
        severity_counts[sev] = r.scalar() or 0

    # Recent incidents
    recent_result = await db.execute(
        select(Incident).order_by(desc(Incident.created_at)).limit(5)
    )
    recent_incidents = [
        {
            "id": str(i.id),
            "title": i.title,
            "severity": i.severity,
            "status": i.status,
            "threat_type": i.threat_type,
            "confidence": i.confidence,
            "source_ip": i.source_ip,
            "dest_ip": i.dest_ip,
            "mitre_techniques": i.mitre_techniques,
            "explanation": i.explanation,
            "created_at": i.created_at.isoformat(),
        }
        for i in recent_result.scalars().all()
    ]

    # Recent alerts
    recent_alerts_result = await db.execute(
        select(Alert).order_by(desc(Alert.created_at)).limit(10)
    )
    recent_alerts = [
        {
            "id": str(a.id),
            "rule_name": a.rule_name,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "mitre_technique": a.mitre_technique,
            "created_at": a.created_at.isoformat(),
        }
        for a in recent_alerts_result.scalars().all()
    ]

    # 7-day severity trend
    last_7d = now - timedelta(days=7)
    severity_trend = []
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count_result = await db.execute(
            select(func.count(ThreatEvent.id)).where(
                ThreatEvent.created_at >= day_start,
                ThreatEvent.created_at < day_end,
            )
        )
        severity_trend.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "alerts": count_result.scalar() or 0,
        })

    # Top MITRE techniques from incidents
    top_techniques_result = await db.execute(
        select(Alert.mitre_technique, func.count(Alert.id).label("count"))
        .where(Alert.mitre_technique.isnot(None))
        .group_by(Alert.mitre_technique)
        .order_by(desc("count"))
        .limit(8)
    )
    top_techniques = [
        {"technique": row[0], "count": row[1]}
        for row in top_techniques_result.all()
    ]

    return {
        # Flat metrics for dashboard cards
        "total_events": total_events,
        "active_threats": active_threats,
        "critical_alerts": critical_alerts,
        "false_positives": false_positives,
        "detection_rate": detection_rate,
        "avg_confidence": avg_confidence,
        "events_per_second": events_per_second,
        "uptime_seconds": uptime_seconds,
        # Rich detail data
        "summary": {
            "active_incidents": active_threats,
            "total_alerts": critical_alerts,
            "alerts_24h": non_benign_24h,
            "total_events": total_events,
            "events_24h": total_24h,
            "anomalies_detected": non_benign_24h,
            "ws_connections": manager.connection_count,
        },
        "incidents_by_severity": severity_counts,
        "recent_incidents": recent_incidents,
        "recent_alerts": recent_alerts,
        "severity_trend": severity_trend,
        "top_mitre_techniques": top_techniques,
        "generated_at": now.isoformat(),
    }


@router.get("/health-check")
async def backend_health(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(select(func.count(Incident.id)))
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "database": "ok" if db_ok else "error",
        "websocket_connections": manager.connection_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
