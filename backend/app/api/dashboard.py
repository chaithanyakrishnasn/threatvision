from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_, text
from datetime import datetime, timezone, timedelta
from app.database import get_db
from app.models import Incident, Alert, ThreatEvent, SimulationRun
from app.websocket.manager import manager
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()

_SUPPORTED_METRIC_TYPES = {"events", "threats", "critical", "false_positive", "detection_rate", "confidence"}


# ── Helper: events (last 24h by event_type + peak hour) ───────────────────────

async def _get_events_details(db: AsyncSession, last_24h: datetime) -> dict:
    # Count by event_type (layer)
    type_result = await db.execute(
        select(ThreatEvent.event_type, func.count(ThreatEvent.id).label("count"))
        .where(ThreatEvent.created_at >= last_24h)
        .group_by(ThreatEvent.event_type)
        .order_by(desc("count"))
    )
    by_type = {row[0] or "unknown": row[1] for row in type_result.all()}
    total = sum(by_type.values())

    # Peak hour (UTC)
    peak_result = await db.execute(
        select(
            func.extract("hour", ThreatEvent.created_at).label("hour"),
            func.count(ThreatEvent.id).label("count"),
        )
        .where(ThreatEvent.created_at >= last_24h)
        .group_by("hour")
        .order_by(desc("count"))
        .limit(1)
    )
    peak_row = peak_result.first()
    peak_hour = int(peak_row[0]) if peak_row else None
    peak_hour_count = int(peak_row[1]) if peak_row else 0

    # Layer normalization (event_type already maps to layer)
    layer_map = {"network": "Network", "endpoint": "Endpoint", "app": "Application", "auth": "Auth"}
    breakdown_by_layer = {
        layer_map.get(k, k.capitalize()): v for k, v in by_type.items()
    }

    return {
        "type": "events",
        "summary": {"value": total, "label": "Total Events (Last 24h)"},
        "breakdown": {
            "by_layer": breakdown_by_layer,
            "peak_hour_utc": peak_hour,
            "peak_hour_count": peak_hour_count,
        },
        "insights": [
            f"Network layer dominates with {by_type.get('network', 0)} events" if by_type.get('network', 0) == max(by_type.values(), default=0) else
            f"Most activity on {max(by_type, key=by_type.get, default='unknown')} layer ({max(by_type.values(), default=0)} events)",
            f"Peak ingestion at {peak_hour:02d}:00 UTC with {peak_hour_count} events" if peak_hour is not None else "No peak hour data available",
            "Cross-layer correlation may boost detection confidence for events sharing a source IP",
        ],
        "explanation": (
            "Events represent raw classified log entries from all ingestion sources "
            "(netflow, Windows Event, HTTP access). Counts reflect the last 24 hours. "
            "Layers are: Network (firewall/IDS flows), Endpoint (EDR/Windows telemetry), "
            "Application (HTTP/app logs), Auth (authentication events)."
        ),
        "recommended_actions": [
            "Check ingestion pipeline stats at /api/v1/ingestion/stats for EPS and queue depth",
            "Correlate high-volume layers with active threat types in the Threat Timeline",
            "Enable cross-layer correlation alerts for source IPs appearing in 2+ layers",
        ],
    }


# ── Helper: threats (active incidents by severity + threat_type) ───────────────

async def _get_threats_details(db: AsyncSession, last_24h: datetime) -> dict:
    # Count by severity
    sev_result = await db.execute(
        select(Incident.severity, func.count(Incident.id).label("count"))
        .where(
            and_(
                Incident.created_at >= last_24h,
                Incident.severity.in_(["high", "critical"]),
                Incident.is_false_positive == False,  # noqa: E712
            )
        )
        .group_by(Incident.severity)
        .order_by(desc("count"))
    )
    by_severity = {row[0]: row[1] for row in sev_result.all()}
    total_active = sum(by_severity.values())

    # Count by threat_type
    type_result = await db.execute(
        select(Incident.threat_type, func.count(Incident.id).label("count"))
        .where(
            and_(
                Incident.created_at >= last_24h,
                Incident.severity.in_(["high", "critical"]),
                Incident.is_false_positive == False,  # noqa: E712
                Incident.threat_type.isnot(None),
            )
        )
        .group_by(Incident.threat_type)
        .order_by(desc("count"))
    )
    by_type = {row[0]: row[1] for row in type_result.all()}

    top_type = max(by_type, key=by_type.get, default=None) if by_type else None

    return {
        "type": "threats",
        "summary": {"value": total_active, "label": "Active Threats (Last 24h)"},
        "breakdown": {
            "by_severity": by_severity,
            "by_threat_type": by_type,
        },
        "insights": [
            f"{by_severity.get('critical', 0)} CRITICAL incidents require immediate triage",
            f"Dominant threat type: {top_type.replace('_', ' ').title() if top_type else 'None'} ({by_type.get(top_type, 0)} incidents)" if top_type else "No dominant threat type identified",
            "Incidents are created when event confidence exceeds 0.30 and the event is non-benign",
        ],
        "explanation": (
            "Active threats are non-false-positive incidents with HIGH or CRITICAL severity "
            "created in the last 24 hours. Each incident aggregates one or more raw events "
            "that exceeded the 0.30 confidence threshold after rule + anomaly scoring."
        ),
        "recommended_actions": [
            "Prioritize CRITICAL incidents for immediate BlueAgent analysis via /api/v1/incidents/{id}/analyze",
            "Review lateral_movement incidents first — they always score HIGH or CRITICAL",
            "Check simulation panel for Red vs Blue detection rate improvement trends",
        ],
    }


# ── Helper: critical (CRITICAL severity incidents breakdown) ──────────────────

async def _get_critical_details(db: AsyncSession, last_24h: datetime) -> dict:
    total_critical: int = (await db.execute(
        select(func.count(Incident.id)).where(
            and_(Incident.created_at >= last_24h, Incident.severity == "critical")
        )
    )).scalar() or 0

    # By threat_type
    type_result = await db.execute(
        select(Incident.threat_type, func.count(Incident.id).label("count"))
        .where(and_(Incident.created_at >= last_24h, Incident.severity == "critical"))
        .group_by(Incident.threat_type)
        .order_by(desc("count"))
    )
    by_type = {(row[0] or "unknown"): row[1] for row in type_result.all()}

    # Most common rule matches across CRITICAL incidents (sampled efficiently)
    rule_result = await db.execute(
        select(Incident.rule_matches)
        .where(and_(Incident.created_at >= last_24h, Incident.severity == "critical"))
        .limit(200)
    )
    rule_counts: dict[str, int] = {}
    for (rule_list,) in rule_result.all():
        for rule in (rule_list or []):
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # MITRE context for lateral_movement (most common CRITICAL type)
    lm_rules = {"TV-003": "Lateral Movement SMB", "TV-004": "Lateral Movement WMI", "TV-005": "Credential Dumping"}

    return {
        "type": "critical",
        "summary": {"value": total_critical, "label": "Critical Incidents (Last 24h)"},
        "breakdown": {
            "by_threat_type": by_type,
            "top_triggered_rules": [{"rule": r, "hits": c} for r, c in top_rules],
        },
        "insights": [
            f"lateral_movement accounts for {by_type.get('lateral_movement', 0)} CRITICAL incidents" if by_type.get('lateral_movement') else "No lateral movement detected",
            "Rules TV-003/TV-004/TV-005 (SMB, WMI, Credential Dump) produce the highest-severity detections",
            f"Top rule: {top_rules[0][0]} fired {top_rules[0][1]} times" if top_rules else "No rule match data available",
        ],
        "explanation": (
            "CRITICAL incidents are generated when the classifier scores an event at CRITICAL severity. "
            "This is automatic for lateral_movement (all lateral movement events are HIGH or CRITICAL), "
            "credential dumping (TV-005, score 0.95), and SMB/WMI traversal (TV-003/TV-004, scores 0.92/0.89). "
            "False positives are included in this count as CRITICAL is assigned before FP suppression."
        ),
        "recommended_actions": [
            "Isolate source IPs appearing in lateral_movement incidents immediately",
            "Cross-reference CRITICAL incidents with ticket queue for SLA compliance",
            "Run BlueAgent triage on all open CRITICAL incidents to generate IR playbooks",
        ],
    }


# ── Helper: false_positive breakdown ─────────────────────────────────────────

async def _get_false_positive_breakdown(db: AsyncSession, last_24h: datetime) -> dict:
    total_events: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.created_at >= last_24h)
    )).scalar() or 0

    fp_events: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(
            and_(ThreatEvent.created_at >= last_24h, ThreatEvent.is_false_positive == True)  # noqa: E712
        )
    )).scalar() or 0

    fp_rate = round((fp_events / total_events * 100), 1) if total_events > 0 else 0.0

    # FP events by event_type (layer)
    layer_result = await db.execute(
        select(ThreatEvent.event_type, func.count(ThreatEvent.id).label("count"))
        .where(
            and_(ThreatEvent.created_at >= last_24h, ThreatEvent.is_false_positive == True)  # noqa: E712
        )
        .group_by(ThreatEvent.event_type)
        .order_by(desc("count"))
    )
    fp_by_layer = {(row[0] or "unknown"): row[1] for row in layer_result.all()}

    # Try to count TV-012 flag conditions from raw_log JSON (approximate)
    known_asset_count = 0
    internal_dest_count = 0
    business_hours_count = 0
    try:
        known_asset_count = (await db.execute(
            select(func.count(ThreatEvent.id)).where(
                and_(
                    ThreatEvent.created_at >= last_24h,
                    ThreatEvent.is_false_positive == True,  # noqa: E712
                    text("raw_log->>'known_asset' = 'true'"),
                )
            )
        )).scalar() or 0

        internal_dest_count = (await db.execute(
            select(func.count(ThreatEvent.id)).where(
                and_(
                    ThreatEvent.created_at >= last_24h,
                    ThreatEvent.is_false_positive == True,  # noqa: E712
                    text("raw_log->>'internal_destination' = 'true'"),
                )
            )
        )).scalar() or 0

        business_hours_count = (await db.execute(
            select(func.count(ThreatEvent.id)).where(
                and_(
                    ThreatEvent.created_at >= last_24h,
                    ThreatEvent.is_false_positive == True,  # noqa: E712
                    text("raw_log->>'business_hours' = 'true'"),
                )
            )
        )).scalar() or 0
    except Exception:
        # Graceful fallback if JSON queries fail (e.g., empty raw_log)
        logger.warning("fp_json_query_failed", detail="falling back to totals only")

    return {
        "type": "false_positive",
        "summary": {"value": fp_rate, "label": "False Positive Rate (%)"},
        "breakdown": {
            "total_events_24h": total_events,
            "false_positive_events_24h": fp_events,
            "fp_by_layer": fp_by_layer,
            "tv012_conditions": {
                "known_asset": known_asset_count,
                "internal_destination": internal_dest_count,
                "business_hours": business_hours_count,
            },
        },
        "insights": [
            f"{fp_events} of {total_events} events ({fp_rate}%) were suppressed as false positives in the last 24h",
            "Most false positives originate from internal admin activity on known assets during business hours",
            f"Network layer generates the most FP events ({fp_by_layer.get('network', 0)})" if fp_by_layer.get('network') else "FP distribution spans multiple layers",
            f"TV-012 known-asset flag triggered on {known_asset_count} events" if known_asset_count > 0 else "No TV-012 known-asset matches found in last 24h",
        ],
        "explanation": (
            "Rule TV-012 (Known Asset FP Suppressor) fires when all three conditions are met: "
            "(1) known_asset flag — source IP is a recognized internal asset, "
            "(2) internal_destination — traffic stays within the internal network, "
            "(3) business_hours — event occurred during normal working hours (08:00–18:00). "
            "When all three match, the event is classified as false_positive with a confidence score "
            "of 0.00 and no incident is created. This suppresses routine IT admin activity from "
            "flooding the incident queue."
        ),
        "recommended_actions": [
            "Review the known_asset allowlist in the normalizer if FP rate is unexpectedly low",
            "Extend business_hours window in threat_classifier.py if legitimate activity is being flagged outside 08-18",
            "Export FP event IDs and verify they are truly benign before expanding suppression scope",
        ],
    }


# ── Helper: detection_rate breakdown ──────────────────────────────────────────

async def _get_detection_rate_stats(db: AsyncSession, last_24h: datetime) -> dict:
    total_24h: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.created_at >= last_24h)
    )).scalar() or 0

    non_benign: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(
            and_(
                ThreatEvent.created_at >= last_24h,
                ThreatEvent.threat_type.isnot(None),
                ThreatEvent.threat_type.notin_(["benign", "false_positive"]),
            )
        )
    )).scalar() or 0

    detection_rate = round(non_benign / total_24h * 100, 1) if total_24h > 0 else 0.0

    # Count per threat_type
    type_result = await db.execute(
        select(ThreatEvent.threat_type, func.count(ThreatEvent.id).label("count"))
        .where(
            and_(
                ThreatEvent.created_at >= last_24h,
                ThreatEvent.threat_type.isnot(None),
                ThreatEvent.threat_type.notin_(["benign", "false_positive"]),
            )
        )
        .group_by(ThreatEvent.threat_type)
        .order_by(desc("count"))
    )
    by_type_raw = {row[0]: row[1] for row in type_result.all()}

    by_type_pct = {
        threat_type: {
            "count": count,
            "pct_of_detected": round(count / non_benign * 100, 1) if non_benign > 0 else 0.0,
            "pct_of_total": round(count / total_24h * 100, 1) if total_24h > 0 else 0.0,
        }
        for threat_type, count in by_type_raw.items()
    }

    # Benign + FP count
    benign_fp: int = (await db.execute(
        select(func.count(ThreatEvent.id)).where(
            and_(
                ThreatEvent.created_at >= last_24h,
                ThreatEvent.threat_type.in_(["benign", "false_positive"]),
            )
        )
    )).scalar() or 0

    top_type = max(by_type_raw, key=by_type_raw.get, default=None) if by_type_raw else None

    return {
        "type": "detection_rate",
        "summary": {"value": detection_rate, "label": "Detection Rate (%)"},
        "breakdown": {
            "total_events_24h": total_24h,
            "detected_threats": non_benign,
            "benign_and_fp": benign_fp,
            "by_threat_type": by_type_pct,
        },
        "insights": [
            f"{non_benign} threats detected out of {total_24h} total events ({detection_rate}%)",
            f"Dominant detected type: {top_type.replace('_', ' ').title() if top_type else 'None'} ({by_type_raw.get(top_type, 0)} events)" if top_type else "No threats detected in this window",
            f"{benign_fp} events classified as benign or false positive (noise floor)",
            "Detection rate improves as Red vs Blue simulation rounds progress (see Simulation Panel)",
        ],
        "explanation": (
            "Detection rate = (non-benign events / total events) × 100. "
            "Non-benign events are those classified as brute_force, c2_beacon, lateral_movement, "
            "or data_exfiltration with confidence > 0.30. Benign and false_positive events are "
            "excluded from the numerator. The classifier combines 70% rule score + 30% anomaly "
            "score (IsolationForest), with a +0.15 boost for cross-layer correlated events."
        ),
        "recommended_actions": [
            "Run /api/v1/simulation/quick-demo to see detection rate improvement over 3 rounds",
            "Tune rule thresholds in rule_engine.py if detection rate is too low or too high",
            "Review benign events to ensure TV-012 FP suppression is not over-firing",
        ],
    }


# ── Helper: confidence distribution ───────────────────────────────────────────

async def _get_confidence_distribution(db: AsyncSession, last_24h: datetime) -> dict:
    dist_result = await db.execute(
        select(
            func.count(ThreatEvent.id).filter(ThreatEvent.confidence >= 0.9).label("very_high"),
            func.count(ThreatEvent.id).filter(
                and_(ThreatEvent.confidence >= 0.7, ThreatEvent.confidence < 0.9)
            ).label("high"),
            func.count(ThreatEvent.id).filter(
                and_(ThreatEvent.confidence >= 0.5, ThreatEvent.confidence < 0.7)
            ).label("medium"),
            func.count(ThreatEvent.id).filter(ThreatEvent.confidence < 0.5).label("low"),
            func.avg(ThreatEvent.confidence).label("avg_conf"),
            func.count(ThreatEvent.id).filter(ThreatEvent.is_anomaly == True).label("anomaly_driven"),  # noqa: E712
        ).where(
            and_(
                ThreatEvent.created_at >= last_24h,
                ThreatEvent.confidence.isnot(None),
            )
        )
    )
    row = dist_result.one()

    very_high = row.very_high or 0
    high = row.high or 0
    medium = row.medium or 0
    low = row.low or 0
    total_conf = very_high + high + medium + low
    avg_conf = round(float(row.avg_conf or 0.0), 3)
    anomaly_driven = row.anomaly_driven or 0
    rule_dominated = total_conf - anomaly_driven  # approximate: events not primarily anomaly-driven

    return {
        "type": "confidence",
        "summary": {"value": avg_conf, "label": "Average Confidence Score"},
        "breakdown": {
            "distribution": {
                "0.9–1.0 (Very High)": very_high,
                "0.7–0.9 (High)": high,
                "0.5–0.7 (Medium)": medium,
                "0.0–0.5 (Low)": low,
            },
            "avg_confidence": avg_conf,
            "total_scored_events": total_conf,
            "anomaly_driven_events": anomaly_driven,
            "rule_dominated_events": rule_dominated,
        },
        "insights": [
            f"{very_high} events scored 0.9–1.0 — high-priority for auto-ticket creation (threshold: 0.85)",
            f"Average confidence of {avg_conf:.3f} across {total_conf} scored events in last 24h",
            f"{anomaly_driven} events flagged by IsolationForest anomaly detector (30% weight in confidence formula)",
            "Cross-layer correlated events receive +0.15 confidence boost, pushing many into auto-ticket range",
        ],
        "explanation": (
            "Confidence is computed as: 0.70 × rule_score + 0.30 × anomaly_score, with an optional "
            "+0.15 boost when the same source IP appears across 2+ distinct layers within a 5-minute "
            "window (cross-layer correlation). Rule scores range from 0.72 (TV-011) to 0.95 (TV-005). "
            "Events with confidence > 0.85 AND severity HIGH/CRITICAL AND not false_positive "
            "automatically generate a ticket in the analyst queue."
        ),
        "recommended_actions": [
            "Events in 0.7–0.9 range may be promotable to auto-ticket with minor rule tuning",
            "Review low-confidence (< 0.5) events for potential rule coverage gaps",
            "Check anomaly detector baseline quality — it trains on 1000 synthetic benign events at startup",
        ],
    }


@router.get("/metric-details")
async def get_metric_details(
    type: str = Query(..., description="Metric type: events|threats|critical|false_positive|detection_rate|confidence"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Returns actionable breakdown, insights, and explanation for a single dashboard metric card.
    Used by frontend metric drilldown modals.
    """
    if type not in _SUPPORTED_METRIC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric type '{type}'. Supported: {sorted(_SUPPORTED_METRIC_TYPES)}",
        )

    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    logger.info("metric_details_requested", metric_type=type)

    if type == "events":
        return await _get_events_details(db, last_24h)
    elif type == "threats":
        return await _get_threats_details(db, last_24h)
    elif type == "critical":
        return await _get_critical_details(db, last_24h)
    elif type == "false_positive":
        return await _get_false_positive_breakdown(db, last_24h)
    elif type == "detection_rate":
        return await _get_detection_rate_stats(db, last_24h)
    else:  # confidence
        return await _get_confidence_distribution(db, last_24h)


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


@router.get("/threat-timeline")
async def get_threat_timeline(
    minutes: int = 60,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns event counts bucketed per minute for the last N minutes,
    broken down by threat type. Always returns exactly N buckets (index 0 =
    oldest, index N-1 = most recent). Used by the ThreatTimeline chart.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    result = await db.execute(
        select(ThreatEvent)
        .where(ThreatEvent.created_at >= cutoff)
        .order_by(ThreatEvent.created_at)
    )
    events = result.scalars().all()

    # Build N buckets indexed 0 (oldest) … N-1 (newest)
    now = datetime.now(timezone.utc)
    buckets: dict[int, dict] = {}
    for i in range(minutes):
        bucket_time = now - timedelta(minutes=minutes - i)
        buckets[i] = {
            "timestamp": bucket_time.isoformat(),
            "minute": i,
            "brute_force": 0,
            "c2_beacon": 0,
            "lateral_movement": 0,
            "data_exfiltration": 0,
            "false_positive": 0,
            "benign": 0,
            "total": 0,
        }

    known_types = {"brute_force", "c2_beacon", "lateral_movement", "data_exfiltration", "false_positive", "benign"}

    for event in events:
        event_time = event.created_at
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        minutes_ago = int((now - event_time).total_seconds() / 60)
        bucket_index = minutes - minutes_ago - 1
        if 0 <= bucket_index < minutes:
            threat_type = (event.threat_type or "benign").lower()
            if threat_type not in known_types:
                threat_type = "brute_force"
            buckets[bucket_index][threat_type] += 1
            buckets[bucket_index]["total"] += 1

    return list(buckets.values())


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
