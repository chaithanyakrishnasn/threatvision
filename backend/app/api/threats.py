"""
Threat detection API endpoints.

Routes:
  GET    /api/v1/threats                      — list stored threat events
  POST   /api/v1/threats/classify             — classify (no DB write)
  POST   /api/v1/threats/classify-batch       — classify a list of events
  GET    /api/v1/threats/rules                — list all 12 detection rules
  GET    /api/v1/threats/mitre/{threat_type}  — MITRE mapping for a threat type
  GET    /api/v1/threats/stats                — classification stats
  POST   /api/v1/threats/demo-classify        — classify 500-event demo dataset
  POST   /api/v1/threats                      — ingest + classify a raw event
  GET    /api/v1/threats/{event_id}           — fetch single stored event
"""
import json
import os
import uuid
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.detection.mitre_mapper import THREAT_TO_MITRE
from app.detection.rule_engine import DETECTION_RULES
from app.detection.threat_classifier import ThreatClassificationResult, classify_event
from app.models import ThreatEvent
from app.schemas import ThreatEventCreate, ThreatEventRead
from app.websocket.manager import manager
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()

_DEMO_DATASET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "demo_dataset.json"
)


def _result_to_dict(r: ThreatClassificationResult) -> dict:
    return r.to_dict()


# ── List / collection endpoints ───────────────────────────────────────────────

@router.get("", response_model=list[ThreatEventRead])
async def list_threats(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: str | None = None,
    is_anomaly: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(ThreatEvent).order_by(desc(ThreatEvent.created_at))
    if event_type:
        q = q.where(ThreatEvent.event_type == event_type)
    if is_anomaly is not None:
        q = q.where(ThreatEvent.is_anomaly == is_anomaly)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


# ── Detection engine endpoints — MUST be registered before /{event_id} ────────

@router.get("/recent")
async def get_recent_threats(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Return the most recent non-benign threat events for the live sidebar."""
    q = (
        select(ThreatEvent)
        .where(
            ThreatEvent.threat_type.isnot(None),
            ThreatEvent.threat_type.notin_(["benign", "false_positive"]),
        )
        .order_by(desc(ThreatEvent.created_at))
        .limit(limit)
    )
    result = await db.execute(q)
    events = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "threat_type": e.threat_type,
            "severity": e.severity,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "confidence": e.confidence,
            "anomaly_score": e.anomaly_score,
            "mitre_technique": e.mitre_technique,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]


@router.post("/classify")
async def classify_single(event: dict[str, Any]) -> dict:
    """Classify a single event dict. No DB write."""
    return _result_to_dict(classify_event(event))


@router.post("/classify-batch")
async def classify_batch(events: list[dict[str, Any]]) -> list[dict]:
    """Classify a list of events. No DB write."""
    return [_result_to_dict(classify_event(e)) for e in events]


@router.get("/rules")
async def list_rules() -> list[dict]:
    """Return all 12 Sigma-style detection rules."""
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "threat_type": r.threat_type,
            "mitre_technique": r.mitre_technique,
            "conditions": r.conditions,
            "score": r.score,
        }
        for r in DETECTION_RULES
    ]


@router.get("/mitre/{threat_type}")
async def get_mitre_mapping(threat_type: str) -> dict:
    """Return the MITRE ATT&CK mapping for a specific threat type."""
    mapping = THREAT_TO_MITRE.get(threat_type)
    if mapping is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown threat type '{threat_type}'. "
                   f"Valid: {list(THREAT_TO_MITRE.keys())}",
        )
    return {"threat_type": threat_type, **mapping}


@router.get("/stats")
async def classification_stats() -> dict:
    """Return aggregated classification stats from the demo dataset."""
    demo_path = os.path.normpath(_DEMO_DATASET_PATH)
    if not os.path.exists(demo_path):
        return {
            "total": 0,
            "by_threat_type": {},
            "by_severity": {},
            "avg_confidence": 0.0,
            "note": "Demo dataset not found — POST /demo-classify to generate.",
        }
    with open(demo_path) as fh:
        events = json.load(fh)
    results = [classify_event(e) for e in events]
    by_type: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    total_conf = 0.0
    for r in results:
        by_type[r.threat_type] += 1
        by_severity[r.severity] += 1
        total_conf += r.confidence
    n = len(results)
    return {
        "total": n,
        "by_threat_type": dict(by_type),
        "by_severity": dict(by_severity),
        "avg_confidence": round(total_conf / n, 4) if n else 0.0,
        "false_positive_count": by_type.get("false_positive", 0),
        "threat_count": n - by_type.get("benign", 0) - by_type.get("false_positive", 0),
    }


@router.post("/demo-classify")
async def demo_classify() -> dict:
    """Load demo_dataset.json, classify all 500 events, return summary."""
    demo_path = os.path.normpath(_DEMO_DATASET_PATH)
    if not os.path.exists(demo_path):
        from app.data.synthetic_generator import save_demo_dataset
        save_demo_dataset(filepath=demo_path, count=500)
    with open(demo_path) as fh:
        events = json.load(fh)
    results = [classify_event(e) for e in events]
    by_type: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    total_conf = 0.0
    for r in results:
        by_type[r.threat_type] += 1
        by_severity[r.severity] += 1
        total_conf += r.confidence
    n = len(results)
    return {
        "total_classified": n,
        "summary": {
            "by_threat_type": dict(by_type),
            "by_severity": dict(by_severity),
            "avg_confidence": round(total_conf / n, 4) if n else 0.0,
            "false_positives": by_type.get("false_positive", 0),
            "true_threats": n - by_type.get("benign", 0) - by_type.get("false_positive", 0),
            "cross_layer_correlated": sum(1 for r in results if r.cross_layer_correlated),
        },
        "sample_results": [_result_to_dict(r) for r in results[:20]],
    }


# ── Ingest + wildcard lookup — MUST come after all static paths ───────────────

@router.post("", response_model=ThreatEventRead, status_code=201)
async def ingest_threat_event(
    payload: ThreatEventCreate, db: AsyncSession = Depends(get_db)
):
    event_dict = payload.model_dump()
    classification = classify_event(event_dict)
    event = ThreatEvent(
        **event_dict,
        anomaly_score=classification.anomaly_score,
        is_anomaly=classification.is_anomaly,
        enriched=True,
        mitre_technique=classification.mitre_technique,
        mitre_tactic=classification.mitre_tactic,
    )
    db.add(event)
    await db.flush()
    await db.refresh(event)
    if classification.is_threat:
        await manager.broadcast_event("threat_detected", {
            "id": str(event.id),
            "event_type": event.event_type,
            "severity": classification.severity,
            "confidence": classification.confidence,
            "threat_type": classification.threat_type,
            "mitre_technique": classification.mitre_technique,
        })
    return event


@router.get("/{event_id}", response_model=ThreatEventRead)
async def get_threat_event(event_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ThreatEvent).where(ThreatEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return event
