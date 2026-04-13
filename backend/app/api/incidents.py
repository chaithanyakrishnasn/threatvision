import uuid
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.database import get_db
from app.models import Incident, Alert
from app.schemas import IncidentCreate, IncidentUpdate, IncidentRead
from app.agents.blue_agent import BlueAgent
from app.websocket.manager import manager
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()

_DEMO_INCIDENTS = [
    {
        "threat_type": "c2_beacon",
        "severity": "high",
        "source_ip": "10.0.2.87",
        "dest_ip": "91.108.4.55",
        "confidence": 0.916,
        "explanation": "Periodic outbound connections from 10.0.2.87 to 91.108.4.55 at 50s intervals with jitter — matches C2 beaconing pattern.",
        "mitre_techniques": ["T1071 - Application Layer Protocol", "T1071.001 - Web Protocols"],
        "is_false_positive": False,
        "recommended_action": "Isolate affected host, block C2 destination, initiate IR playbook.",
        "rule_matches": ["TV-003", "TV-005"],
        "cross_layer_correlated": True,
    },
    {
        "threat_type": "brute_force",
        "severity": "high",
        "source_ip": "185.220.101.42",
        "dest_ip": "10.0.1.50",
        "confidence": 0.881,
        "explanation": "Repeated authentication failures from 185.220.101.42 (multiple attempts) followed by successful login — consistent with credential stuffing attack.",
        "mitre_techniques": ["T1110 - Brute Force", "T1110.004 - Credential Stuffing"],
        "is_false_positive": False,
        "recommended_action": "Block source IP, enforce MFA, review auth logs for compromised accounts.",
        "rule_matches": ["TV-001"],
        "cross_layer_correlated": False,
    },
    {
        "threat_type": "lateral_movement",
        "severity": "critical",
        "source_ip": "10.0.3.15",
        "dest_ip": "10.0.1.100",
        "confidence": 0.943,
        "explanation": "Internal host 10.0.3.15 accessing multiple endpoints via SMB/WMI — consistent with post-compromise lateral movement.",
        "mitre_techniques": ["T1021 - Remote Services", "T1021.002 - SMB/Windows Admin Shares"],
        "is_false_positive": False,
        "recommended_action": "Isolate pivot host, revoke credentials, escalate to CRITICAL incident.",
        "rule_matches": ["TV-006", "TV-007"],
        "cross_layer_correlated": True,
    },
    {
        "threat_type": "data_exfiltration",
        "severity": "critical",
        "source_ip": "10.0.4.22",
        "dest_ip": "203.0.113.99",
        "confidence": 0.892,
        "explanation": "Unusually large outbound transfer (142.3MB) from 10.0.4.22 to external destination.",
        "mitre_techniques": ["T1048 - Exfiltration Over Alternative Protocol", "T1041 - Exfiltration Over C2 Channel"],
        "is_false_positive": False,
        "recommended_action": "Block egress path, preserve forensic image, notify DLP team.",
        "rule_matches": ["TV-008", "TV-009"],
        "cross_layer_correlated": False,
    },
    {
        "threat_type": "c2_beacon",
        "severity": "medium",
        "source_ip": "10.0.5.33",
        "dest_ip": "198.51.100.44",
        "confidence": 0.654,
        "explanation": "Periodic outbound connections from 10.0.5.33 to 198.51.100.44 at 50s intervals with jitter — matches C2 beaconing pattern.",
        "mitre_techniques": ["T1071 - Application Layer Protocol"],
        "is_false_positive": False,
        "recommended_action": "Isolate affected host, block C2 destination, initiate IR playbook.",
        "rule_matches": ["TV-003"],
        "cross_layer_correlated": False,
    },
    {
        "threat_type": "brute_force",
        "severity": "high",
        "source_ip": "185.220.101.77",
        "dest_ip": "10.0.1.50",
        "confidence": 0.812,
        "explanation": "Repeated authentication failures from 185.220.101.77 (multiple attempts) followed by successful login — consistent with credential stuffing attack.",
        "mitre_techniques": ["T1110 - Brute Force"],
        "is_false_positive": False,
        "recommended_action": "Block source IP, enforce MFA, review auth logs for compromised accounts.",
        "rule_matches": ["TV-001", "TV-002"],
        "cross_layer_correlated": True,
    },
    {
        "threat_type": "lateral_movement",
        "severity": "critical",
        "source_ip": "10.0.3.88",
        "dest_ip": "10.0.1.101",
        "confidence": 0.958,
        "explanation": "Internal host 10.0.3.88 accessing multiple endpoints via SMB/WMI — consistent with post-compromise lateral movement.",
        "mitre_techniques": ["T1021 - Remote Services", "T1047 - Windows Management Instrumentation"],
        "is_false_positive": False,
        "recommended_action": "Isolate pivot host, revoke credentials, escalate to CRITICAL incident.",
        "rule_matches": ["TV-006"],
        "cross_layer_correlated": True,
    },
    {
        "threat_type": "false_positive",
        "severity": "low",
        "source_ip": "10.0.1.25",
        "dest_ip": "10.0.50.100",
        "confidence": 0.05,
        "explanation": "Traffic matches known backup schedule from admin workstation 10.0.1.25 to internal NAS — flagged as false positive.",
        "mitre_techniques": [],
        "is_false_positive": True,
        "recommended_action": "No action required — confirmed as scheduled backup activity.",
        "rule_matches": ["TV-012"],
        "cross_layer_correlated": False,
    },
    {
        "threat_type": "data_exfiltration",
        "severity": "high",
        "source_ip": "10.0.4.55",
        "dest_ip": "192.0.2.88",
        "confidence": 0.734,
        "explanation": "Unusually large outbound transfer (87.6MB) from 10.0.4.55 to external destination.",
        "mitre_techniques": ["T1048 - Exfiltration Over Alternative Protocol"],
        "is_false_positive": False,
        "recommended_action": "Block egress path, preserve forensic image, notify DLP team.",
        "rule_matches": ["TV-008"],
        "cross_layer_correlated": False,
    },
    {
        "threat_type": "c2_beacon",
        "severity": "critical",
        "source_ip": "10.0.2.91",
        "dest_ip": "91.108.4.55",
        "confidence": 0.952,
        "explanation": "Periodic outbound connections from 10.0.2.91 to 91.108.4.55 at 50s intervals with jitter — matches C2 beaconing pattern.",
        "mitre_techniques": ["T1071 - Application Layer Protocol", "T1071.001 - Web Protocols", "T1132 - Data Encoding"],
        "is_false_positive": False,
        "recommended_action": "Isolate affected host, block C2 destination, initiate IR playbook.",
        "rule_matches": ["TV-003", "TV-004", "TV-005"],
        "cross_layer_correlated": True,
    },
]


def _make_demo_response(limit: int) -> list[dict]:
    """Return synthetic demo incidents so the dashboard is never blank on first run."""
    now = datetime.now(timezone.utc)
    result = []
    for i, tmpl in enumerate(_DEMO_INCIDENTS[:limit]):
        ts = now - timedelta(minutes=i * 7 + 2)
        result.append({
            "id": str(uuid.uuid4()),
            "title": f"{tmpl['threat_type'].replace('_', ' ').title()} detected from {tmpl['source_ip']}",
            "description": tmpl["explanation"],
            "severity": tmpl["severity"],
            "status": "open",
            "source_ip": tmpl["source_ip"],
            "dest_ip": tmpl["dest_ip"],
            "mitre_tactics": [],
            "mitre_techniques": tmpl["mitre_techniques"],
            "confidence": tmpl["confidence"],
            "tags": [],
            "ai_analysis": None,
            "playbook_id": None,
            "raw_events": [],
            "created_at": ts.isoformat(),
            "updated_at": ts.isoformat(),
            "alerts": [],
            "threat_type": tmpl["threat_type"],
            "is_false_positive": tmpl["is_false_positive"],
            "explanation": tmpl["explanation"],
            "recommended_action": tmpl["recommended_action"],
            "rule_matches": tmpl["rule_matches"],
            "cross_layer_correlated": tmpl["cross_layer_correlated"],
            "anomaly_score": round(tmpl["confidence"] * 0.8, 3),
        })
    return result


@router.get("")
async def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident).order_by(desc(Incident.created_at))
    if severity:
        q = q.where(Incident.severity == severity)
    if status:
        q = q.where(Incident.status == status)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    incidents = result.scalars().all()

    if not incidents and offset == 0:
        # DB is empty on first run — return demo data so the dashboard is never blank
        logger.info("incidents_empty_returning_demo")
        return _make_demo_response(min(limit, 10))

    return [
        {
            "id": str(i.id),
            "title": i.title,
            "description": i.description,
            "severity": i.severity,
            "status": i.status,
            "source_ip": i.source_ip,
            "dest_ip": i.dest_ip,
            "mitre_tactics": i.mitre_tactics or [],
            "mitre_techniques": i.mitre_techniques or [],
            "confidence": i.confidence,
            "tags": i.tags or [],
            "ai_analysis": i.ai_analysis,
            "playbook_id": i.playbook_id,
            "raw_events": [],
            "created_at": i.created_at.isoformat(),
            "updated_at": i.updated_at.isoformat(),
            "alerts": [],
            "threat_type": i.threat_type,
            "is_false_positive": i.is_false_positive or False,
            "explanation": i.explanation,
            "recommended_action": i.recommended_action,
            "rule_matches": i.rule_matches or [],
            "cross_layer_correlated": i.cross_layer_correlated or False,
            "anomaly_score": i.anomaly_score or 0.0,
        }
        for i in incidents
    ]


@router.post("", response_model=IncidentRead, status_code=201)
async def create_incident(
    payload: IncidentCreate,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    incident = Incident(**payload.model_dump())
    db.add(incident)
    await db.flush()
    await db.refresh(incident)
    background.add_task(_analyze_and_broadcast, incident.id)
    return incident


@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(incident_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
async def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(incident, field, value)
    await db.flush()
    await db.refresh(incident)
    await manager.broadcast_event("incident_updated", {"id": str(incident.id), "status": incident.status})
    return incident


@router.post("/{incident_id}/analyze")
async def analyze_incident(incident_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    agent = BlueAgent()
    analysis = await agent.analyze_incident({
        "title": incident.title,
        "severity": incident.severity,
        "source_ip": incident.source_ip,
        "dest_ip": incident.dest_ip,
        "mitre_tactics": incident.mitre_tactics,
        "mitre_techniques": incident.mitre_techniques,
        "alerts": [{"rule_name": a.rule_name, "severity": a.severity, "description": a.description}
                   for a in (incident.alerts or [])],
        "raw_events": incident.raw_events,
    })

    incident.ai_analysis = analysis
    await db.flush()
    return {"incident_id": str(incident_id), "analysis": analysis}


async def _analyze_and_broadcast(incident_id: uuid.UUID) -> None:
    from app.database import async_session_factory
    async with async_session_factory() as db:
        result = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = result.scalar_one_or_none()
        if not incident:
            return
        await manager.broadcast_event("new_incident", {
            "id": str(incident.id),
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
        })
