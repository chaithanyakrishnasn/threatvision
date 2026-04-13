"""
Playbook API endpoints.

Routes (static paths before wildcard /{id}):
  GET  /api/v1/playbooks                    — list all playbooks in memory
  POST /api/v1/playbooks/generate           — generate playbook for a threat type
  GET  /api/v1/playbooks/quick/{threat_type} — instant hardcoded response commands
  POST /api/v1/playbooks/explain            — explain an alert via BlueAgent
  GET  /api/v1/playbooks/{id}               — fetch stored playbook by ID
"""
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException

from app.agents.blue_agent import BlueAgent
from app.agents.playbook_agent import PlaybookAgent

logger = structlog.get_logger(__name__)
router = APIRouter()

# ── In-memory playbook store ──────────────────────────────────────────────────
_playbook_store: dict[str, dict] = {}


# ── Static endpoints (must come before /{id} wildcard) ───────────────────────

@router.get("")
async def list_playbooks() -> list[dict]:
    """Return all generated playbooks (in-memory store)."""
    return list(_playbook_store.values())


@router.post("/generate")
async def generate_playbook(payload: dict[str, Any]) -> dict:
    """
    Generate a full IR playbook for a threat type.

    Body:
      threat_type: str       — e.g. "brute_force", "c2_beacon"
      severity:    str       — "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
      affected_ips: list[str] — IPs involved in the incident
    """
    threat_type = payload.get("threat_type", "brute_force")
    severity = payload.get("severity", "HIGH").upper()
    affected_ips = payload.get("affected_ips", ["10.0.1.50"])

    agent = PlaybookAgent()
    playbook = await agent.generate_for_threat(
        threat_type=threat_type,
        severity=severity,
        affected_ips=affected_ips,
    )

    # Serialize and store
    playbook_dict = {
        "playbook_id": playbook.playbook_id,
        "incident_id": playbook.incident_id,
        "threat_type": playbook.threat_type,
        "title": playbook.title,
        "phases": [
            {
                "phase_name": ph.phase_name,
                "priority": ph.priority,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "title": s.title,
                        "description": s.description,
                        "commands": s.commands,
                        "expected_outcome": s.expected_outcome,
                        "estimated_minutes": s.estimated_minutes,
                    }
                    for s in ph.steps
                ],
            }
            for ph in playbook.phases
        ],
        "estimated_time_minutes": playbook.estimated_time_minutes,
        "required_tools": playbook.required_tools,
        "success_criteria": playbook.success_criteria,
    }
    _playbook_store[playbook.playbook_id] = playbook_dict
    return playbook_dict


@router.get("/quick/{threat_type}")
async def get_quick_response(threat_type: str) -> dict:
    """
    Return instant hardcoded response commands for a threat type.
    No LLM call — sub-millisecond response.

    Valid threat types: brute_force, c2_beacon, lateral_movement,
                        data_exfiltration, false_positive
    """
    agent = PlaybookAgent()
    commands = agent.get_quick_response(threat_type)
    return {
        "threat_type": threat_type,
        "commands": commands,
        "count": len(commands),
        "note": "These are immediate response commands. Replace {placeholders} with actual values.",
    }


@router.post("/explain")
async def explain_alert(payload: dict[str, Any]) -> dict:
    """
    Use BlueAgent to explain an alert in plain language.

    Body:
      event:          dict  — raw event data
      classification: dict  — classification result (optional)
    """
    event = payload.get("event", {})
    classification = payload.get("classification", {})

    if not event:
        raise HTTPException(status_code=422, detail="'event' field is required.")

    agent = BlueAgent()
    explanation = await agent.explain_alert(event, classification)

    return {
        "what_happened": explanation.what_happened,
        "why_suspicious": explanation.why_suspicious,
        "false_positive_likelihood": explanation.false_positive_likelihood,
        "false_positive_reason": explanation.false_positive_reason,
        "recommended_action": explanation.recommended_action,
        "confidence_explanation": explanation.confidence_explanation,
    }


# ── Wildcard endpoint (must be last) ─────────────────────────────────────────

@router.get("/{playbook_id}")
async def get_playbook(playbook_id: str) -> dict:
    """Fetch a stored playbook by ID."""
    playbook = _playbook_store.get(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return playbook
