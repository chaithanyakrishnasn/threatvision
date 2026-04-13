"""
Simulation API endpoints.

Routes (order matters — static paths before wildcards):
  POST /api/v1/simulation/start           — start simulation (background)
  GET  /api/v1/simulation/history         — list past runs
  POST /api/v1/simulation/quick-demo      — synchronous 3-round demo
  GET  /api/v1/simulation/{id}/status     — status + current round
  GET  /api/v1/simulation/{id}/results    — full SimulationResult
  GET  /api/v1/simulation               — legacy list
  POST /api/v1/simulation/run             — legacy DB-stored run
  GET  /api/v1/simulation/{simulation_id} — legacy DB lookup
"""
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.sim_engine import (
    SimulationConfig,
    SimulationEngine,
    _sim_result_to_dict,
)
from app.database import get_db
from app.models import SimulationRun
from app.schemas import SimulationRunCreate, SimulationRunRead
from app.websocket.manager import manager

logger = structlog.get_logger(__name__)
router = APIRouter()

# ── In-memory store for new-style simulation results ─────────────────────────
_simulations: dict[str, dict] = {}


# ── New API endpoints (registered first to avoid wildcard capture) ────────────

@router.post("/start", status_code=202)
async def start_simulation(
    payload: dict[str, Any],
    background: BackgroundTasks,
) -> dict:
    """Start a simulation run in the background. Returns simulation_id immediately."""
    sim_id = payload.get("simulation_id") or str(uuid.uuid4())
    name = payload.get("name", "Simulation Run")
    rounds = int(payload.get("rounds", 6))
    attack_types = payload.get("attack_types", ["brute_force", "c2_beacon", "lateral_movement"])
    target_context = payload.get("target_context", {})

    config = SimulationConfig(
        simulation_id=sim_id,
        name=name,
        rounds=rounds,
        attack_types=attack_types,
        target_context=target_context,
        broadcast_live=True,
    )

    _simulations[sim_id] = {
        "simulation_id": sim_id,
        "name": name,
        "status": "running",
        "rounds_completed": 0,
        "rounds_total": rounds,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
    }

    background.add_task(_run_simulation_new, config)
    return {
        "simulation_id": sim_id,
        "status": "running",
        "message": f"Simulation '{name}' started with {rounds} rounds.",
    }


@router.get("/history")
async def simulation_history(db: AsyncSession = Depends(get_db)) -> list[dict]:
    """Return recent simulation history (DB + in-memory combined)."""
    history = []

    # In-memory new-style simulations
    for sim in sorted(
        _simulations.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )[:20]:
        history.append({
            "simulation_id": sim["simulation_id"],
            "name": sim["name"],
            "status": sim["status"],
            "rounds_completed": sim["rounds_completed"],
            "rounds_total": sim["rounds_total"],
            "started_at": sim.get("started_at"),
            "source": "memory",
        })

    # Legacy DB simulations
    try:
        result = await db.execute(
            select(SimulationRun).order_by(desc(SimulationRun.created_at)).limit(20)
        )
        for sim in result.scalars().all():
            history.append({
                "simulation_id": str(sim.id),
                "name": sim.name,
                "status": sim.status,
                "rounds_completed": None,
                "rounds_total": None,
                "started_at": sim.created_at.isoformat() if sim.created_at else None,
                "source": "db",
            })
    except Exception as exc:
        logger.warning("sim_history_db_error", error=str(exc))

    return history


@router.post("/quick-demo")
async def quick_demo() -> dict:
    """Run a synchronous 3-round demo simulation and return the full result."""
    sim_id = str(uuid.uuid4())
    config = SimulationConfig(
        simulation_id=sim_id,
        name="Quick Demo (3 rounds)",
        rounds=3,
        attack_types=["brute_force", "c2_beacon", "lateral_movement"],
        target_context={"network": "10.0.0.0/8", "environment": "demo"},
        broadcast_live=True,
    )
    engine = SimulationEngine()
    result = await engine.run_simulation(config=config)
    return _sim_result_to_dict(result)


@router.get("/{sim_id}/status")
async def get_simulation_status(sim_id: str) -> dict:
    """Return current status and round progress for a running simulation."""
    sim = _simulations.get(sim_id)
    if sim:
        return {
            "simulation_id": sim_id,
            "status": sim["status"],
            "rounds_completed": sim["rounds_completed"],
            "rounds_total": sim["rounds_total"],
            "started_at": sim.get("started_at"),
        }
    # Fall back to DB lookup
    raise HTTPException(
        status_code=404,
        detail=f"Simulation '{sim_id}' not found. Use /history to list all runs.",
    )


@router.get("/{sim_id}/results")
async def get_simulation_results(sim_id: str) -> dict:
    """Return the full SimulationResult for a completed simulation."""
    sim = _simulations.get(sim_id)
    if sim:
        if sim["status"] == "running":
            raise HTTPException(status_code=202, detail="Simulation still running.")
        if sim["result"] is None:
            raise HTTPException(status_code=404, detail="No result available yet.")
        return sim["result"]
    raise HTTPException(status_code=404, detail=f"Simulation '{sim_id}' not found.")


# ── Legacy endpoints (DB-backed) ──────────────────────────────────────────────

@router.get("", response_model=list[SimulationRunRead])
async def list_simulations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SimulationRun).order_by(desc(SimulationRun.created_at)).limit(50)
    )
    return result.scalars().all()


@router.post("/run", response_model=SimulationRunRead, status_code=202)
async def start_legacy_simulation(
    payload: SimulationRunCreate,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    sim = SimulationRun(
        name=payload.name,
        scenario=payload.scenario,
        status="running",
        red_agent_config=payload.red_agent_config,
        blue_agent_config=payload.blue_agent_config,
    )
    db.add(sim)
    await db.flush()
    await db.refresh(sim)
    sim_id = str(sim.id)

    background.add_task(_run_simulation_background, sim_id, payload.scenario)
    await manager.broadcast_event("simulation_started", {"id": sim_id, "scenario": payload.scenario})
    return sim


@router.get("/{simulation_id}", response_model=SimulationRunRead)
async def get_simulation(simulation_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SimulationRun).where(SimulationRun.id == simulation_id)
    )
    sim = result.scalar_one_or_none()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return sim


# ── Background task helpers ───────────────────────────────────────────────────

async def _run_simulation_new(config: SimulationConfig) -> None:
    """Background task for new-style simulation runs."""
    sim_id = config.simulation_id
    engine = SimulationEngine()
    try:
        result = await engine.run_simulation(config=config)
        result_dict = _sim_result_to_dict(result)
        if sim_id in _simulations:
            _simulations[sim_id]["status"] = "completed"
            _simulations[sim_id]["rounds_completed"] = config.rounds
            _simulations[sim_id]["result"] = result_dict
        logger.info("sim_new_complete", simulation_id=sim_id)
    except Exception as exc:
        logger.error("sim_new_error", simulation_id=sim_id, error=str(exc))
        if sim_id in _simulations:
            _simulations[sim_id]["status"] = "failed"
            _simulations[sim_id]["error"] = str(exc)


async def _run_simulation_background(simulation_id: str, scenario: str) -> None:
    """Background task for legacy DB-stored simulation runs."""
    from app.database import async_session_factory

    engine = SimulationEngine()

    async def on_event(event: dict) -> None:
        await manager.broadcast_event("sim_event", {"simulation_id": simulation_id, **event})

    async def on_alert(alert: dict) -> None:
        await manager.broadcast_event("sim_alert", {"simulation_id": simulation_id, **alert})

    try:
        results = await engine.run_simulation(
            simulation_id=simulation_id,
            scenario=scenario,
            on_event=on_event,
            on_alert=on_alert,
        )

        async with async_session_factory() as db:
            q = select(SimulationRun).where(SimulationRun.id == uuid.UUID(simulation_id))
            result = await db.execute(q)
            sim = result.scalar_one_or_none()
            if sim:
                sim.status = "completed"
                sim.events_generated = results["events_generated"]
                sim.alerts_triggered = results["alerts_triggered"]
                sim.detection_rate = results["detection_rate"]
                sim.mean_time_to_detect = results["mean_time_to_detect"]
                sim.duration_seconds = results["duration_seconds"]
                sim.red_agent_log = results["red_agent_log"]
                sim.blue_agent_log = results["blue_agent_log"]
                sim.findings = results["findings"]
                sim.recommendations = results["recommendations"]
                await db.commit()

        await manager.broadcast_event("simulation_complete", {
            "id": simulation_id,
            "detection_rate": results["detection_rate"],
            "events": results["events_generated"],
            "alerts": results["alerts_triggered"],
        })
    except Exception as exc:
        logger.error("simulation_error", simulation_id=simulation_id, error=str(exc))
        try:
            async with async_session_factory() as db:
                q = select(SimulationRun).where(SimulationRun.id == uuid.UUID(simulation_id))
                result = await db.execute(q)
                sim = result.scalar_one_or_none()
                if sim:
                    sim.status = "failed"
                    await db.commit()
        except Exception:
            pass
        await manager.broadcast_event("simulation_failed", {"id": simulation_id, "error": str(exc)})
