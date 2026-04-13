"""
Ingestion API router.

POST /ingest        — normalize + publish a raw log batch
POST /demo          — start demo scenario (background task)
POST /stress-test   — run throughput stress test (background task)
GET  /stats         — live throughput / queue / DLQ stats
GET  /status        — pipeline running state
"""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from app.ingestion.pipeline import get_pipeline
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()

# ── Request/response schemas ──────────────────────────────────────────────────

class IngestRequest(BaseModel):
    events: list[dict] = Field(..., min_length=1, max_length=10_000)
    log_format: str = Field("auto", pattern="^(auto|netflow|windows_event|http_access|unified)$")


class IngestResponse(BaseModel):
    accepted: int
    rejected: int
    queued: int
    format: str


class StressTestRequest(BaseModel):
    target_eps: int = Field(600, ge=1, le=5000)
    duration: int = Field(30, ge=5, le=300)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/ingest", response_model=IngestResponse)
async def ingest_events(body: IngestRequest):
    """
    Normalize and publish a batch of raw logs.

    Accepts netflow, windows_event, http_access, or unified-schema dicts.
    Returns counts of accepted/rejected/queued events.
    """
    pipeline = get_pipeline()
    if not pipeline._running:
        await pipeline.start()

    result = await pipeline.ingest_events(body.events, log_format=body.log_format)
    return IngestResponse(**result)


@router.post("/demo", status_code=202)
async def start_demo(background: BackgroundTasks):
    """
    Load demo_dataset.json and ingest at 50 events/sec in the background.
    Progress events are broadcast over WebSocket ("demo_progress").
    """
    pipeline = get_pipeline()
    if not pipeline._running:
        await pipeline.start()

    background.add_task(_run_demo_bg, pipeline)
    return {"status": "started", "message": "Demo ingesting at 50 eps — watch /ws for progress"}


@router.post("/stress-test", status_code=202)
async def start_stress_test(body: StressTestRequest, background: BackgroundTasks):
    """
    Run a synthetic stress test at target_eps for duration seconds.
    Results are broadcast over WebSocket ("stress_test_complete").
    """
    pipeline = get_pipeline()
    if not pipeline._running:
        await pipeline.start()

    background.add_task(_run_stress_bg, pipeline, body.target_eps, body.duration)
    return {
        "status": "started",
        "target_eps": body.target_eps,
        "duration_s": body.duration,
        "message": "Stress test running — watch /ws for results",
    }


@router.get("/stats")
async def get_stats():
    """Live ingestion stats: EPS, queue depth, DLQ size, totals."""
    pipeline = get_pipeline()
    if not pipeline._running:
        return {
            "running": False,
            "queue_depth": 0,
            "dlq_size": 0,
            "eps": 0,
            "total_processed": 0,
            "errors": 0,
        }
    return await pipeline.stats()


@router.get("/status")
async def get_status():
    """Pipeline running state and uptime."""
    pipeline = get_pipeline()
    if not pipeline._running:
        return {"running": False, "message": "Pipeline not started"}
    stats = await pipeline.stats()
    return {
        "running": True,
        "uptime_s": stats.get("uptime_s", 0),
        "eps": stats.get("eps", 0),
        "queue_depth": stats.get("queue_depth", 0),
    }


# ── Background helpers ────────────────────────────────────────────────────────

async def _run_demo_bg(pipeline) -> None:
    try:
        await pipeline.run_demo_scenario()
    except Exception as exc:
        logger.error("demo_bg_error", error=str(exc))


async def _run_stress_bg(pipeline, target_eps: int, duration: int) -> None:
    try:
        await pipeline.run_stress_test(target_eps=target_eps, duration=duration)
    except Exception as exc:
        logger.error("stress_bg_error", error=str(exc))
