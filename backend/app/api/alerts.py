import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.database import get_db
from app.models import Alert
from app.schemas import AlertCreate, AlertUpdate, AlertRead
from app.websocket.manager import manager
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("", response_model=list[AlertRead])
async def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    false_positive: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert).order_by(desc(Alert.created_at))
    if severity:
        q = q.where(Alert.severity == severity)
    if false_positive is not None:
        q = q.where(Alert.false_positive == false_positive)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=AlertRead, status_code=201)
async def create_alert(payload: AlertCreate, db: AsyncSession = Depends(get_db)):
    alert = Alert(**payload.model_dump())
    db.add(alert)
    await db.flush()
    await db.refresh(alert)
    await manager.broadcast_event("new_alert", {
        "id": str(alert.id),
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
    })
    return alert


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertRead)
async def update_alert(
    alert_id: uuid.UUID,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(alert, field, value)
    await db.flush()
    await db.refresh(alert)
    return alert
