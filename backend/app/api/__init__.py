from fastapi import APIRouter
from .incidents import router as incidents_router
from .alerts import router as alerts_router
from .simulation import router as simulation_router
from .threats import router as threats_router
from .playbooks import router as playbooks_router
from .dashboard import router as dashboard_router
from .ingestion import router as ingestion_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(incidents_router, prefix="/incidents",  tags=["incidents"])
api_router.include_router(alerts_router,    prefix="/alerts",     tags=["alerts"])
api_router.include_router(simulation_router,prefix="/simulation", tags=["simulation"])
api_router.include_router(threats_router,   prefix="/threats",    tags=["threats"])
api_router.include_router(playbooks_router, prefix="/playbooks",  tags=["playbooks"])
api_router.include_router(dashboard_router, prefix="/dashboard",  tags=["dashboard"])
api_router.include_router(ingestion_router, prefix="/ingestion",  tags=["ingestion"])
