"""
AuditMiddleware — captures every API call and fires an audit log entry.

Skips:
  - /health  (high-frequency health probe)
  - /ws      (WebSocket upgrade)
  - /docs, /redoc, /openapi.json  (Swagger UI assets)

Logs everything else under /api/v1/ as actor_type="system", action="api_call".
The actor_id is the client IP; metadata includes method, path, status, duration.

Audit writes are fire-and-forget so the middleware adds no latency to the
request path.
"""
from __future__ import annotations

import time
from typing import Callable

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)

# Paths to skip entirely — health probes, WS handshake, Swagger UI
_SKIP_PREFIXES = ("/health", "/ws", "/docs", "/redoc", "/openapi")


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Starlette BaseHTTPMiddleware that records every significant API call
    to the AuditLog via fire-and-forget background task.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Fast-exit: skip noise
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        # Only audit recognised API paths
        if not path.startswith("/api/v1/"):
            return await call_next(request)

        t0 = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = round((time.perf_counter() - t0) * 1000)

        # Resolve caller identity (IP or forwarded header)
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        result = "success" if response.status_code < 400 else "failed"

        # Fire-and-forget — does NOT block the response
        try:
            from app.services.audit_service import fire_and_forget, log_event
            fire_and_forget(log_event(
                actor_type="human",
                actor_id=client_ip,
                action="api_call",
                target_type="endpoint",
                target_id=path,
                result=result,
                duration_ms=duration_ms,
                metadata={
                    "method": request.method,
                    "path": path,
                    "status_code": response.status_code,
                    "query": str(request.query_params) or None,
                },
            ))
        except Exception as exc:
            logger.warning("audit_middleware_error", path=path, error=str(exc))

        return response
