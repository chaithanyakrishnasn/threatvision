import json
import asyncio
from typing import Any
from fastapi import WebSocket
import structlog

logger = structlog.get_logger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("ws_client_connected", total=len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("ws_client_disconnected", total=len(self.active_connections))

    async def send_personal(self, data: Any, websocket: WebSocket) -> None:
        payload = json.dumps(data) if not isinstance(data, str) else data
        await websocket.send_text(payload)

    async def broadcast(self, data: Any) -> None:
        if not self.active_connections:
            return
        payload = json.dumps(data) if not isinstance(data, str) else data
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

    async def broadcast_event(self, event_type: str, payload: dict) -> None:
        await self.broadcast({"type": event_type, "data": payload})

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


manager = ConnectionManager()
