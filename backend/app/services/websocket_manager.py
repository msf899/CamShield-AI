"""
CamShield AI - WebSocket Manager
Pushes live scan updates to the React dashboard
"""
import json
import asyncio
from typing import List, Dict, Any
from fastapi import WebSocket


class WebSocketManager:
    """Manages active WebSocket connections and broadcasts live events."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event_type: str, data: Any):
        """Send event to all connected dashboard clients."""
        message = json.dumps({"type": event_type, "data": data})
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    # Convenience broadcast methods
    async def device_found(self, device: Dict):
        await self.broadcast("device_found", device)

    async def scan_progress(self, percent: int, message: str):
        await self.broadcast("scan_progress", {"percent": percent, "message": message})

    async def vulnerability_found(self, vuln: Dict):
        await self.broadcast("vulnerability_found", vuln)

    async def scan_complete(self, summary: Dict):
        await self.broadcast("scan_complete", summary)

    async def alert(self, severity: str, message: str, ip: str = ""):
        await self.broadcast("alert", {"severity": severity, "message": message, "ip": ip})


# Global singleton
ws_manager = WebSocketManager()
