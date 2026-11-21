"""
WebSocket Manager.

Handles real-time connections for logcat streaming,
scan progress updates, and device status notifications.
"""

import json
import logging
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError, jwt

from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        # channel -> set of connections
        self._connections: Dict[str, Set[WebSocket]] = {}
        # websocket -> user info
        self._user_map: Dict[WebSocket, dict] = {}

    async def connect(
        self, websocket: WebSocket, channel: str = "general", user_info: dict | None = None
    ) -> None:
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        if channel not in self._connections:
            self._connections[channel] = set()
        self._connections[channel].add(websocket)
        if user_info:
            self._user_map[websocket] = user_info
        logger.info(f"WebSocket connected to channel '{channel}' ({len(self._connections[channel])} total)")

    def disconnect(self, websocket: WebSocket, channel: str = "general") -> None:
        """Remove a WebSocket connection."""
        if channel in self._connections:
            self._connections[channel].discard(websocket)
            if not self._connections[channel]:
                del self._connections[channel]
        self._user_map.pop(websocket, None)

    async def send_message(self, websocket: WebSocket, message: dict) -> None:
        """Send a JSON message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            pass

    async def broadcast(self, channel: str, message: dict) -> None:
        """Broadcast a message to all connections in a channel."""
        if channel not in self._connections:
            return

        disconnected = []
        for ws in self._connections[channel]:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)

        # Clean up disconnected clients
        for ws in disconnected:
            self._connections[channel].discard(ws)

    async def broadcast_all(self, message: dict) -> None:
        """Broadcast to all channels."""
        for channel in list(self._connections.keys()):
            await self.broadcast(channel, message)

    def get_connection_count(self, channel: Optional[str] = None) -> int:
        """Get the number of active connections."""
        if channel:
            return len(self._connections.get(channel, set()))
        return sum(len(conns) for conns in self._connections.values())


# Singleton manager
ws_manager = ConnectionManager()


def _validate_ws_token(token: str) -> Optional[dict]:
    """Validate a JWT token for WebSocket authentication."""
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        if payload.get("type") != "access":
            return None
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "role": payload.get("role"),
        }
    except JWTError:
        return None


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(None),
    channel: str = Query("general"),
):
    """
    Main WebSocket endpoint.
    
    Channels:
    - general: General notifications
    - logcat:{serial}: Device logcat stream
    - scan: Scan progress updates
    - devices: Device status changes
    """
    # Authenticate
    user_info = None
    if token:
        user_info = _validate_ws_token(token)
        if not user_info:
            await websocket.close(code=4001, reason="Invalid token")
            return
    else:
        await websocket.close(code=4001, reason="Token required")
        return

    await ws_manager.connect(websocket, channel, user_info)

    try:
        # Send welcome message
        await ws_manager.send_message(websocket, {
            "type": "connected",
            "channel": channel,
            "message": f"Connected to {channel}",
        })

        # Listen for messages
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                msg_type = message.get("type", "")

                if msg_type == "ping":
                    await ws_manager.send_message(websocket, {"type": "pong"})

                elif msg_type == "subscribe":
                    new_channel = message.get("channel", "general")
                    await ws_manager.connect(websocket, new_channel, user_info)
                    await ws_manager.send_message(websocket, {
                        "type": "subscribed",
                        "channel": new_channel,
                    })

                elif msg_type == "unsubscribe":
                    old_channel = message.get("channel", "general")
                    ws_manager.disconnect(websocket, old_channel)

            except json.JSONDecodeError:
                await ws_manager.send_message(websocket, {
                    "type": "error",
                    "message": "Invalid JSON",
                })

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
        logger.info(f"WebSocket disconnected from '{channel}'")


@router.get("/api/v1/ws/status")
async def ws_status():
    """Get WebSocket connection statistics."""
    return {
        "total_connections": ws_manager.get_connection_count(),
    }
