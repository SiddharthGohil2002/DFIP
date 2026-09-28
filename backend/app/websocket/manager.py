import asyncio
from datetime import datetime, timezone
from fastapi import WebSocket
from typing import Dict, Set, Optional, Any
import logging

logger = logging.getLogger('dfip.websocket')

class Manager:
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.client_meta: Dict[WebSocket, dict] = {}
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    async def connect(self, user_id: str, ws: WebSocket, client_type: str = 'web', device_id: Optional[str] = None):
        await ws.accept()
        uid = str(user_id)
        self.connections.setdefault(uid, set()).add(ws)
        self.client_meta[ws] = {
            'user_id': uid,
            'client_type': client_type,
            'device_id': device_id,
            'connected_at': datetime.now(timezone.utc).isoformat()
        }
        logger.info(f"WebSocket client connected: user={uid} type={client_type} device={device_id}")
        # Broadcast connection event
        if client_type == 'desktop':
            await self.broadcast_event('DESKTOP_CONNECTED', {
                'user_id': uid,
                'device_id': device_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })

    def disconnect(self, user_id: str, ws: WebSocket):
        uid = str(user_id)
        if uid in self.connections:
            self.connections[uid].discard(ws)
            if not self.connections[uid]:
                del self.connections[uid]
        meta = self.client_meta.pop(ws, None)
        if meta and meta.get('client_type') == 'desktop':
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.broadcast_event('DESKTOP_DISCONNECTED', {
                        'user_id': uid,
                        'device_id': meta.get('device_id'),
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }),
                    self.loop
                )

    async def send(self, user_id: str, message: dict):
        uid = str(user_id)
        sockets = list(self.connections.get(uid, set()))
        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(uid, ws)

    async def broadcast(self, message: dict):
        for uid in list(self.connections.keys()):
            await self.send(uid, message)

    async def broadcast_event(self, event_type: str, data: dict):
        msg = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        await self.broadcast(msg)

    async def send_event(self, user_id: str, event_type: str, data: dict):
        msg = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        await self.send(user_id, msg)

    async def send_desktop_event(self, user_id: str, event_type: str, data: dict):
        await self.send_event(user_id, event_type, data)

    def emit_sync(self, event_type: str, data: dict, user_id: Optional[str] = None):
        """Thread-safe synchronous emitter that dispatches to the running asyncio loop."""
        try:
            loop = self.loop
            if not loop or loop.is_closed():
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    return
            
            if user_id:
                coro = self.send_event(user_id, event_type, data)
            else:
                coro = self.broadcast_event(event_type, data)

            if loop.is_running():
                asyncio.run_coroutine_threadsafe(coro, loop)
            else:
                loop.run_until_complete(coro)
        except Exception as e:
            logger.debug(f"Failed to emit WS event {event_type}: {e}")

manager = Manager()

def emit_event(event_type: str, data: dict, user_id: Optional[str] = None):
    manager.emit_sync(event_type, data, user_id)
