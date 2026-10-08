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

    def recipients(self, data: dict) -> Set[str]:
        """Connected users allowed to receive an event: the members of the case it concerns
        (found from case_id, evidence_id or job_id) plus administrators. Events about one
        user, such as a desktop connecting, go to that user and administrators. Anything
        that cannot be attributed goes to administrators only."""
        connected = set(self.connections)
        if not connected:
            return set()
        try:
            from bson import ObjectId
            from ..database import get_db
            db = get_db()
            ids = [ObjectId(x) for x in connected if ObjectId.is_valid(x)]
            admins = {str(u['_id']) for u in db['users'].find({'_id': {'$in': ids}, 'role': 'ADMIN'}, {'_id': 1})}
            case_id, owner = data.get('case_id'), data.get('user_id')
            if not case_id and data.get('job_id'):
                job = db['jobs'].find_one({'job_id': data['job_id']}, {'payload': 1, 'created_by': 1}) or {}
                owner = owner or job.get('created_by')
                data = {**data, 'evidence_id': data.get('evidence_id') or (job.get('payload') or {}).get('evidence_id')}
            if not case_id and data.get('evidence_id'):
                ev = db['evidence'].find_one({'evidence_id': data['evidence_id']}, {'case_id': 1})
                case_id = ev and ev.get('case_id')
            if case_id:
                c = db['cases'].find_one({'case_id': case_id}, {'investigator_id': 1, 'created_by': 1, 'member_ids': 1}) or {}
                members = {c.get('investigator_id'), c.get('created_by'), *(c.get('member_ids') or [])}
                return (members | admins) & connected
            return ({str(owner)} | admins) & connected if owner else admins
        except Exception:
            logger.warning('Could not resolve WebSocket recipients; event not delivered', exc_info=True)
            return set()

    async def broadcast_event(self, event_type: str, data: dict, recipients: Optional[Set[str]] = None):
        msg = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        for uid in (self.recipients(data) if recipients is None else recipients):
            await self.send(uid, msg)

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
                # Audience is resolved here, in the calling thread, so database lookups stay off the event loop.
                coro = self.broadcast_event(event_type, data, self.recipients(data))

            if loop.is_running():
                asyncio.run_coroutine_threadsafe(coro, loop)
            else:
                loop.run_until_complete(coro)
        except Exception as e:
            logger.debug(f"Failed to emit WS event {event_type}: {e}")

manager = Manager()

def emit_event(event_type: str, data: dict, user_id: Optional[str] = None):
    manager.emit_sync(event_type, data, user_id)
