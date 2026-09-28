from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from .security import decode_token
from .repositories.users import get_user_by_id
from .websocket.manager import manager
import json

r = APIRouter()

@r.websocket('/ws')
async def websocket(ws: WebSocket):
    token = ws.query_params.get('token')
    client_type = ws.query_params.get('client', 'web')
    device_id = ws.query_params.get('device_id')
    u = None
    try:
        p = decode_token(token or '')
        u = get_user_by_id(p['sub'])
        if not u or u.get('status') != 'ACTIVE':
            await ws.close(code=1008)
            return

        await manager.connect(str(u['_id']), ws, client_type=client_type, device_id=device_id)
        while True:
            text = await ws.receive_text()
            try:
                data = json.loads(text)
                if data.get('type') == 'ping':
                    await ws.send_json({'type': 'pong'})
            except Exception:
                pass
    except WebSocketDisconnect:
        if u:
            manager.disconnect(str(u['_id']), ws)
    except Exception:
        try:
            await ws.close(code=1008)
        except Exception:
            pass
