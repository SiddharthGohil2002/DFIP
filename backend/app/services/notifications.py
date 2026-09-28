import asyncio
from datetime import datetime,timezone
from ..database import get_db

def _store(user_id,title,message,level):
    now=datetime.now(timezone.utc)
    r=get_db()['notifications'].insert_one({'user_id':str(user_id),'title':title,'message':message,'level':level,'read':False,'created_at':now})
    return str(r.inserted_id),{'type':'notification','notification':{'_id':str(r.inserted_id),'title':title,'message':message,'level':level,'read':False,'created_at':now.isoformat()}}

async def create(user_id,title,message,level='INFO'):
    nid,msg=_store(user_id,title,message,level)
    from ..websocket.manager import manager
    await manager.send(str(user_id),msg)
    return nid

def create_sync(user_id,title,message,level='INFO'):
    """For sync endpoints (FastAPI threadpool): stores the notification and hands
    the WebSocket push to the server's event loop instead of awaiting it."""
    nid,msg=_store(user_id,title,message,level)
    from ..websocket.manager import manager
    if manager.loop and manager.loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.send(str(user_id),msg),manager.loop)
    return nid
