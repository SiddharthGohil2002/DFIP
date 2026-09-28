from datetime import datetime,timezone
from ..database import get_db
async def create(user_id,title,message,level='INFO'):
    now=datetime.now(timezone.utc)
    r=get_db()['notifications'].insert_one({'user_id':str(user_id),'title':title,'message':message,'level':level,'read':False,'created_at':now})
    from ..websocket.manager import manager
    await manager.send(str(user_id),{'type':'notification','notification':{'_id':str(r.inserted_id),'title':title,'message':message,'level':level,'read':False,'created_at':now.isoformat()}})
    return str(r.inserted_id)
