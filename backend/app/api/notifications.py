from fastapi import APIRouter,Depends,HTTPException
from datetime import datetime,timezone
from bson import ObjectId
from ..security import current_user
from ..database import get_db
r=APIRouter(prefix='/notifications',tags=['notifications'])
@r.get('')
def notifications(u=Depends(current_user)):
    out=[]
    for x in get_db()['notifications'].find({'user_id':str(u['_id'])}).sort('created_at',-1).limit(100):
        x['_id']=str(x['_id']);x['created_at']=x['created_at'].isoformat();out.append(x)
    return {'data':out}
@r.patch('/{nid}/read')
def read(nid,u=Depends(current_user)):
    try:oid=ObjectId(nid)
    except:raise HTTPException(400,'Invalid notification id')
    res=get_db()['notifications'].update_one({'_id':oid,'user_id':str(u['_id'])},{'$set':{'read':True,'read_at':datetime.now(timezone.utc)}})
    if not res.matched_count:raise HTTPException(404,'Notification not found')
    return {'ok':True}
