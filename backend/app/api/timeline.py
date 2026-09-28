from fastapi import APIRouter,Depends
from ..security import current_user
from ..database import get_db
r=APIRouter(prefix='/timeline',tags=['timeline'])
@r.get('')
def timeline(u=Depends(current_user)):
    q={}
    if u['role']!='ADMIN':q={'case_id':{'$in':[x['case_id'] for x in get_db()['cases'].find({'investigator_id':str(u['_id'])},{'case_id':1})]}}
    out=[]
    for x in get_db()['timeline_events'].find(q).sort('timestamp',-1).limit(500):
        x['_id']=str(x['_id']);x['timestamp']=x['timestamp'].isoformat() if hasattr(x['timestamp'],'isoformat') else str(x['timestamp']);out.append(x)
    return {'data':out}
