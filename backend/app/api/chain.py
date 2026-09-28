from fastapi import APIRouter,Depends
from ..security import current_user,require_permission
from ..database import get_db
from ..services.audit import verify_chain
r=APIRouter(prefix='/chain',tags=['chain'])
@r.get('')
def chain(u=Depends(current_user)):
    rows=[]
    for x in get_db()['audit_logs'].find({'action':{'$regex':'EVIDENCE|CHAIN'}}).sort('timestamp',-1).limit(1000):
        x['_id']=str(x['_id']);rows.append(x)
    return {'data':rows,'audit_chain':verify_chain()}
@r.get('/verify')
def verify(u=Depends(require_permission('AUDIT_READ'))): return verify_chain()
