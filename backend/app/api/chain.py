from fastapi import APIRouter,Depends,HTTPException
from bson import ObjectId
from ..security import current_user,require_permission
from ..database import get_db
from ..repositories.cases import allowed_case_query,get_case
from ..services.audit import verify_chain
r=APIRouter(prefix='/chain',tags=['chain'])

@r.get('')
def chain(case_id:str|None=None,evidence_id:str|None=None,u=Depends(current_user)):
    """Chain-of-custody records (registration, verification, integrity checks,
    recoveries) for the evidence the user may access, newest first."""
    db=get_db()
    if case_id:
        if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
        q={'case_id':case_id}
    elif u['role']=='ADMIN':
        q={}
    else:
        q={'case_id':{'$in':[x['case_id'] for x in db['cases'].find(allowed_case_query(u),{'case_id':1})]}}
    if evidence_id: q['evidence_id']=evidence_id
    rows=[]
    names={}  # older records carry only the user ID; show the name instead
    for x in db['chain_of_custody'].find(q).sort('timestamp',-1).limit(1000):
        x['_id']=str(x['_id'])
        if not x.get('user_name') and ObjectId.is_valid(str(x.get('user_id'))):
            uid=str(x['user_id'])
            if uid not in names: names[uid]=(db['users'].find_one({'_id':ObjectId(uid)},{'name':1}) or {}).get('name')
            x['user_name']=names[uid]
        if hasattr(x.get('timestamp'),'isoformat'): x['timestamp']=x['timestamp'].isoformat()
        rows.append(x)
    return {'data':rows,'audit_chain':verify_chain()}

@r.get('/verify')
def verify(u=Depends(require_permission('AUDIT_READ'))): return verify_chain()
