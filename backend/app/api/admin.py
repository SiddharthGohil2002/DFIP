from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field,EmailStr
from datetime import datetime,timezone
from bson import ObjectId
from ..security import require_roles,hash_password,require_permission
from ..repositories.users import list_users,get_by_email,serial as user_serial
from ..repositories.cases import allowed_case_query
from ..database import get_db
from ..services.audit import log
from ..services.notifications import create as notify
r=APIRouter(prefix='/admin',tags=['admin'])
class UserCreate(BaseModel):name:str=Field(min_length=2,max_length=120);email:EmailStr;role:str='INVESTIGATOR';password:str=Field(min_length=12,max_length=128)
class UserUpdate(BaseModel):name:str|None=None;role:str|None=None;status:str|None=None
class RoleUpdate(BaseModel):permissions:list[str]
ROLES={'ADMIN','INVESTIGATOR','ANALYST','VIEWER'}
@r.get('/users')
def users(u=Depends(require_permission('USER_MANAGE'))):return {'data':[user_serial(x) for x in list_users()]}
@r.post('/users')
async def create_user(x:UserCreate,u=Depends(require_permission('USER_MANAGE'))):
    if x.role not in ROLES:raise HTTPException(400,'Invalid role')
    if get_by_email(str(x.email)):raise HTTPException(409,'Email already exists')
    now=datetime.now(timezone.utc);d={'name':x.name.strip(),'email':str(x.email).lower(),'role':x.role,'status':'ACTIVE','password_hash':hash_password(x.password),'created_at':now,'updated_at':now};res=get_db()['users'].insert_one(d);d['_id']=res.inserted_id;log(u,'USER_CREATED','user',res.inserted_id,{'role':x.role});await notify(str(res.inserted_id),'Welcome to DFIP','Your account has been created.')
    return user_serial({k:v for k,v in d.items() if k!='password_hash'})
@r.patch('/users/{uid}')
async def update_user(uid:str,x:UserUpdate,u=Depends(require_permission('USER_MANAGE'))):
    try:oid=ObjectId(uid)
    except:raise HTTPException(400,'Invalid user id')
    updates={k:v for k,v in x.model_dump().items() if v is not None}
    if 'role' in updates and updates['role'] not in ROLES:raise HTTPException(400,'Invalid role')
    if 'status' in updates and updates['status'] not in {'ACTIVE','SUSPENDED','DISABLED'}:raise HTTPException(400,'Invalid status')
    updates['updated_at']=datetime.now(timezone.utc);res=get_db()['users'].update_one({'_id':oid},{'$set':updates})
    if not res.matched_count:raise HTTPException(404,'User not found')
    log(u,'USER_UPDATED','user',uid,updates);fresh=get_db()['users'].find_one({'_id':oid},{'password_hash':0});return user_serial(fresh)
@r.get('/investigators')
def investigators(all:bool=False,u=Depends(require_permission('CASE_UPDATE'))):
    """Active users who can lead a case; `all=true` adds viewers (who can be case members)."""
    roles=['ADMIN','INVESTIGATOR','ANALYST']+(['VIEWER'] if all else [])
    return {'data':[user_serial(x) for x in get_db()['users'].find({'role':{'$in':roles},'status':'ACTIVE'},{'password_hash':0}).sort('name',1)]}
@r.get('/roles')
def roles(u=Depends(require_permission('ROLE_MANAGE'))):
    return {'data':[user_serial(x) for x in get_db()['roles'].find().sort('name',1)]}
@r.patch('/roles/{name}')
def update_role(name:str,x:RoleUpdate,u=Depends(require_permission('ROLE_MANAGE'))):
    if name not in ROLES:raise HTTPException(404,'Role not found')
    get_db()['roles'].update_one({'name':name},{'$set':{'permissions':sorted(set(x.permissions)),'updated_at':datetime.now(timezone.utc)}},upsert=True);log(u,'ROLE_UPDATED','role',name,{'permissions':x.permissions});return {'name':name,'permissions':sorted(set(x.permissions))}
@r.get('/security')
def security(u=Depends(require_roles('ADMIN'))):
    events=list(get_db()['audit_logs'].find({'action':{'$in':['LOGIN','EVIDENCE_VERIFIED','USER_UPDATED']}}).sort('timestamp',-1).limit(100));out=[]
    for x in events:
        x['_id']=str(x['_id'])
        if hasattr(x.get('timestamp'),'isoformat'): x['timestamp']=x['timestamp'].isoformat()
        out.append(x)
    return {'data':out}
def _audit_scope(u):
    """Administrators see the whole log; everyone else sees their own actions and
    actions on the cases they can open (matched by case, evidence and report IDs)."""
    if u['role']=='ADMIN':return {}
    db=get_db();cases=list(db['cases'].find(allowed_case_query(u),{'case_id':1}))
    case_ids=[c['case_id'] for c in cases]
    ev=list(db['evidence'].find({'case_id':{'$in':case_ids}},{'evidence_id':1}))
    ids=case_ids+[str(c['_id']) for c in cases]+[e['evidence_id'] for e in ev]+[str(e['_id']) for e in ev]
    ids+=[x['report_id'] for x in db['reports'].find({'case_id':{'$in':case_ids}},{'report_id':1})]
    return {'$or':[{'user_id':str(u['_id'])},{'metadata.case_id':{'$in':case_ids}},{'resource_id':{'$in':ids}}]}
@r.get('/audit')
def audit(u=Depends(require_permission('AUDIT_READ'))):
    docs=[]
    for x in get_db()['audit_logs'].find(_audit_scope(u)).sort('timestamp',-1).limit(300):
        x['_id']=str(x['_id'])
        if hasattr(x.get('timestamp'),'isoformat'): x['timestamp']=x['timestamp'].isoformat()
        docs.append(x)
    return {'data':docs}
@r.get('/stats')
def stats(u=Depends(require_roles('ADMIN'))):
    db=get_db();return {'users':db['users'].count_documents({}),'active_users':db['users'].count_documents({'status':'ACTIVE'}),'cases':db['cases'].count_documents({}),'evidence':db['evidence'].count_documents({}),'verified':db['evidence'].count_documents({'verification_status':'VERIFIED'}),'reports':db['reports'].count_documents({})}


class RetentionPolicy(BaseModel):
    enabled: bool = True
    days: int = Field(ge=1, le=36500)


def _retention_view():
    from ..services.retention import due_cases, policy
    db = get_db()
    plain = lambda v: v.isoformat() if hasattr(v, 'isoformat') else v
    due = [{'case_id': c['case_id'], 'name': c.get('name'), 'status': c.get('status'), 'closed_at': plain(c.get('closed_at')),
            'due_at': plain((c.get('retention') or {}).get('due_at')), 'notified_at': plain((c.get('retention') or {}).get('notified_at')),
            'legal_hold': bool((c.get('legal_hold') or {}).get('active'))} for c in due_cases()]
    closed = [{'case_id': c['case_id'], 'name': c.get('name'), 'status': c.get('status'), 'closed_at': plain(c.get('closed_at')),
               'due_at': plain((c.get('retention') or {}).get('due_at'))}
              for c in db['cases'].find({'retention.due_at': {'$exists': True}, 'deleted': {'$ne': True}}).sort('retention.due_at', 1).limit(500)]
    runs = [{'at': plain(x['at']), 'due': x.get('due', []), 'held': x.get('held', []), 'notified': x.get('notified', [])}
            for x in db['retention_runs'].find().sort('at', -1).limit(10)]
    deleted = [{'case_id': c['case_id'], 'name': c.get('name'), 'deleted_at': plain(c.get('deleted_at')), 'deleted_by_name': c.get('deleted_by_name'),
                'reason': c.get('deletion_reason')} for c in db['cases'].find({'deleted': True}).sort('deleted_at', -1).limit(100)]
    p = policy()
    return {'policy': {**p, 'set_at': plain(p.get('set_at'))}, 'due': due, 'closed': closed, 'runs': runs, 'deleted': deleted}


@r.get('/retention')
def retention(u=Depends(require_permission('SYSTEM_MANAGE'))):
    """The retention policy, the closed cases with their due dates, those due now, the last daily checks and the cases
    deleted."""
    return _retention_view()


@r.put('/retention')
def set_retention(x: RetentionPolicy, u=Depends(require_permission('SYSTEM_MANAGE'))):
    """Sets how long closed cases are kept. It applies to cases closed from now on; cases already closed keep their date."""
    from ..services.retention import set_policy
    set_policy(x.enabled, x.days, u)
    log(u, 'RETENTION_POLICY_SET', 'settings', 'retention', {'enabled': x.enabled, 'days': x.days})
    return _retention_view()


@r.post('/retention/run')
def run_retention(u=Depends(require_permission('SYSTEM_MANAGE'))):
    """Runs the daily retention check now: administrators are notified of the cases due (cases under legal hold are
    listed as held). Nothing is deleted."""
    from ..services.retention import run_check
    result = run_check()
    log(u, 'RETENTION_CHECK_RUN', 'settings', 'retention', result)
    return result
