from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from ..security import current_user, require_permission, require_desktop_workstation
from bson import ObjectId
from ..repositories.cases import list_cases, create_case, get_case, col
from ..services.audit import log
from ..services.notifications import create as notify
from ..database import get_db
from ..websocket.manager import manager

r = APIRouter(prefix='/cases', tags=['cases'])

class CaseCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = ''
    priority: str = 'MEDIUM'
    investigator_id: str | None = None

class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    priority: str | None = None
    status: str | None = None
    investigator_id: str | None = None

@r.get('')
def get_cases(u=Depends(current_user)):
    return {'data': list_cases(u)}

@r.get('/{case_id}')
def one(case_id: str, u=Depends(current_user)):
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    return c

@r.post('')
def post_case(x: CaseCreate, u=Depends(require_desktop_workstation)):
    if x.priority not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'Invalid priority')
    if x.investigator_id:
        assignee = get_db()['users'].find_one({'_id': ObjectId(x.investigator_id), 'status': 'ACTIVE'}) if ObjectId.is_valid(x.investigator_id) else None
        if not assignee:
            raise HTTPException(400, 'Invalid investigator assignment')
    
    c = create_case(x.model_dump(), u)
    log(u, 'CASE_CREATED', 'case', c['_id'], {'case_id': c['case_id']})
    
    # Broadcast to all clients (both web and desktop)
    manager.emit_sync('CASE_CREATED', {
        'case_id': c['case_id'],
        'name': c['name'],
        'priority': c['priority'],
        'status': c['status'],
        'created_at': c['created_at']
    })
    
    if c.get('investigator_id') and c['investigator_id'] != str(u['_id']):
        import asyncio
        asyncio.create_task(notify(c['investigator_id'], 'Case assigned', f'{c["case_id"]} was assigned to you.'))
    return c

@r.patch('/{case_id}')
async def update_case(case_id: str, x: CaseUpdate, u=Depends(require_desktop_workstation)):
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    updates = {k: v for k, v in x.model_dump().items() if v is not None}
    if 'investigator_id' in updates:
        try:
            assignee = get_db()['users'].find_one({'_id': ObjectId(updates['investigator_id']), 'status': 'ACTIVE'})
        except Exception:
            assignee = None
        if not assignee:
            raise HTTPException(400, 'Invalid investigator assignment')
    if 'status' in updates and updates['status'] not in {'OPEN', 'IN_PROGRESS', 'ON_HOLD', 'COMPLETED', 'ARCHIVED'}:
        raise HTTPException(400, 'Invalid status')
    if 'priority' in updates and updates['priority'] not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'Invalid priority')
    
    updates['updated_at'] = datetime.now(timezone.utc)
    col().update_one({'case_id': case_id}, {'$set': updates})
    fresh = get_case(case_id, u)
    log(u, 'CASE_UPDATED', 'case', fresh['_id'], updates)
    
    manager.emit_sync('CASE_UPDATED', {
        'case_id': case_id,
        'updates': updates
    })
    
    target = updates.get('investigator_id') or c.get('investigator_id')
    if target and target != str(u['_id']):
        await notify(target, 'Case updated', f'{case_id} was updated.', 'INFO')
    return fresh
