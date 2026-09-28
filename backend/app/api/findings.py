from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from ..security import current_user, require_write
from ..database import get_db
from ..repositories.cases import get_case
from ..services.audit import log
from ..websocket.manager import manager

r = APIRouter(prefix='/findings', tags=['findings'])

class FindingIn(BaseModel):
    case_id: str
    title: str = Field(min_length=2)
    description: str
    severity: str = 'MEDIUM'
    evidence_ids: list[str] = []
    timeline_ids: list[str] = []

@r.get('')
def list_findings(case_id: str | None = None, u=Depends(current_user)):
    q = {'case_id': case_id} if case_id else {}
    out = []
    for x in get_db()['findings'].find(q).sort('created_at', -1):
        if not get_case(x['case_id'], u):
            continue
        x['_id'] = str(x['_id'])
        x['created_at'] = x['created_at'].isoformat()
        out.append(x)
    return {'data': out}

@r.post('')
def create(x: FindingIn, u=Depends(require_write('FINDING_CREATE'))):
    if not get_case(x.case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if x.severity not in {'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'Invalid severity')
    
    now = datetime.now(timezone.utc)
    d = {
        **x.model_dump(),
        'created_by': str(u['_id']),
        'created_at': now,
        'updated_at': now
    }
    res = get_db()['findings'].insert_one(d)
    log(u, 'FINDING_CREATED', 'finding', res.inserted_id, {'case_id': x.case_id})
    d['_id'] = str(res.inserted_id)
    d['created_at'] = now.isoformat()
    
    manager.emit_sync('FINDING_CREATED', {
        '_id': d['_id'],
        'case_id': x.case_id,
        'title': x.title,
        'severity': x.severity,
        'created_at': d['created_at']
    })
    return d
