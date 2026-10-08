from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from ..security import current_user, require_permission, require_write
from bson import ObjectId
from ..repositories.cases import list_cases, create_case, get_case, col
from ..services.audit import log
from ..services.notifications import create as notify, create_sync as notify_sync
from ..database import get_db
from ..websocket.manager import manager

r = APIRouter(prefix='/cases', tags=['cases'])

class CaseCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = ''
    priority: str = 'MEDIUM'
    investigator_id: str | None = None

class CaseUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=120)
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
def post_case(x: CaseCreate, u=Depends(require_write('CASE_CREATE'))):
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
        notify_sync(c['investigator_id'], 'Case assigned', f'{c["case_id"]} was assigned to you.')
    return c

@r.patch('/{case_id}')
async def update_case(case_id: str, x: CaseUpdate, u=Depends(require_write('CASE_UPDATE'))):
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    updates = {k: v for k, v in x.model_dump().items() if v is not None}
    if 'name' in updates:
        updates['name'] = updates['name'].strip()
        if len(updates['name']) < 2:
            raise HTTPException(400, 'Case name must have at least 2 characters')
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


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


@r.get('/{case_id}/overview')
def overview(case_id: str, u=Depends(current_user)):
    """Everything the case workspace shows at a glance: evidence with analysis
    state, per-function counts and the latest jobs."""
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    evidence = list(db['evidence'].find({'case_id': case_id}, {
        'evidence_id': 1, 'filename': 1, 'format': 1, 'size': 1, 'sha256': 1, 'verification_status': 1,
        'analysis_status': 1, 'analysis_summary': 1, 'last_analysis_job': 1, 'analyzed_at': 1,
        'created_at': 1, 'demo': 1}).sort('created_at', 1))
    eids = [e['evidence_id'] for e in evidence]
    art = db['forensic_artifacts']
    counts = {
        'evidence': len(evidence),
        'evidence_analyzed': sum(1 for e in evidence if e.get('analysis_status') == 'COMPLETED'),
        'files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'is_virtual': False}),
        'deleted_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'deleted': True, 'is_virtual': False}),
        'recovered_files': art.count_documents({'case_id': case_id, 'type': 'RECOVERED_FILE'}),
        'carved_files': art.count_documents({'case_id': case_id, 'type': 'CARVED_FILE'}),
        'timeline_events': db['timeline_events'].count_documents({'case_id': case_id}),
        'browser_history': art.count_documents({'case_id': case_id, 'type': 'BROWSER_HISTORY'}),
        'browser_downloads': art.count_documents({'case_id': case_id, 'type': 'BROWSER_DOWNLOAD'}),
        'usb_devices': db['usb_artifacts'].count_documents({'case_id': case_id}),
        'malware_indicators': art.count_documents({'case_id': case_id, 'type': 'MALWARE_INDICATOR'}),
        'patterns': db['patterns'].count_documents({'case_id': case_id}),
        'anomalies_flagged': db['anomalies'].count_documents({'case_id': case_id, 'is_anomaly': True}),
        'findings': db['findings'].count_documents({'case_id': case_id}),
        'reports': db['reports'].count_documents({'case_id': case_id}),
        'custody_events': db['chain_of_custody'].count_documents({'case_id': case_id}),
    }
    jobs = list(db['jobs'].find({'payload.evidence_id': {'$in': eids}}, {
        'job_id': 1, 'type': 1, 'status': 1, 'progress': 1, 'stage': 1, 'error': 1, 'payload': 1,
        'created_at': 1, 'finished_at': 1}).sort('created_at', -1).limit(8))
    return {'case': c, 'evidence': _plain(evidence), 'counts': counts, 'jobs': _plain(jobs)}
