from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from ..security import current_user, require_write
from ..database import get_db
from ..websocket.manager import manager
from datetime import datetime, timezone

r = APIRouter(prefix='/jobs', tags=['jobs'])

def serial(x):
    if not x:
        return None
    d = dict(x)
    d['_id'] = str(d['_id'])
    for k, v in list(d.items()):
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d

@r.get('')
def jobs(status: str | None = None, u=Depends(current_user)):
    q = {}
    if status:
        q['status'] = status
    if u['role'] != 'ADMIN':
        q['created_by'] = str(u['_id'])
    return {'data': [serial(x) for x in get_db()['jobs'].find(q).sort('created_at', -1).limit(200)]}

@r.post('/verify/{evidence_id}')
def enqueue_verify(evidence_id: str, u=Depends(require_write('EVIDENCE_VERIFY'))):
    from ..repositories.evidence import get_evidence
    from ..repositories.cases import get_case
    e = get_evidence(evidence_id)
    if not e or not get_case(e['case_id'], u):
        raise HTTPException(404, 'Evidence not found or access denied')
    from ..services.jobs import queue
    job_id = queue.enqueue('HASH_VERIFY', {'evidence_id': evidence_id}, u['_id'])
    manager.emit_sync('JOB_CREATED', {
        'job_id': job_id,
        'type': 'HASH_VERIFY',
        'evidence_id': evidence_id,
        'status': 'QUEUED'
    })
    return {'job_id': job_id}

class AnalysisRequest(BaseModel):
    """Which analysis to run: a profile (quick, standard, full) or an explicit list of modules (default: standard)."""
    profile: str | None = Field(default=None, max_length=20)
    modules: list[str] | None = Field(default=None, max_length=50)


@r.get('/analysis/modules')
def analysis_modules(u=Depends(current_user)):
    """The analysis modules and processing profiles a job can run."""
    from ..forensic.modules import describe
    return describe()


@r.post('/analysis/{evidence_id}')
def enqueue_analysis(evidence_id: str, req: AnalysisRequest | None = None, u=Depends(require_write('ANALYSIS_RUN'))):
    from ..repositories.evidence import get_evidence
    from ..repositories.cases import get_case
    from ..forensic.modules import resolve_request
    e = get_evidence(evidence_id)
    if not e or not get_case(e['case_id'], u):
        raise HTTPException(404, 'Evidence not found or access denied')
    from ..services.jobs import active_analysis
    busy = active_analysis(evidence_id)
    if busy:
        raise HTTPException(409, f'An analysis of this evidence is already queued or running ({busy["job_id"]})')
    req = req or AnalysisRequest()
    try:
        requested = resolve_request(req.profile, req.modules)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    payload = {'evidence_id': evidence_id, 'profile': None if req.modules else (req.profile or 'standard'),
               'modules': requested if req.modules else None}
    from ..services.jobs import queue
    job_id = queue.enqueue('FORENSIC_ANALYSIS', payload, u['_id'])
    manager.emit_sync('JOB_CREATED', {
        'job_id': job_id,
        'type': 'FORENSIC_ANALYSIS',
        'evidence_id': evidence_id,
        'status': 'QUEUED'
    })
    return {'job_id': job_id}

@r.get('/{job_id}')
def job(job_id, u=Depends(current_user)):
    x = get_db()['jobs'].find_one({'job_id': job_id})
    if not x:
        raise HTTPException(404, 'Job not found')
    if u['role'] != 'ADMIN' and x.get('created_by') != str(u['_id']):
        # Members of the job's case may follow it too (e.g. an analysis started by a colleague).
        from ..repositories.evidence import get_evidence
        from ..repositories.cases import get_case
        e = get_evidence((x.get('payload') or {}).get('evidence_id', ''))
        if not e or not get_case(e['case_id'], u):
            raise HTTPException(403, 'Job access denied')
    return serial(x)

@r.post('/{job_id}/cancel')
def cancel(job_id, u=Depends(require_write('JOB_CANCEL'))):
    from ..services.jobs import queue
    x = queue.cancel(job_id)
    if not x:
        raise HTTPException(404, 'Job not found')
    manager.emit_sync('JOB_CANCELLED', {
        'job_id': job_id,
        'status': 'CANCELLED'
    })
    return serial(x)

@r.post('/desktop/{evidence_id}')
def enqueue_desktop_job(
    evidence_id: str,
    job_type: str = 'DESKTOP_ACQUIRE_EVIDENCE',
    u=Depends(require_write('ANALYSIS_RUN'))
):
    from ..repositories.evidence import get_evidence
    from ..repositories.cases import get_case
    e = get_evidence(evidence_id)
    if not e or not get_case(e['case_id'], u):
        raise HTTPException(404, 'Evidence not found or access denied')
    ALLOWED = {'DESKTOP_HASH_FILE', 'DESKTOP_RUN_TOOL', 'DESKTOP_ACQUIRE_EVIDENCE'}
    if job_type not in ALLOWED:
        raise HTTPException(400, 'Invalid desktop job type')
    db = get_db()
    now = datetime.now(timezone.utc)
    seq = db['job_sequences'].find_one_and_update(
        {'_id': 'jobs'}, {'$inc': {'value': 1}}, upsert=True, return_document=True
    )
    n = int(seq.get('value', 1))
    job_id = f'JOB-{n:06d}'
    doc = {
        'job_id': job_id,
        'type': job_type,
        'payload': {'evidence_id': evidence_id},
        'status': 'PENDING_DESKTOP',
        'progress': 0,
        'stage': 'pending_desktop',
        'created_by': str(u['_id']),
        'created_at': now,
        'updated_at': now
    }
    db['jobs'].insert_one(doc)
    manager.emit_sync('JOB_CREATED', {
        'job_id': job_id,
        'type': job_type,
        'evidence_id': evidence_id,
        'status': 'PENDING_DESKTOP'
    })
    return {'job_id': job_id, 'status': 'PENDING_DESKTOP'}
