from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import Optional, Any
from ..security import current_user, require_permission, require_desktop_workstation
from ..repositories.cases import get_case
from ..database import get_db
from ..core.config import settings
from ..repositories.devices import register_device, heartbeat as hb, get_device_for_user, list_devices_for_user, get_online_devices
from ..services.audit import log
from ..websocket.manager import manager
import asyncio
import hashlib

r = APIRouter(prefix='/desktop', tags=['desktop'])

ALLOWED_DESKTOP_JOB_TYPES = {'DESKTOP_HASH_FILE', 'DESKTOP_RUN_TOOL', 'DESKTOP_ACQUIRE_EVIDENCE'}
ALLOWED_TOOLS = {'fls', 'istat', 'fsstat', 'mmls', 'icat', 'exiftool', 'tshark', 'yara', 'vol', 'strings', 'file'}

def serial(x):
    if x is None: return None
    d = dict(x)
    d.pop('_id', None)
    for k, v in list(d.items()):
        if hasattr(v, 'isoformat'): d[k] = v.isoformat()
    return d

class DeviceRegister(BaseModel):
    device_id: str = Field(min_length=4, max_length=80)
    device_name: str = Field(min_length=1, max_length=120)
    app_version: str = '1.0.0'
    os: str = 'windows'

class JobComplete(BaseModel):
    result: Any = None
    summary: Optional[str] = None

class JobFail(BaseModel):
    error: str
    traceback: Optional[str] = None

class SyncPushRecord(BaseModel):
    record_type: str  # 'finding', 'custody_event', 'audit_event', 'case_update'
    record_id: str
    case_id: Optional[str] = None
    data: Any
    local_created_at: str
    local_modified_at: str
    device_id: str

class SyncPush(BaseModel):
    records: list[SyncPushRecord]
    device_id: str

@r.post('/register')
def device_register(req: DeviceRegister, u=Depends(current_user)):
    from ..security import create_device_token
    device = register_device(
        device_id=req.device_id,
        device_name=req.device_name,
        user_id=str(u['_id']),
        app_version=req.app_version,
        os=req.os,
    )
    device_token = create_device_token(str(u['_id']), req.device_id)
    log(u, 'DESKTOP_REGISTERED', 'device', req.device_id, {'device_name': req.device_name})
    manager.emit_sync('DESKTOP_CONNECTED', {
        'device_id': req.device_id,
        'device_name': req.device_name,
        'user_id': str(u['_id']),
        'os': req.os,
        'app_version': req.app_version
    })
    return {'status': 'registered', 'device': device, 'device_token': device_token}

@r.post('/heartbeat')
async def device_heartbeat(device_id: str, u=Depends(current_user)):
    dev = get_device_for_user(str(u['_id']))
    if not dev or dev.get('device_id') != device_id:
        raise HTTPException(403, 'Device not registered for this user')
    hb(device_id)
    pending = get_db()['jobs'].count_documents({
        'status': 'PENDING_DESKTOP',
        'created_by': str(u['_id'])
    })
    manager.emit_sync('DESKTOP_HEARTBEAT', {
        'device_id': device_id,
        'user_id': str(u['_id']),
        'pending_jobs': pending,
        'last_seen': datetime.now(timezone.utc).isoformat()
    })
    return {'status': 'ok', 'pending_jobs': pending}

@r.get('/status')
def device_status(u=Depends(current_user)):
    devices = list_devices_for_user(str(u['_id']))
    online = get_online_devices(str(u['_id']), within_minutes=5)
    pending = get_db()['jobs'].count_documents({
        'status': 'PENDING_DESKTOP',
        'created_by': str(u['_id'])
    })
    return {
        'devices': devices,
        'online_count': len(online),
        'is_online': len(online) > 0,
        'pending_desktop_jobs': pending,
    }

@r.get('/devices')
def list_devices(u=Depends(current_user)):
    return {'data': list_devices_for_user(str(u['_id']))}

@r.get('/jobs')
def desktop_jobs(u=Depends(current_user)):
    jobs = list(get_db()['jobs'].find(
        {'status': 'PENDING_DESKTOP', 'created_by': str(u['_id'])}
    ).sort('created_at', 1).limit(50))
    return {'data': [serial(j) for j in jobs]}

@r.post('/jobs/{job_id}/claim')
def claim_job(job_id: str, device_id: str, u=Depends(current_user)):
    db = get_db()
    job = db['jobs'].find_one({'job_id': job_id})
    if not job:
        raise HTTPException(404, 'Job not found')
    if job.get('created_by') != str(u['_id']) and u.get('role') != 'ADMIN':
        raise HTTPException(403, 'Job access denied')
    if job.get('status') != 'PENDING_DESKTOP':
        raise HTTPException(409, f'Job cannot be claimed (status={job["status"]})')
    now = datetime.now(timezone.utc)
    db['jobs'].update_one(
        {'job_id': job_id, 'status': 'PENDING_DESKTOP'},
        {'$set': {'status': 'ASSIGNED', 'claimed_by_device': device_id, 'claimed_at': now, 'updated_at': now}}
    )
    log(u, 'DESKTOP_JOB_CLAIMED', 'job', job_id, {'device_id': device_id})
    return serial(db['jobs'].find_one({'job_id': job_id}))

@r.post('/jobs/{job_id}/start')
def start_job(job_id: str, u=Depends(current_user)):
    db = get_db()
    job = db['jobs'].find_one({'job_id': job_id})
    if not job: raise HTTPException(404, 'Job not found')
    if job.get('created_by') != str(u['_id']) and u.get('role') != 'ADMIN':
        raise HTTPException(403, 'Job access denied')
    now = datetime.now(timezone.utc)
    db['jobs'].update_one(
        {'job_id': job_id},
        {'$set': {'status': 'RUNNING', 'started_at': now, 'updated_at': now, 'stage': 'running'}}
    )
    log(u, 'DESKTOP_JOB_STARTED', 'job', job_id, {})
    manager.emit_sync('JOB_STARTED', {'job_id': job_id, 'stage': 'running'})
    return serial(db['jobs'].find_one({'job_id': job_id}))

@r.post('/jobs/{job_id}/complete')
async def complete_job(job_id: str, body: JobComplete, u=Depends(current_user)):
    db = get_db()
    job = db['jobs'].find_one({'job_id': job_id})
    if not job: raise HTTPException(404, 'Job not found')
    if job.get('created_by') != str(u['_id']) and u.get('role') != 'ADMIN':
        raise HTTPException(403, 'Job access denied')
    now = datetime.now(timezone.utc)
    db['jobs'].update_one(
        {'job_id': job_id},
        {'$set': {
            'status': 'COMPLETED', 'result': body.result,
            'summary': body.summary, 'finished_at': now, 'updated_at': now,
            'stage': 'complete', 'progress': 100,
        }}
    )
    log(u, 'DESKTOP_JOB_COMPLETED', 'job', job_id, {'summary': body.summary})
    manager.emit_sync('JOB_COMPLETED', {
        'job_id': job_id,
        'job_type': job.get('type'),
        'summary': body.summary,
        'result': body.result,
        'progress': 100
    })
    return serial(db['jobs'].find_one({'job_id': job_id}))

@r.post('/jobs/{job_id}/fail')
async def fail_job(job_id: str, body: JobFail, u=Depends(current_user)):
    db = get_db()
    job = db['jobs'].find_one({'job_id': job_id})
    if not job: raise HTTPException(404, 'Job not found')
    if job.get('created_by') != str(u['_id']) and u.get('role') != 'ADMIN':
        raise HTTPException(403, 'Job access denied')
    now = datetime.now(timezone.utc)
    db['jobs'].update_one(
        {'job_id': job_id},
        {'$set': {
            'status': 'FAILED', 'error': body.error, 'traceback': body.traceback,
            'finished_at': now, 'updated_at': now, 'stage': 'failed',
        }}
    )
    log(u, 'DESKTOP_JOB_FAILED', 'job', job_id, {'error': body.error})
    manager.emit_sync('JOB_FAILED', {
        'job_id': job_id,
        'error': body.error
    })
    return serial(db['jobs'].find_one({'job_id': job_id}))

@r.post('/sync/push')
async def sync_push(body: SyncPush, request: Request, u=Depends(current_user)):
    """Applies changes a workstation made offline. Each record goes through the same
    case-access and permission checks as the online API, and only the fields a
    client may set are written."""
    if settings.require_desktop_for_writes:
        require_desktop_workstation(request, u)
    db = get_db()
    results = []
    for rec in body.records:
        try:
            outcome = _apply_sync_record(db, rec, u)
            results.append({'record_id': rec.record_id, 'status': outcome})
        except HTTPException as e:
            results.append({'record_id': rec.record_id, 'status': 'SYNC_REJECTED', 'error': e.detail})
        except Exception as e:
            results.append({'record_id': rec.record_id, 'status': 'SYNC_FAILED', 'error': str(e)})
    log(u, 'OFFLINE_CHANGES_SYNCED', 'device', body.device_id, {'count': len(body.records), 'device': body.device_id,
                                                                'applied': sum(1 for x in results if x['status'] == 'SYNCED')})
    await manager.send(str(u['_id']), {'type': 'sync.push_completed', 'count': len(results)})
    return {'results': results}


SYNC_FINDING_FIELDS = {'title', 'description', 'severity', 'evidence_ids', 'timeline_ids'}
SYNC_CASE_FIELDS = {'name', 'description', 'priority', 'status'}


def _has_permission(u, permission: str) -> bool:
    if u.get('role') == 'ADMIN':
        return True
    role = get_db()['roles'].find_one({'name': u.get('role')}) or {}
    return permission in role.get('permissions', [])


def _sync_case(rec: SyncPushRecord, u, permission: str) -> dict:
    data = rec.data if isinstance(rec.data, dict) else {}
    case_id = rec.case_id or data.get('case_id')
    if not case_id or not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if data.get('case_id') not in (None, case_id):
        raise HTTPException(400, 'Record case does not match')
    if not _has_permission(u, permission):
        raise HTTPException(403, f'Missing permission: {permission}')
    return {'case_id': case_id, 'data': data}


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _apply_sync_record(db, rec: SyncPushRecord, u) -> str:
    now = datetime.now(timezone.utc)
    if rec.record_type == 'finding':
        ctx = _sync_case(rec, u, 'FINDING_CREATE')
        fields = {k: v for k, v in ctx['data'].items() if k in SYNC_FINDING_FIELDS}
        if fields.get('severity', 'MEDIUM') not in {'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
            raise HTTPException(400, 'Invalid severity')
        if len(str(fields.get('title', '')).strip()) < 2:
            raise HTTPException(400, 'Finding title is required')
        existing = db['findings'].find_one({'local_id': rec.record_id, 'created_by': str(u['_id'])})
        if existing:
            if existing.get('case_id') != ctx['case_id']:
                raise HTTPException(400, 'Record case does not match')
            if existing.get('updated_at') and _aware(existing['updated_at']) > _aware(datetime.fromisoformat(rec.local_modified_at)):
                return 'SYNC_CONFLICT'
            db['findings'].update_one({'_id': existing['_id']}, {'$set': {**fields, 'updated_at': now, 'sync_status': 'SYNCED'}})
        else:
            db['findings'].insert_one({'severity': 'MEDIUM', 'evidence_ids': [], 'timeline_ids': [], 'description': '', **fields,
                                       'case_id': ctx['case_id'], 'local_id': rec.record_id, 'created_by': str(u['_id']),
                                       'created_at': now, 'updated_at': now, 'sync_status': 'SYNCED', 'source': 'DESKTOP_OFFLINE'})
            log(u, 'FINDING_CREATED', 'finding', rec.record_id, {'case_id': ctx['case_id'], 'source': 'DESKTOP_OFFLINE'})
        return 'SYNCED'
    if rec.record_type == 'custody_event':
        # Workstation-side events (e.g. a local hash check) are recorded as such and attributed
        # to the user; they can never pose as server events like EVIDENCE_VERIFIED.
        ctx = _sync_case(rec, u, 'EVIDENCE_VERIFY')
        data = ctx['data']
        evidence = db['evidence'].find_one({'evidence_id': data.get('evidence_id'), 'case_id': ctx['case_id']})
        if not evidence:
            raise HTTPException(404, 'Evidence not found in this case')
        if not db['chain_of_custody'].find_one({'local_id': rec.record_id}):
            db['chain_of_custody'].insert_one({
                'evidence_id': evidence['evidence_id'], 'case_id': ctx['case_id'], 'timestamp': now,
                'local_timestamp': rec.local_created_at, 'user_id': str(u['_id']), 'user_name': u.get('name'),
                'action': 'DESKTOP_' + str(data.get('action', 'EVENT')).upper()[:60], 'sha256': data.get('sha256'),
                'status': data.get('status'), 'local_id': rec.record_id, 'device_id': rec.device_id,
                'synced_at': now, 'source': 'DESKTOP_OFFLINE'})
        return 'SYNCED'
    if rec.record_type == 'audit_event':
        if not db['audit_logs'].find_one({'local_id': rec.record_id}):
            # Appended through the hash chain under one fixed action name, so offline events
            # cannot imitate server actions; the reported action is kept in the metadata.
            from ..services.audit import append
            data = rec.data if isinstance(rec.data, dict) else {'value': rec.data}
            append({'timestamp': now.isoformat(), 'user_id': str(u['_id']), 'user_name': u.get('name'),
                    'user_role': u.get('role'), 'action': 'DESKTOP_OFFLINE_EVENT',
                    'resource_type': 'desktop', 'resource_id': rec.device_id,
                    'metadata': {'reported_action': str(data.get('action', ''))[:80], 'data': data},
                    'local_id': rec.record_id, 'source': 'DESKTOP_OFFLINE'})
        return 'SYNCED'
    if rec.record_type == 'case_update':
        ctx = _sync_case(rec, u, 'CASE_UPDATE')
        fields = {k: v for k, v in ctx['data'].items() if k in SYNC_CASE_FIELDS}
        if 'status' in fields and fields['status'] not in {'OPEN', 'IN_PROGRESS', 'ON_HOLD', 'COMPLETED', 'ARCHIVED'}:
            raise HTTPException(400, 'Invalid status')
        if 'priority' in fields and fields['priority'] not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
            raise HTTPException(400, 'Invalid priority')
        if 'name' in fields and not 2 <= len(str(fields['name']).strip()) <= 120:
            raise HTTPException(400, 'Invalid case name')
        existing = db['cases'].find_one({'case_id': ctx['case_id']})
        if existing.get('updated_at') and _aware(existing['updated_at']) > _aware(datetime.fromisoformat(rec.local_modified_at)):
            return 'SYNC_CONFLICT'
        if fields:
            db['cases'].update_one({'case_id': ctx['case_id']}, {'$set': {**fields, 'updated_at': now, 'sync_status': 'SYNCED'}})
            log(u, 'CASE_UPDATED', 'case', existing['_id'], {**fields, 'source': 'DESKTOP_OFFLINE'})
        return 'SYNCED'
    return 'SYNC_FAILED'

@r.get('/sync/pull')
def sync_pull(since: Optional[str] = None, u=Depends(current_user)):
    db = get_db()
    since_dt = datetime.fromisoformat(since) if since else None
    user_id = str(u['_id'])

    def case_filter():
        q = {'$or': [{'investigator_id': user_id}, {'created_by': user_id}]}
        if since_dt: q['updated_at'] = {'$gte': since_dt}
        return q

    def ev_filter(case_ids):
        q = {'case_id': {'$in': case_ids}}
        if since_dt: q['updated_at'] = {'$gte': since_dt}
        return q

    cases = list(db['cases'].find(case_filter()).sort('updated_at', -1).limit(100))
    case_ids = [c['case_id'] for c in cases]

    def ser_list(lst):
        out = []
        for x in lst:
            x = dict(x); x['_id'] = str(x['_id'])
            for k, v in list(x.items()):
                if hasattr(v, 'isoformat'): x[k] = v.isoformat()
            out.append(x)
        return out

    evidence = list(db['evidence'].find({'case_id': {'$in': case_ids}}).limit(500)) if case_ids else []
    jobs = list(db['jobs'].find({'created_by': user_id, 'status': {'$in': ['PENDING_DESKTOP', 'ASSIGNED', 'RUNNING', 'COMPLETED', 'FAILED']}}).sort('updated_at', -1).limit(100))
    findings = list(db['findings'].find({'case_id': {'$in': case_ids}}).limit(500)) if case_ids else []
    notifications = list(db['notifications'].find({'user_id': user_id, 'read': False}).limit(50))

    return {
        'pull_timestamp': datetime.now(timezone.utc).isoformat(),
        'cases': ser_list(cases),
        'evidence': ser_list(evidence),
        'jobs': ser_list(jobs),
        'findings': ser_list(findings),
        'notifications': ser_list(notifications),
    }

@r.post('/jobs/create')
def create_desktop_job(job_type: str, payload: dict, u=Depends(require_permission('ANALYSIS_RUN'))):
    """Create a PENDING_DESKTOP job that waits for a desktop agent to claim."""
    if job_type not in ALLOWED_DESKTOP_JOB_TYPES:
        raise HTTPException(400, f'Unsupported desktop job type: {job_type}. Allowed: {sorted(ALLOWED_DESKTOP_JOB_TYPES)}')
    if job_type == 'DESKTOP_RUN_TOOL':
        tool = payload.get('tool', '')
        if tool not in ALLOWED_TOOLS:
            raise HTTPException(400, f'Tool not on allow-list: {tool}')
    db = get_db()
    now = datetime.now(timezone.utc)
    seq = db['job_sequences'].find_one_and_update(
        {'_id': 'jobs'}, {'$inc': {'value': 1}}, upsert=True,
        return_document=True
    )
    n = int(seq.get('value', 1))
    job_id = f'JOB-{n:06d}'
    db['jobs'].insert_one({
        'job_id': job_id, 'type': job_type, 'payload': payload,
        'status': 'PENDING_DESKTOP',
        'progress': 0, 'stage': 'pending_desktop',
        'created_by': str(u['_id']),
        'created_at': now, 'updated_at': now,
    })
    log(u, 'DESKTOP_JOB_CREATED', 'job', job_id, {'type': job_type, 'payload': payload})
    return {'job_id': job_id, 'status': 'PENDING_DESKTOP'}

# Installer files produced by the Tauri build (desktop/scripts/build-windows.ps1) and
# copied to storage/downloads. Only real build outputs are offered; nothing is
# advertised when no build has been published.
INSTALLER_PATTERNS = ('*_x64-setup.exe', '*_x64_en-US.msi')
_hash_cache: dict = {}


def _installers():
    root = Path(settings.storage_path) / 'downloads'
    files = []
    for pattern in INSTALLER_PATTERNS:
        for p in sorted(root.glob(pattern)):
            if not p.is_file():
                continue
            stat = p.stat()
            key = (p.name, stat.st_size, stat.st_mtime)
            if key not in _hash_cache:
                h = hashlib.sha256()
                with p.open('rb') as f:
                    while chunk := f.read(1024 * 1024):
                        h.update(chunk)
                _hash_cache[key] = h.hexdigest()
            files.append({'filename': p.name, 'size': stat.st_size, 'sha256': _hash_cache[key],
                          'format': p.suffix.lstrip('.').upper(), 'url': f'/api/desktop/download/file/{p.name}',
                          'published_at': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()})
    return files


@r.get('/download/info')
def desktop_download_info():
    """Published desktop installers with their SHA-256, or available=false when none exist."""
    files = _installers()
    return {'available': bool(files), 'files': files,
            'verification': 'Get-FileHash <file> -Algorithm SHA256 (PowerShell) must match sha256'}


@r.get('/download/file/{filename}')
def download_desktop_file(filename: str):
    match = next((f for f in _installers() if f['filename'] == filename), None)
    if not match:
        raise HTTPException(404, 'Installer not published')
    path = Path(settings.storage_path) / 'downloads' / match['filename']
    return FileResponse(str(path), filename=match['filename'], media_type='application/octet-stream',
                        headers={'X-DFIP-SHA256': match['sha256']})
