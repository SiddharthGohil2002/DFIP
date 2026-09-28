from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import Optional, Any
from ..security import current_user, require_permission
from ..database import get_db
from ..core.config import settings
from ..repositories.devices import register_device, heartbeat as hb, get_device_for_user, list_devices_for_user, get_online_devices
from ..services.audit import log
from ..websocket.manager import manager
import asyncio

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
async def sync_push(body: SyncPush, u=Depends(current_user)):
    db = get_db()
    results = []
    for rec in body.records:
        try:
            outcome = _apply_sync_record(db, rec, u)
            results.append({'record_id': rec.record_id, 'status': outcome})
        except Exception as e:
            results.append({'record_id': rec.record_id, 'status': 'SYNC_FAILED', 'error': str(e)})
    log(u, 'OFFLINE_CHANGES_SYNCED', 'device', body.device_id, {'count': len(body.records), 'device': body.device_id})
    await manager.send(str(u['_id']), {'type': 'sync.push_completed', 'count': len(results)})
    return {'results': results}

def _apply_sync_record(db, rec: SyncPushRecord, u) -> str:
    if rec.record_type == 'finding':
        existing = db['findings'].find_one({'_id': {'$exists': True}, 'local_id': rec.record_id})
        if existing:
            backend_modified = existing.get('updated_at')
            local_modified = datetime.fromisoformat(rec.local_modified_at)
            if backend_modified and backend_modified > local_modified:
                return 'SYNC_CONFLICT'
            db['findings'].update_one({'local_id': rec.record_id}, {'$set': {**rec.data, 'updated_at': datetime.now(timezone.utc), 'sync_status': 'SYNCED'}})
        else:
            db['findings'].insert_one({**rec.data, 'local_id': rec.record_id, 'created_by': str(u['_id']), 'created_at': datetime.now(timezone.utc), 'updated_at': datetime.now(timezone.utc), 'sync_status': 'SYNCED', 'source': 'DESKTOP_OFFLINE'})
        return 'SYNCED'
    elif rec.record_type == 'custody_event':
        # Chain of custody events are append-only — no conflict possible
        existing = db['chain_of_custody'].find_one({'local_id': rec.record_id})
        if not existing:
            db['chain_of_custody'].insert_one({**rec.data, 'local_id': rec.record_id, 'synced_at': datetime.now(timezone.utc), 'source': 'DESKTOP_OFFLINE'})
        return 'SYNCED'
    elif rec.record_type == 'audit_event':
        existing = db['audit_logs'].find_one({'local_id': rec.record_id})
        if not existing:
            db['audit_logs'].insert_one({**rec.data, 'local_id': rec.record_id, 'synced_at': datetime.now(timezone.utc)})
        return 'SYNCED'
    elif rec.record_type == 'case_update':
        case_id = rec.case_id
        if not case_id: return 'SYNC_FAILED'
        existing = db['cases'].find_one({'case_id': case_id})
        if existing:
            backend_modified = existing.get('updated_at')
            local_modified = datetime.fromisoformat(rec.local_modified_at)
            if backend_modified and backend_modified > local_modified:
                return 'SYNC_CONFLICT'
            db['cases'].update_one({'case_id': case_id}, {'$set': {**rec.data, 'updated_at': datetime.now(timezone.utc), 'sync_status': 'SYNCED'}})
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

@r.get('/download/info')
def desktop_download_info():
    """Returns latest desktop application release metadata, direct URLs, and verification checksums."""
    return {
        'version': '2.0.0',
        'release_name': 'DFIP Investigator 2026 Edition',
        'release_date': '2026-09-14',
        'status': 'OFFICIAL_RELEASE',
        'downloads': {
            'installer': {
                'title': 'DFIP Investigator Windows Installer (.exe)',
                'filename': 'DFIP-Investigator-Windows-x64.exe',
                'url': '/downloads/DFIP-Investigator-Windows-x64.exe',
                'api_url': '/api/desktop/download/exe',
                'sha256': '42DCF7204532CD213FA12B432A20FA2A860F822BA1C075C5649E61200667ADC9',
                'arch': 'x86_64',
                'format': 'EXE'
            },
            'portable': {
                'title': 'DFIP Investigator Portable Archive (.zip)',
                'filename': 'DFIP-Investigator-v1.0.0-Windows-x64.zip',
                'url': '/downloads/DFIP-Investigator-v1.0.0-Windows-x64.zip',
                'api_url': '/api/desktop/download/zip',
                'sha256': '1C45B6C880BA34D941F5EF4F23781DAD50D46C7B233138625FD6F6534C8D7B6D',
                'arch': 'x86_64',
                'format': 'ZIP'
            }
        },
        'verification': {
            'algorithm': 'SHA-256',
            'command_powershell': 'Get-FileHash .\\DFIP-Investigator-Windows-x64.exe -Algorithm SHA256'
        }
    }

@r.get('/download/exe')
def download_desktop_exe():
    """Direct stream download for DFIP Windows Client installer executable."""
    root = Path(__file__).resolve().parents[3]
    candidates = [
        Path(settings.storage_path) / 'downloads' / 'DFIP-Investigator-Windows-x64.exe',
        root / 'releases' / 'DFIP-Investigator-Windows-x64.exe',
        root / 'frontend' / 'public' / 'downloads' / 'DFIP-Investigator-Windows-x64.exe',
        root / 'desktop' / 'ui' / 'public' / 'downloads' / 'DFIP-Investigator-Windows-x64.exe'
    ]
    for target in candidates:
        if target.exists():
            return FileResponse(
                str(target),
                media_type='application/vnd.microsoft.portable-executable',
                filename='DFIP-Investigator-Windows-x64.exe',
                headers={'X-DFIP-Release-Version': '2.0.0', 'X-DFIP-SHA256': '42DCF7204532CD213FA12B432A20FA2A860F822BA1C075C5649E61200667ADC9'}
            )
    raise HTTPException(404, 'Desktop application installer binary not available in storage')

@r.get('/download/zip')
def download_desktop_zip():
    """Direct stream download for DFIP Windows Portable zip package."""
    root = Path(__file__).resolve().parents[3]
    candidates = [
        Path(settings.storage_path) / 'downloads' / 'DFIP-Investigator-v1.0.0-Windows-x64.zip',
        root / 'releases' / 'DFIP-Investigator-v1.0.0-Windows-x64.zip',
        root / 'frontend' / 'public' / 'downloads' / 'DFIP-Investigator-v1.0.0-Windows-x64.zip',
        root / 'desktop' / 'ui' / 'public' / 'downloads' / 'DFIP-Investigator-v1.0.0-Windows-x64.zip'
    ]
    for target in candidates:
        if target.exists():
            return FileResponse(
                str(target),
                media_type='application/zip',
                filename='DFIP-Investigator-v1.0.0-Windows-x64.zip',
                headers={'X-DFIP-Release-Version': '2.0.0', 'X-DFIP-SHA256': '1C45B6C880BA34D941F5EF4F23781DAD50D46C7B233138625FD6F6534C8D7B6D'}
            )
    raise HTTPException(404, 'Desktop application portable bundle not available in storage')

