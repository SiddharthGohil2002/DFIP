from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from pydantic import BaseModel, Field, field_validator
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import shutil
from typing import Optional
from ..security import current_user, require_write
from ..repositories.evidence import list_evidence, get_evidence, insert
from ..repositories.cases import get_case
from ..forensic.hashing import sha256_file
from ..forensic.adapters import support_status
from ..services.audit import log
from ..services.sequences import next_sequence
from ..services.notifications import create as notify
from ..database import get_db
from ..core.config import settings
from ..websocket.manager import manager

r = APIRouter(prefix='/evidence', tags=['evidence'])

def sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def _duplicate_message(existing: dict) -> str:
    return (f"This disk image is already registered in {existing['case_id']} as {existing['evidence_id']} "
            f"({existing.get('filename')}): its SHA-256 is identical. The duplicate upload was discarded.")

@r.get('')
def get_all(u=Depends(current_user)):
    return {'data': list_evidence(u)}

@r.get('/{eid}')
def get_one(eid, u=Depends(current_user)):
    x = get_evidence(eid)
    if not x:
        raise HTTPException(404, 'Evidence not found')
    if not get_case(x['case_id'], u):
        raise HTTPException(403, 'Evidence access denied')
    x['_id'] = str(x['_id'])
    for k, v in list(x.items()):
        if hasattr(v, 'isoformat'):
            x[k] = v.isoformat()
    x['time_zone'] = _time_zone_info(x['evidence_id'])
    return x


def _time_zone_info(eid: str):
    """The time zone the last analysis used for local times, where it came from, and what the registry says."""
    f = (get_db()['analysis_facts'].find_one({'evidence_id': eid}, {'tz_probe': 1}) or {}).get('tz_probe')
    if not f:
        return None
    return {k: f.get(k) for k in ('zone', 'source', 'detected', 'override', 'hive')}


class TimeZoneIn(BaseModel):
    """The computer's time zone, set by the investigator (an IANA name such as America/New_York, or UTC);
    null returns to the time zone in the SYSTEM hive."""
    zone: Optional[str] = Field(default=None, max_length=64)
    reason: str = Field(min_length=5, max_length=500)

    @field_validator('reason')
    @classmethod
    def _reason(cls, v):
        v = v.strip()
        if len(v) < 5:
            raise ValueError('Give a reason of at least 5 characters')
        return v


@r.put('/{eid}/time-zone')
def set_time_zone(eid: str, body: TimeZoneIn, u=Depends(require_write('ANALYSIS_RUN'))):
    """Sets (or clears) the time zone local times are read in, then re-runs the analysis modules that depend on it."""
    from ..forensic.timezone import valid_zone
    from ..services.jobs import active_analysis, queue
    x = get_evidence(eid)
    if not x or not get_case(x['case_id'], u):
        raise HTTPException(404, 'Evidence not found or access denied')
    if x.get('demo'):
        raise HTTPException(400, 'Demo evidence cannot be analysed')
    if body.zone is not None and not valid_zone(body.zone):
        raise HTTPException(400, f'Unknown time zone {body.zone!r}: use an IANA name such as America/New_York, or UTC')
    busy = active_analysis(eid)
    if busy:
        raise HTTPException(409, f'An analysis of this evidence is already queued or running ({busy["job_id"]})')
    db = get_db()
    now = datetime.now(timezone.utc)
    if body.zone is not None:
        override = {'zone': body.zone, 'reason': body.reason, 'set_by': str(u['_id']), 'set_by_name': u.get('name'),
                    'set_at': now}
        db['evidence'].update_one({'evidence_id': eid}, {'$set': {'time_zone_override': override}})
    else:
        override = None
        db['evidence'].update_one({'evidence_id': eid}, {'$unset': {'time_zone_override': ''}})
    log(u, 'TIME_ZONE_SET' if body.zone is not None else 'TIME_ZONE_CLEARED', 'evidence', x['_id'],
        {'evidence_id': eid, 'zone': body.zone, 'reason': body.reason})
    job_id = queue.enqueue('FORENSIC_ANALYSIS', {'evidence_id': eid, 'profile': None, 'modules': ['tz_probe']}, u['_id'])
    manager.emit_sync('JOB_CREATED', {'job_id': job_id, 'type': 'FORENSIC_ANALYSIS', 'evidence_id': eid, 'status': 'QUEUED'})
    return {'job_id': job_id, 'time_zone_override': override and dict(override, set_at=now.isoformat())}


@r.post('/upload')
async def upload(
    case_id: str = Form(...),
    file: UploadFile = File(...),
    sha512: Optional[str] = Form(None),
    u=Depends(require_write('EVIDENCE_UPLOAD'))
):
    ext, ok, _ = support_status(file.filename or '')
    if not ok:
        raise HTTPException(400, f'Unsupported forensic image format: {ext}. Supported: E01, RAW/DD, AFF/AFF4.')
    case = get_case(case_id, u)
    if not case:
        raise HTTPException(404, 'Case not found or access denied')
    
    root = Path(settings.storage_path) / 'evidence' / 'original'
    root.mkdir(parents=True, exist_ok=True)
    safe = Path(file.filename or 'evidence.bin').name
    target = root / f'{datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")}_{safe}'
    written = 0
    
    with target.open('wb') as out:
        while chunk := await file.read(1024 * 1024):
            written += len(chunk)
            if written > settings.max_upload_bytes:
                target.unlink(missing_ok=True)
                raise HTTPException(413, f'File exceeds configured limit of {settings.max_upload_bytes} bytes')
            out.write(chunk)
    
    digest_sha256 = sha256_file(target)
    digest_sha512 = sha512_file(target)
    # A client-computed SHA-512 (e.g. from the acquisition workstation) is only used to
    # confirm the transfer; the recorded hashes are always computed here from the stored file.
    if sha512 and sha512.strip().lower() != digest_sha512:
        target.unlink(missing_ok=True)
        raise HTTPException(400, 'The SHA-512 supplied with the upload does not match the received file. The upload was discarded; please upload it again.')
    # The same image (same content, whatever the file name) is registered only once per case.
    existing = get_db()['evidence'].find_one({'case_id': case_id, 'sha256': digest_sha256}, {'evidence_id': 1, 'case_id': 1, 'filename': 1})
    if existing:
        target.unlink(missing_ok=True)
        raise HTTPException(409, _duplicate_message(existing))

    # Strictly preserve original: mark immutable & read-only on filesystem
    try:
        target.chmod(0o444)
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    n = next_sequence('evidence', floor=get_db()['evidence'].count_documents({}))
    eid = f'EVID-{n:03d}'
    
    doc = {
        'evidence_id': eid,
        'case_id': case_id,
        'filename': safe,
        'format': ext,
        'size': target.stat().st_size,
        'sha256': digest_sha256,
        'sha512': digest_sha512,
        'storage_path': str(target.resolve()),
        'verification_status': 'VERIFIED',
        'verified_at': now,
        'created_at': now,
        'updated_at': now,
        'created_by': str(u['_id']),
        'read_only': True,
        'immutable': True,
        'demo': False,
        'acquisition_status': 'PRESERVED',
        'integrity_algorithm': 'SHA-256 + SHA-512'
    }
    
    out = insert(doc)
    # Two uploads of the same image that finished at the same moment both pass the check above;
    # the earlier record stands and this one is withdrawn before anything refers to it.
    first = get_db()['evidence'].find_one({'case_id': case_id, 'sha256': digest_sha256}, sort=[('_id', 1)])
    if first and first['evidence_id'] != eid:
        get_db()['evidence'].delete_one({'evidence_id': eid})
        target.unlink(missing_ok=True)
        raise HTTPException(409, _duplicate_message(first))
    log(u, 'EVIDENCE_UPLOADED', 'evidence', out['_id'], {'sha256': digest_sha256, 'case_id': case_id})
    
    custody_entry = {
        'evidence_id': eid,
        'case_id': case_id,
        'timestamp': now,
        'user_id': str(u['_id']),
        'user_name': u.get('name', 'Administrator'),
        'action': 'EVIDENCE_REGISTERED',
        'sha256': digest_sha256,
        'sha512': digest_sha512,
        'result': 'PRESERVED_READONLY'
    }
    get_db()['chain_of_custody'].insert_one(custody_entry)
    
    # Broadcast realtime events to Web and Desktop
    manager.emit_sync('EVIDENCE_REGISTERED', {
        'evidence_id': eid,
        'case_id': case_id,
        'filename': safe,
        'size': target.stat().st_size,
        'sha256': digest_sha256,
        'sha512': digest_sha512,
        'format': ext,
        'verification_status': 'VERIFIED'
    })
    manager.emit_sync('CHAIN_OF_CUSTODY_UPDATED', {
        'evidence_id': eid,
        'case_id': case_id,
        'action': 'EVIDENCE_REGISTERED'
    })
    
    if case.get('investigator_id'):
        await notify(case['investigator_id'], 'Evidence uploaded', f'{eid} was added to {case_id}.')
    return out

@r.post('/{eid}/verify')
def verify(eid, u=Depends(require_write('EVIDENCE_VERIFY'))):
    x = get_evidence(eid)
    if not x or not get_case(x['case_id'], u):
        raise HTTPException(404, 'Evidence not found or access denied')
    if x.get('demo'):
        return {
            'evidence_id': eid,
            'sha256': x['sha256'],
            'current_sha256': x['sha256'],
            'verification_status': 'VERIFIED',
            'demo': True,
            'warning': 'Synthetic demo evidence is not a real forensic image.'
        }
    p = Path(x['storage_path'])
    if not p.exists():
        raise HTTPException(409, 'Original evidence object is unavailable')
    
    digest = sha256_file(p)
    status = 'VERIFIED' if digest == x['sha256'] else 'INTEGRITY_FAILED'
    now = datetime.now(timezone.utc)
    
    get_db()['evidence'].update_one(
        {'_id': x['_id']},
        {'$set': {'verification_status': status, 'verified_at': now, 'updated_at': now}}
    )
    log(u, 'EVIDENCE_VERIFIED', 'evidence', x['_id'], {'status': status, 'sha256': digest})
    
    get_db()['chain_of_custody'].insert_one({
        'evidence_id': x['evidence_id'],
        'case_id': x['case_id'],
        'timestamp': now,
        'user_id': str(u['_id']),
        'user_name': u.get('name'),
        'action': 'EVIDENCE_VERIFIED',
        'sha256': digest,
        'status': status
    })
    
    # Broadcast verification result
    manager.emit_sync('EVIDENCE_VERIFICATION_COMPLETED', {
        'evidence_id': x['evidence_id'],
        'case_id': x['case_id'],
        'status': status,
        'sha256': digest
    })
    manager.emit_sync('CHAIN_OF_CUSTODY_UPDATED', {
        'evidence_id': x['evidence_id'],
        'case_id': x['case_id'],
        'action': 'EVIDENCE_VERIFIED'
    })
    
    return {
        '_id': str(x['_id']),
        'evidence_id': x['evidence_id'],
        'sha256': x['sha256'],
        'current_sha256': digest,
        'verification_status': status,
        'verified_at': now.isoformat()
    }


class DeleteEvidence(BaseModel):
    reason: str = Field(min_length=5, max_length=500)

    @field_validator('reason', mode='before')
    @classmethod
    def strip_reason(cls, v):
        return v.strip() if isinstance(v, str) else v


# Jobs that may still read the image: a deletion waits until they finish or are cancelled.
ACTIVE_JOB_STATES = ['QUEUED', 'RUNNING', 'ASSIGNED']


def _remove(path: Path, storage: Path, removed: list, problems: list):
    """Deletes a file or directory, but only inside the DFIP storage area."""
    try:
        p = path.resolve()
        if storage not in p.parents or not p.exists():
            return
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        removed.append(str(p))
    except OSError as e:
        problems.append(f'{path}: {e.strerror or e}')


@r.delete('/{eid}')
def delete(eid, body: DeleteEvidence, u=Depends(require_write('EVIDENCE_DELETE'))):
    """Deletes an evidence item: the stored image, its working copy, recovered and carved files, and every
    analysis result taken from it. The chain of custody and the audit log keep the item's history and gain a
    deletion record with the reason; reports already generated are not changed."""
    x = get_evidence(eid)
    case = get_case(x['case_id'], u) if x else None
    if not x or not case:
        raise HTTPException(404, 'Evidence not found or access denied')
    hold = case.get('legal_hold') or {}
    if hold.get('active'):
        since = hold['set_at'].strftime('%Y-%m-%d %H:%M UTC') if hasattr(hold.get('set_at'), 'strftime') else hold.get('set_at')
        raise HTTPException(423, f"{case['case_id']} is under legal hold since {since} ({hold.get('set_by_name')}: {hold.get('reason')}). "
                                 'Evidence cannot be deleted until the hold is released.')
    db = get_db()
    eid, case_id = x['evidence_id'], x['case_id']
    active = db['jobs'].find_one({'payload.evidence_id': eid, 'status': {'$in': ACTIVE_JOB_STATES}}, {'job_id': 1, 'status': 1})
    if active:
        raise HTTPException(409, f"{active['job_id']} is {active['status'].lower()} for {eid}. Wait for it to finish or cancel it, then delete the evidence.")

    now = datetime.now(timezone.utc)
    q = {'evidence_id': eid}
    counts = {col: db[col].delete_many(q).deleted_count
              for col in ('fs_entries', 'timeline_events', 'forensic_artifacts', 'usb_artifacts', 'entities', 'event_records',
                          'usn_records')}
    counts['jobs'] = db['jobs'].delete_many({'payload.evidence_id': eid}).deleted_count
    counts['tags'] = db['tags'].delete_many({'evidence_id': eid}).deleted_count
    for col in ('analysis_facts', 'pipeline_warnings'):  # module bookkeeping, not counted as results
        db[col].delete_many(q)
    unlinked = db['findings'].update_many({'case_id': case_id, 'evidence_ids': eid},
                                          {'$pull': {'evidence_ids': eid}, '$set': {'updated_at': now}}).modified_count

    storage = Path(settings.storage_path).resolve()
    analysis = storage / 'analysis'
    removed, problems = [], []
    if x.get('storage_path'):
        _remove(Path(x['storage_path']), storage, removed, problems)
    for p in (analysis / 'working').glob(f'{eid}.*'):
        _remove(p, storage, removed, problems)
    for area in ('recovered', 'carved', 'pipeline', 'members', 'thumbs'):
        _remove(analysis / area / eid, storage, removed, problems)
    for p in (analysis / 'text').glob(f'{eid}.*'):  # the content index (and an unfinished rebuild)
        _remove(p, storage, removed, problems)
    db['evidence'].delete_one({'_id': x['_id']})

    # Patterns and anomalies are computed over the whole case timeline; recompute them without this image.
    # A failure here must not stop the deletion from being recorded below.
    if counts['timeline_events']:
        from ..analysis.services import compute_anomalies, compute_patterns
        try:
            compute_patterns(db, case_id)
            compute_anomalies(db, case_id)
        except Exception as e:
            problems.append(f'case patterns and anomalies were not recomputed: {e}')
    db['cases'].update_one({'case_id': case_id}, {'$set': {'updated_at': now}})

    db['chain_of_custody'].insert_one({
        'evidence_id': eid, 'case_id': case_id, 'timestamp': now, 'user_id': str(u['_id']), 'user_name': u.get('name'),
        'action': 'EVIDENCE_DELETED', 'sha256': x.get('sha256'), 'sha512': x.get('sha512'), 'filename': x.get('filename'),
        'reason': body.reason, 'result': 'DELETED', **({'warnings': problems} if problems else {}),
    })
    log(u, 'EVIDENCE_DELETED', 'evidence', x['_id'], {
        'evidence_id': eid, 'case_id': case_id, 'sha256': x.get('sha256'), 'filename': x.get('filename'),
        'reason': body.reason, 'removed': counts, 'files_removed': len(removed), 'findings_unlinked': unlinked})

    manager.emit_sync('EVIDENCE_DELETED', {'evidence_id': eid, 'case_id': case_id})
    manager.emit_sync('CHAIN_OF_CUSTODY_UPDATED', {'evidence_id': eid, 'case_id': case_id, 'action': 'EVIDENCE_DELETED'})
    case = get_case(case_id)
    if case and case.get('investigator_id') and case['investigator_id'] != str(u['_id']):
        from ..services.notifications import create_sync
        create_sync(case['investigator_id'], 'Evidence deleted', f"{eid} ({x.get('filename')}) was deleted from {case_id} by {u.get('name')}: {body.reason}")
    return {'evidence_id': eid, 'case_id': case_id, 'deleted': True, 'removed': counts,
            'files_removed': len(removed), 'findings_unlinked': unlinked, 'warnings': problems}
