"""The volumes of an evidence item, and unlocking encrypted ones (BitLocker, LUKS) with the investigator's key.

Unlocking checks the key at once (a wrong key is refused and audited), stores it encrypted (app/services/secrets.py)
and starts a VOLUME_DECRYPT job that receives only the key's reference. The job writes the decrypted volume, which
becomes evidence of its own, and analyses it.
"""
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..core.config import settings
from ..database import get_db
from ..forensic.disk_formats import ensure_space
from ..forensic.volume_crypto import METHOD_LABELS, WrongKey, check_secret, open_volume
from ..forensic.working_image import WorkingCopyUnavailable, analysis_image
from ..repositories.cases import get_case
from ..repositories.evidence import get_evidence
from ..security import current_user, require_write
from ..services.audit import log
from ..services.sequences import next_sequence
from ..websocket.manager import manager

r = APIRouter(prefix='/evidence', tags=['volumes'])
SECTOR = 512


def derived_dir(evidence_id: str) -> Path:
    return Path(settings.storage_path).resolve() / 'analysis' / 'derived' / evidence_id


def _evidence(eid: str, u) -> dict:
    e = get_evidence(eid)
    if not e or not get_case(e['case_id'], u):
        raise HTTPException(404, 'Evidence not found or access denied')
    return e


def volumes_of(e: dict) -> list[dict]:
    """Each file system the analysis found, with its size, encryption, shadow copies, stored key and decrypted copy."""
    db = get_db()
    facts = db['analysis_facts'].find_one({'evidence_id': e['evidence_id']}, {'fs_index': 1, 'shadow_copies': 1}) or {}
    fs = (facts.get('fs_index') or {}).get('filesystems') or []
    parts = {p.get('start'): p for p in (facts.get('fs_index') or {}).get('partitions') or []}
    shadows = (facts.get('shadow_copies') or {}).get('stores') or []
    keys = {k['volume_id']: k for k in db['volume_keys'].find({'evidence_id': e['evidence_id']}, {'secret': 0})}
    derived = {d['derived_from']['volume_id']: d for d in db['evidence'].find(
        {'derived_from.evidence_id': e['evidence_id']}, {'evidence_id': 1, 'derived_from': 1, 'sha256': 1, 'size': 1, 'analysis_status': 1})}
    jobs = {j['payload'].get('volume_id'): j for j in db['jobs'].find(
        {'type': 'VOLUME_DECRYPT', 'payload.evidence_id': e['evidence_id'], 'status': {'$in': ['QUEUED', 'RUNNING', 'ASSIGNED']}},
        {'job_id': 1, 'status': 1, 'progress': 1, 'payload': 1})}
    out = []
    for f in fs:
        part = parts.get(f.get('partition_offset'))
        vid = f.get('volume_id')
        key = keys.get(vid)
        d = derived.get(vid)
        out.append({
            'volume_id': vid, 'partition_offset': f.get('partition_offset'), 'filesystem_type': f.get('filesystem_type'),
            'encryption': f.get('encryption'), 'length': part['length'] * SECTOR if part and part.get('length') else None,
            'files': f.get('files'), 'error': f.get('error'),
            'shadow_copies': [{k: s.get(k) for k in ('store', 'volume_id', 'identifier', 'created', 'counts')}
                              for s in shadows if s.get('parent_volume_id') == vid],
            'key': {k: key.get(k) for k in ('key_id', 'kind', 'method', 'created_by_name', 'created_at', 'last_used_at', 'use_count')} if key else None,
            'decrypted': {'evidence_id': d['evidence_id'], 'sha256': d.get('sha256'), 'size': d.get('size'),
                          'analysis_status': d.get('analysis_status')} if d else None,
            'job': {'job_id': jobs[vid]['job_id'], 'status': jobs[vid]['status'], 'progress': jobs[vid].get('progress')} if vid in jobs else None,
        })
    return out


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


@r.get('/{eid}/volumes')
def volumes(eid: str, u=Depends(current_user)):
    """The volumes found by the last analysis: file system, size, encryption, shadow copies, and whether an
    encrypted one was unlocked (its decrypted copy is evidence of its own)."""
    e = _evidence(eid, u)
    return {'data': _plain(volumes_of(e)), 'derived_from': _plain(e.get('derived_from'))}


class UnlockIn(BaseModel):
    # Plain strings, checked by check_secret: field constraints would echo the value back in a validation error.
    method: str
    secret: str


@r.post('/{eid}/volumes/{vid}/unlock')
def unlock(eid: str, vid: str, body: UnlockIn, u=Depends(require_write('EVIDENCE_UPLOAD'))):
    """Checks the key against the volume now, stores it encrypted, and starts decrypting the volume (VOLUME_DECRYPT).
    A wrong key is refused (400) and audited; the key itself is never logged or returned."""
    e = _evidence(eid, u)
    if e.get('demo'):
        raise HTTPException(400, 'Demo evidence has no volumes')
    vol = next((v for v in volumes_of(e) if v['volume_id'] == vid), None)
    if not vol:
        raise HTTPException(404, f'{eid} has no volume {vid} (run the analysis first)')
    kind = vol.get('encryption')
    if not kind:
        raise HTTPException(400, f'Volume {vid} is not encrypted')
    if vol['decrypted']:
        raise HTTPException(409, f'Volume {vid} was already decrypted as {vol["decrypted"]["evidence_id"]}')
    if vol['job']:
        raise HTTPException(409, f'Volume {vid} is being decrypted ({vol["job"]["job_id"]})')
    try:
        secret = check_secret(kind, body.method, body.secret)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    try:
        image = analysis_image(e)
    except WorkingCopyUnavailable as exc:
        raise HTTPException(409, str(exc))
    if not Path(image).exists():
        raise HTTPException(409, 'Original evidence object is unavailable')
    try:
        opened = open_volume(image, vol['partition_offset'], vol['length'], kind, body.method, secret)
    except WrongKey as exc:
        log(u, 'VOLUME_UNLOCK_FAILED', 'evidence', e['_id'], {'evidence_id': eid, 'volume_id': vid, 'kind': kind, 'method': body.method})
        raise HTTPException(400, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    size = opened.size
    opened.close()
    try:
        ensure_space(derived_dir(eid), size, 'the decrypted volume')
    except ValueError as exc:
        raise HTTPException(507, str(exc))

    from ..services.secrets import encrypt
    db = get_db()
    now = datetime.now(timezone.utc)
    key_id = f'VK-{next_sequence("volume_keys", floor=db["volume_keys"].count_documents({})):04d}'
    db['volume_keys'].delete_many({'evidence_id': eid, 'volume_id': vid})  # one key per volume: the one that worked last
    db['volume_keys'].insert_one({'key_id': key_id, 'evidence_id': eid, 'case_id': e['case_id'], 'volume_id': vid, 'kind': kind,
                                  'method': body.method, 'secret': encrypt(secret), 'created_by': str(u['_id']),
                                  'created_by_name': u.get('name'), 'created_at': now, 'use_count': 0})
    log(u, 'VOLUME_UNLOCKED', 'evidence', e['_id'], {'evidence_id': eid, 'volume_id': vid, 'kind': kind, 'method': body.method,
                                                      'key_id': key_id, 'decrypted_size': size})
    from ..services.jobs import queue
    job_id = queue.enqueue('VOLUME_DECRYPT', {'evidence_id': eid, 'volume_id': vid, 'key_id': key_id}, u['_id'])
    manager.emit_sync('JOB_CREATED', {'job_id': job_id, 'type': 'VOLUME_DECRYPT', 'evidence_id': eid, 'status': 'QUEUED'})
    return {'job_id': job_id, 'key_id': key_id, 'kind': kind, 'method': METHOD_LABELS[body.method], 'size': size}


@r.delete('/{eid}/volumes/{vid}/key')
def forget_key(eid: str, vid: str, u=Depends(require_write('EVIDENCE_UPLOAD'))):
    """Deletes the stored key of a volume (the decrypted copy, if made, stays)."""
    e = _evidence(eid, u)
    key = get_db()['volume_keys'].find_one_and_delete({'evidence_id': eid, 'volume_id': vid})
    if not key:
        raise HTTPException(404, 'No key is stored for this volume')
    log(u, 'VOLUME_KEY_DELETED', 'evidence', e['_id'], {'evidence_id': eid, 'volume_id': vid, 'key_id': key['key_id']})
    return {'deleted': key['key_id']}
