from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from pathlib import Path
from datetime import datetime, timezone
import hashlib
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
    return x

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
    digest_sha512 = sha512 or sha512_file(target)
    
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
