from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime, timezone
import hashlib
from ..security import current_user, require_write, require_permission
from ..database import get_db
from ..core.config import settings
from ..repositories.cases import get_case
from ..services.audit import log
from ..services.sequences import next_sequence
from ..services.report_pdf import build_case_report
from ..websocket.manager import manager

r = APIRouter(prefix='/reports', tags=['reports'])

def serial(x):
    d = dict(x)
    d['_id'] = str(d['_id'])
    for k, v in list(d.items()):
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d

@r.get('')
def reports(case_id: str | None = None, u=Depends(current_user)):
    docs = []
    for x in get_db()['reports'].find({'case_id': case_id} if case_id else {}).sort('created_at', -1).limit(100 if not case_id else 1000):
        if get_case(x['case_id'], u):
            docs.append(serial(x))
    return {'data': docs}

@r.post('')
def create_report(case_id: str, u=Depends(require_write('REPORT_CREATE'))):
    case = get_case(case_id, u)
    if not case:
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    rid = f"RPT-{next_sequence('reports', floor=db['reports'].count_documents({})):03d}"
    root = Path(settings.storage_path) / 'reports'
    root.mkdir(parents=True, exist_ok=True)
    path = root / f'{rid}.pdf'
    now = datetime.now(timezone.utc)
    version = db['reports'].count_documents({'case_id': case_id}) + 1
    build_case_report(db, case, rid, version, path, u, now)
    pdf_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    doc = {
        'report_id': rid,
        'case_id': case_id,
        'path': str(path.resolve()),
        'created_at': now,
        'created_by': str(u['_id']),
        'version': version,
        'sha256': pdf_sha256
    }
    db['reports'].insert_one(doc)
    log(u, 'REPORT_GENERATED', 'report', rid, {'case_id': case_id, 'sha256': pdf_sha256})
    
    manager.emit_sync('REPORT_GENERATED', {
        'report_id': rid,
        'case_id': case_id,
        'sha256': pdf_sha256,
        'created_at': now.isoformat()
    })
    return serial(doc)

@r.get('/{rid}/download')
def download_report(rid, u=Depends(require_permission('REPORT_READ'))):
    x = get_db()['reports'].find_one({'report_id': rid})
    if not x or not get_case(x['case_id'], u):
        raise HTTPException(404, 'Report not found')
    p = Path(x['path'])
    if not p.exists():
        raise HTTPException(410, 'Report file unavailable')
    return FileResponse(
        str(p),
        media_type='application/pdf',
        filename=f'{rid}.pdf',
        headers={'X-DFIP-Report-SHA256': x.get('sha256', '')}
    )
