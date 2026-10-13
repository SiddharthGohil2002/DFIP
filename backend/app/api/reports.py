"""Case reports: generated from a template (which sections, in which order, the cover, approved findings only, pictures
of findings) as a signed PDF and the same content as one self-contained HTML file; downloaded with their SHA-256;
verified (the stored report or any PDF uploaded). Report templates are kept for reuse."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field, field_validator

from ..core.config import settings
from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user, require_permission, require_write
from ..services.audit import log
from ..services.report_pdf import SECTIONS, build_case_report
from ..services.sequences import next_sequence
from ..websocket.manager import manager

r = APIRouter(prefix='/reports', tags=['reports'])
SECTION_IDS = [s[0] for s in SECTIONS]


class Cover(BaseModel):
    title: str = Field('', max_length=200)
    organisation: str = Field('', max_length=200)
    reference: str = Field('', max_length=120)
    prepared_for: str = Field('', max_length=200)
    classification: str = Field('', max_length=80)
    scope: str = Field('', max_length=4000)

    @field_validator('*', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class TemplateIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field('', max_length=1000)
    sections: list[str] = Field(min_length=1, max_length=len(SECTION_IDS))
    cover: Cover = Cover()
    approved_findings_only: bool = False
    include_screenshots: bool = True

    @field_validator('sections')
    @classmethod
    def known(cls, v):
        unknown = [s for s in v if s not in SECTION_IDS]
        if unknown:
            raise ValueError(f'unknown sections: {", ".join(unknown)}')
        if len(set(v)) != len(v):
            raise ValueError('a section is listed twice')
        return v


class GenerateIn(BaseModel):
    template_id: str | None = None
    template: TemplateIn | None = None


def serial(x):
    d = {k: v for k, v in dict(x).items() if k != 'html_path'}
    d['_id'] = str(x['_id'])
    for k, v in list(d.items()):
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    d['has_html'] = bool(x.get('html_path'))
    return d


def _tpl_out(t: dict) -> dict:
    d = {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in t.items() if k != '_id'}
    return d


@r.get('/sections')
def sections(u=Depends(current_user)):
    """Every section a report can have, in the default order, with its group."""
    return {'data': [{'id': sid, 'title': title, 'group': group} for sid, title, group in SECTIONS]}


@r.get('/templates')
def templates(u=Depends(require_permission('REPORT_READ'))):
    return {'data': [_tpl_out(t) for t in get_db()['report_templates'].find().sort('name', 1)]}


@r.post('/templates')
def create_template(x: TemplateIn, u=Depends(require_write('REPORT_CREATE'))):
    db = get_db()
    tid = f"TPL-{next_sequence('report-templates', floor=db['report_templates'].count_documents({})):03d}"
    now = datetime.now(timezone.utc)
    doc = {'template_id': tid, **x.model_dump(), 'created_by': str(u['_id']), 'created_by_name': u.get('name'), 'created_at': now, 'updated_at': now}
    db['report_templates'].insert_one(doc)
    log(u, 'REPORT_TEMPLATE_CREATED', 'report_template', tid, {'name': x.name, 'sections': x.sections})
    return _tpl_out(doc)


@r.put('/templates/{tid}')
def update_template(tid: str, x: TemplateIn, u=Depends(require_write('REPORT_CREATE'))):
    db = get_db()
    if not db['report_templates'].find_one({'template_id': tid}):
        raise HTTPException(404, 'Template not found')
    db['report_templates'].update_one({'template_id': tid}, {'$set': {**x.model_dump(), 'updated_at': datetime.now(timezone.utc),
                                                                      'updated_by_name': u.get('name')}})
    log(u, 'REPORT_TEMPLATE_UPDATED', 'report_template', tid, {'name': x.name, 'sections': x.sections})
    return _tpl_out(db['report_templates'].find_one({'template_id': tid}))


@r.delete('/templates/{tid}')
def delete_template(tid: str, u=Depends(require_write('REPORT_CREATE'))):
    res = get_db()['report_templates'].delete_one({'template_id': tid})
    if not res.deleted_count:
        raise HTTPException(404, 'Template not found')
    log(u, 'REPORT_TEMPLATE_DELETED', 'report_template', tid, {})
    return {'deleted': True, 'template_id': tid}


@r.get('')
def reports(case_id: str | None = None, u=Depends(current_user)):
    docs = []
    for x in get_db()['reports'].find({'case_id': case_id} if case_id else {}).sort('created_at', -1).limit(100 if not case_id else 1000):
        if get_case(x['case_id'], u):
            docs.append(serial(x))
    return {'data': docs}


@r.post('')
def create_report(case_id: str, body: GenerateIn | None = None, u=Depends(require_write('REPORT_CREATE'))):
    """Generates a report: a template by ID, one given inline, or every section in the default order. The PDF is signed
    (and timestamped when a timestamp authority is configured); the HTML file has the same content."""
    from ..services.report_signing import sign
    case = get_case(case_id, u)
    if not case:
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    template = None
    if body and body.template_id:
        t = db['report_templates'].find_one({'template_id': body.template_id})
        if not t:
            raise HTTPException(404, 'Template not found')
        template = {k: t.get(k) for k in ('template_id', 'name', 'sections', 'cover', 'approved_findings_only', 'include_screenshots')}
    elif body and body.template:
        template = body.template.model_dump()
    rid = f"RPT-{next_sequence('reports', floor=db['reports'].count_documents({})):03d}"
    root = Path(settings.storage_path) / 'reports'
    root.mkdir(parents=True, exist_ok=True)
    path, html_path, unsigned = root / f'{rid}.pdf', root / f'{rid}.html', root / f'{rid}.unsigned.pdf'
    now = datetime.now(timezone.utc)
    version = db['reports'].count_documents({'case_id': case_id}) + 1
    build_case_report(db, case, rid, version, unsigned, u, now, template=template, html_path=html_path)
    try:
        signed, signature = sign(unsigned.read_bytes(), rid, ((template or {}).get('cover') or {}).get('organisation'))
    except Exception as exc:  # never lose the report: keep it unsigned and say why
        signed, signature = unsigned.read_bytes(), {'signed': False, 'error': f'{type(exc).__name__}: {exc}'[:300]}
    path.write_bytes(signed)
    unsigned.unlink(missing_ok=True)
    pdf_sha256 = hashlib.sha256(signed).hexdigest()
    html_sha256 = hashlib.sha256(html_path.read_bytes()).hexdigest()
    doc = {'report_id': rid, 'case_id': case_id, 'path': str(path.resolve()), 'html_path': str(html_path.resolve()), 'created_at': now,
           'created_by': str(u['_id']), 'created_by_name': u.get('name'), 'version': version, 'sha256': pdf_sha256, 'html_sha256': html_sha256,
           'signature': signature, 'template': template}
    db['reports'].insert_one(doc)
    log(u, 'REPORT_GENERATED', 'report', rid, {'case_id': case_id, 'sha256': pdf_sha256, 'html_sha256': html_sha256,
                                               'signed': signature.get('signed'), 'timestamped': signature.get('timestamped'),
                                               'template_id': (template or {}).get('template_id'), 'sections': (template or {}).get('sections')})
    manager.emit_sync('REPORT_GENERATED', {'report_id': rid, 'case_id': case_id, 'sha256': pdf_sha256, 'created_at': now.isoformat()})
    return serial(doc)


def _report(rid: str, u) -> dict:
    x = get_db()['reports'].find_one({'report_id': rid})
    if not x or not get_case(x['case_id'], u):
        raise HTTPException(404, 'Report not found')
    return x


@r.get('/{rid}/download')
def download_report(rid: str, format: str = 'pdf', u=Depends(require_permission('REPORT_READ'))):
    x = _report(rid, u)
    if format not in ('pdf', 'html'):
        raise HTTPException(400, 'format must be pdf or html')
    p = Path(x['path'] if format == 'pdf' else x.get('html_path') or '')
    if not p.is_file():
        raise HTTPException(410, 'Report file unavailable' if format == 'pdf' else 'This report has no HTML version (made before HTML reports)')
    log(u, 'REPORT_DOWNLOADED', 'report', rid, {'case_id': x['case_id'], 'format': format})
    if format == 'pdf':
        return FileResponse(str(p), media_type='application/pdf', filename=f'{rid}.pdf', headers={'X-DFIP-Report-SHA256': x.get('sha256', '')})
    return Response(content=p.read_bytes(), media_type='text/html; charset=utf-8', headers={
        'Content-Disposition': f'attachment; filename="{rid}.html"', 'X-DFIP-Report-SHA256': x.get('html_sha256', ''),
        'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'"})


@r.get('/{rid}/verify')
def verify_report(rid: str, u=Depends(require_permission('REPORT_READ'))):
    """The stored report checked again: its SHA-256 against the one recorded when it was made, and its signature."""
    from ..services.report_signing import verify
    x = _report(rid, u)
    p = Path(x['path'])
    if not p.is_file():
        raise HTTPException(410, 'Report file unavailable')
    data = p.read_bytes()
    out = verify(data)
    out.update(report_id=rid, sha256=hashlib.sha256(data).hexdigest(), recorded_sha256=x.get('sha256'),
               sha256_matches=hashlib.sha256(data).hexdigest() == x.get('sha256'))
    log(u, 'REPORT_VERIFIED', 'report', rid, {'case_id': x['case_id'], 'valid': out['valid'], 'sha256_matches': out['sha256_matches']})
    return out


@r.post('/verify')
async def verify_upload(file: UploadFile = File(...), u=Depends(require_permission('REPORT_READ'))):
    """Checks a report PDF someone was given: its signature, and whether it is byte for byte a report DFIP made (of a case
    the user can see)."""
    from starlette.concurrency import run_in_threadpool
    from ..services.report_signing import verify
    data = await file.read(200 << 20)
    out = await run_in_threadpool(verify, data)  # pyHanko runs its own event loop
    sha = hashlib.sha256(data).hexdigest()
    known = get_db()['reports'].find_one({'sha256': sha})
    out.update(sha256=sha, matches_report=known['report_id'] if known and get_case(known['case_id'], u) else None)
    log(u, 'REPORT_VERIFIED', 'report', out['matches_report'] or 'upload', {'sha256': sha, 'valid': out['valid'], 'matches_report': out['matches_report']})
    return out
