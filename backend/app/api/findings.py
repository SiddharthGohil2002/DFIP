"""Findings and their peer review: a finding is written (DRAFT), submitted for review (IN_REVIEW), and approved or sent
back with changes requested by someone else who may review findings (FINDING_REVIEW). Edits, reviews, reopening and
deletion are kept in the finding's history and the audit log."""
from datetime import datetime, timezone
from pathlib import Path

from bson import ObjectId
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field, field_validator

from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from ..services.notifications import create_sync as notify
from ..services.team import can_see, has_permission, name_of, user_by_id
from ..websocket.manager import manager

r = APIRouter(prefix='/findings', tags=['findings'])
SEVERITIES = {'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
STATUSES = ('DRAFT', 'IN_REVIEW', 'CHANGES_REQUESTED', 'APPROVED')
EDITABLE = {'DRAFT', 'CHANGES_REQUESTED'}


class FindingIn(BaseModel):
    case_id: str
    title: str = Field(min_length=2, max_length=300)
    description: str = Field(max_length=20000)
    severity: str = 'MEDIUM'
    evidence_ids: list[str] = []
    timeline_ids: list[str] = []


class FindingEdit(BaseModel):
    title: str | None = Field(None, min_length=2, max_length=300)
    description: str | None = Field(None, max_length=20000)
    severity: str | None = None
    evidence_ids: list[str] | None = None


class Submit(BaseModel):
    reviewer_id: str | None = None
    note: str = Field('', max_length=2000)


class Review(BaseModel):
    decision: str
    note: str = Field('', max_length=4000)

    @field_validator('note', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class Reason(BaseModel):
    reason: str = Field(min_length=5, max_length=500)

    @field_validator('reason', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _out(x: dict, comments: dict | None = None) -> dict:
    d = _plain({k: v for k, v in x.items() if k != '_id'})
    d['_id'] = str(x['_id'])
    d['status'] = x.get('status') or 'DRAFT'
    d['created_by_name'] = x.get('created_by_name') or name_of(x.get('created_by'))
    if comments is not None:
        d['comment_count'] = comments.get(d['_id'], 0)
    return d


def _check_evidence(case_id: str, ids: list[str]):
    if ids:
        known = {e['evidence_id'] for e in get_db()['evidence'].find({'case_id': case_id, 'evidence_id': {'$in': ids}}, {'evidence_id': 1})}
        missing = sorted(set(ids) - known)
        if missing:
            raise HTTPException(400, f'Evidence not in this case: {", ".join(missing)}')


def _finding(fid: str, u) -> tuple[dict, dict]:
    """The finding and its case, if the user can see the case (else 404)."""
    x = get_db()['findings'].find_one({'_id': ObjectId(fid)}) if ObjectId.is_valid(fid) else None
    case = get_case(x['case_id'], u) if x else None
    if not x or not case:
        raise HTTPException(404, 'Finding not found or access denied')
    return x, case


def _own(x: dict, u):
    if str(u['_id']) != x.get('created_by') and u.get('role') != 'ADMIN':
        raise HTTPException(403, 'Only the author (or an administrator) can change this finding')


def _held(case: dict):
    hold = case.get('legal_hold') or {}
    if hold.get('active'):
        raise HTTPException(423, f"{case['case_id']} is under legal hold: its findings cannot be deleted until the hold is released")


def _event(u, action: str, **extra) -> dict:
    return {'at': datetime.now(timezone.utc), 'by': str(u['_id']), 'by_name': u.get('name'), 'action': action, **extra}


def _update(x: dict, u, action: str, set_: dict, audit: str, **event) -> dict:
    now = datetime.now(timezone.utc)
    get_db()['findings'].update_one({'_id': x['_id']}, {'$set': {**set_, 'updated_at': now}, '$push': {'history': _event(u, action, **event)},
                                                         '$inc': {'version': 1}})
    fresh = get_db()['findings'].find_one({'_id': x['_id']})
    log(u, audit, 'finding', x['_id'], {'case_id': x['case_id'], 'title': x.get('title'), **{k: v for k, v in event.items() if k in ('note', 'reason')},
                                        **({'changes': event['changes']} if 'changes' in event else {})})
    manager.emit_sync('FINDING_UPDATED', {'_id': str(x['_id']), 'case_id': x['case_id'], 'status': fresh.get('status')})
    return fresh


@r.get('')
def list_findings(case_id: str | None = None, status: str | None = None, u=Depends(current_user)):
    q = {'case_id': case_id} if case_id else {}
    if status:
        if status not in STATUSES:
            raise HTTPException(400, f'status must be one of {", ".join(STATUSES)}')
        q['status'] = status if status != 'DRAFT' else {'$in': ['DRAFT', None]}
    rows = [x for x in get_db()['findings'].find(q).sort('created_at', -1) if get_case(x['case_id'], u)]
    ids = [str(x['_id']) for x in rows]
    counts = {c['_id']: c['n'] for c in get_db()['comments'].aggregate([
        {'$match': {'target_type': 'FINDING', 'target_id': {'$in': ids}, 'deleted': {'$ne': True}}},
        {'$group': {'_id': '$target_id', 'n': {'$sum': 1}}}])} if ids else {}
    return {'data': [_out(x, counts) for x in rows]}


@r.get('/{fid}')
def one(fid: str, u=Depends(current_user)):
    x, _ = _finding(fid, u)
    return _out(x)


@r.post('')
def create(x: FindingIn, u=Depends(require_write('FINDING_CREATE'))):
    if not get_case(x.case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if x.severity not in SEVERITIES:
        raise HTTPException(400, 'Invalid severity')
    _check_evidence(x.case_id, x.evidence_ids)
    now = datetime.now(timezone.utc)
    d = {**x.model_dump(), 'title': x.title.strip(), 'status': 'DRAFT', 'version': 1, 'created_by': str(u['_id']), 'created_by_name': u.get('name'),
         'created_at': now, 'updated_at': now, 'history': [_event(u, 'CREATED')]}
    res = get_db()['findings'].insert_one(d)
    log(u, 'FINDING_CREATED', 'finding', res.inserted_id, {'case_id': x.case_id})
    d['_id'] = res.inserted_id
    out = _out(d)
    manager.emit_sync('FINDING_CREATED', {'_id': out['_id'], 'case_id': x.case_id, 'title': x.title, 'severity': x.severity, 'created_at': out['created_at']})
    return out


@r.patch('/{fid}')
def edit(fid: str, x: FindingEdit, u=Depends(require_write('FINDING_CREATE'))):
    f, case = _finding(fid, u)
    _own(f, u)
    status = f.get('status') or 'DRAFT'
    if status not in EDITABLE:
        raise HTTPException(409, 'An approved finding is locked: reopen it to change it' if status == 'APPROVED'
                            else 'The finding is in review: withdraw it (reopen) to change it')
    updates = {k: v for k, v in x.model_dump().items() if v is not None}
    if 'severity' in updates and updates['severity'] not in SEVERITIES:
        raise HTTPException(400, 'Invalid severity')
    if 'title' in updates:
        updates['title'] = updates['title'].strip()
    if 'evidence_ids' in updates:
        _check_evidence(f['case_id'], updates['evidence_ids'])
    changes = {k: [f.get(k), v] for k, v in updates.items() if f.get(k) != v}
    if not changes:
        return _out(f)
    return _out(_update(f, u, 'EDITED', updates, 'FINDING_UPDATED', changes=changes))


@r.post('/{fid}/submit')
def submit(fid: str, x: Submit, u=Depends(require_write('FINDING_CREATE'))):
    """Sends the finding for review, optionally to a chosen reviewer (who may review findings, can see the case and is
    not the author); the reviewer, or else the case's investigator, is notified."""
    f, case = _finding(fid, u)
    _own(f, u)
    if (f.get('status') or 'DRAFT') not in EDITABLE:
        raise HTTPException(409, 'Only a draft, or a finding with changes requested, can be submitted for review')
    reviewer = None
    if x.reviewer_id:
        reviewer = user_by_id(x.reviewer_id)
        if not reviewer or not can_see(reviewer, case) or not has_permission(reviewer, 'FINDING_REVIEW'):
            raise HTTPException(400, 'The reviewer must be an active user who can see the case and may review findings')
        if str(reviewer['_id']) == f.get('created_by'):
            raise HTTPException(400, 'The author cannot review their own finding')
    fresh = _update(f, u, 'SUBMITTED', {'status': 'IN_REVIEW', 'reviewer_id': x.reviewer_id or None, 'submitted_at': datetime.now(timezone.utc)},
                    'FINDING_SUBMITTED', note=x.note.strip() or None, reviewer_id=x.reviewer_id or None)
    target = str(reviewer['_id']) if reviewer else case.get('investigator_id')
    if target and target != f.get('created_by'):
        notify(target, 'Finding to review', f"{u.get('name')} asks you to review \"{f['title']}\" in {f['case_id']}.")
    return _out(fresh)


@r.post('/{fid}/review')
def review(fid: str, x: Review, u=Depends(require_write('FINDING_REVIEW'))):
    f, case = _finding(fid, u)
    if str(u['_id']) == f.get('created_by'):
        raise HTTPException(403, 'You cannot review your own finding')
    if (f.get('status') or 'DRAFT') != 'IN_REVIEW':
        raise HTTPException(409, 'Only a finding in review can be approved or sent back')
    if x.decision not in ('APPROVED', 'CHANGES_REQUESTED'):
        raise HTTPException(400, 'decision must be APPROVED or CHANGES_REQUESTED')
    if x.decision == 'CHANGES_REQUESTED' and not x.note:
        raise HTTPException(400, 'Say what should change')
    now = datetime.now(timezone.utc)
    fresh = _update(f, u, x.decision, {'status': x.decision, 'reviewed_by': str(u['_id']), 'reviewed_by_name': u.get('name'), 'reviewed_at': now,
                                       **({'approved_at': now} if x.decision == 'APPROVED' else {})},
                    'FINDING_APPROVED' if x.decision == 'APPROVED' else 'FINDING_CHANGES_REQUESTED', note=x.note or None)
    if f.get('created_by'):
        notify(f['created_by'], 'Finding approved' if x.decision == 'APPROVED' else 'Changes requested on a finding',
               f"{u.get('name')} {'approved' if x.decision == 'APPROVED' else 'asks for changes to'} \"{f['title']}\" in {f['case_id']}"
               + (f': {x.note}' if x.note else '.'))
    return _out(fresh)


@r.post('/{fid}/reopen')
def reopen(fid: str, x: Reason, u=Depends(require_write('FINDING_CREATE'))):
    """Takes a finding in review, or an approved one, back to draft (for example to correct it); the approval is kept in
    the history."""
    f, _ = _finding(fid, u)
    _own(f, u)
    if (f.get('status') or 'DRAFT') not in ('IN_REVIEW', 'APPROVED'):
        raise HTTPException(409, 'Only a finding in review or approved can be reopened')
    return _out(_update(f, u, 'REOPENED', {'status': 'DRAFT', 'reviewer_id': None}, 'FINDING_REOPENED', reason=x.reason))


@r.delete('/{fid}')
def delete(fid: str, x: Reason, u=Depends(require_write('FINDING_CREATE'))):
    f, case = _finding(fid, u)
    _own(f, u)
    _held(case)
    if (f.get('status') or 'DRAFT') == 'APPROVED':
        raise HTTPException(409, 'An approved finding cannot be deleted: reopen it first')
    db = get_db()
    db['findings'].delete_one({'_id': f['_id']})
    removed = db['comments'].delete_many({'target_type': 'FINDING', 'target_id': fid}).deleted_count
    import shutil
    from ..services.finding_files import root
    shutil.rmtree(root() / fid, ignore_errors=True)
    log(u, 'FINDING_DELETED', 'finding', f['_id'], {'case_id': f['case_id'], 'reason': x.reason, 'comments_removed': removed,
                                                    'finding': _plain({k: f.get(k) for k in ('title', 'description', 'severity', 'status', 'evidence_ids',
                                                                                             'created_by', 'created_at', 'version')})})
    manager.emit_sync('FINDING_DELETED', {'_id': fid, 'case_id': f['case_id']})
    return {'deleted': True, '_id': fid, 'comments_removed': removed}


@r.post('/{fid}/attachments')
async def add_attachment(fid: str, file: UploadFile = File(...), caption: str = Form(''), u=Depends(require_write('FINDING_CREATE'))):
    """A screenshot for the finding (PNG or JPEG by content, up to 10 MB), kept under its SHA-256. Only while the finding
    can be edited (a draft, or with changes requested)."""
    import hashlib
    from ..services.finding_files import MAX_BYTES, root, sniff
    f, _ = _finding(fid, u)
    _own(f, u)
    if (f.get('status') or 'DRAFT') not in EDITABLE:
        raise HTTPException(409, 'Pictures can be added while the finding is a draft or has changes requested')
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, 'A picture may be at most 10 MB')
    kind = sniff(data)
    if not kind:
        raise HTTPException(415, 'Only PNG and JPEG pictures are accepted')
    sha = hashlib.sha256(data).hexdigest()
    if any(a['sha256'] == sha for a in f.get('attachments') or []):
        raise HTTPException(409, 'This picture is already attached')
    folder = root() / fid
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / f'{sha}.{kind[1]}'
    if not dest.exists():  # named by its SHA-256, so a file already there holds these bytes (and is read-only)
        dest.write_bytes(data)
        dest.chmod(0o440)
    a = {'attachment_id': sha[:16], 'sha256': sha, 'size': len(data), 'mime': kind[0], 'file': dest.name, 'name': Path(file.filename or 'picture').name[:200],
         'caption': caption.strip()[:300]}
    fresh = _update(f, u, 'EDITED', {'attachments': (f.get('attachments') or []) + [a]}, 'FINDING_ATTACHMENT_ADDED', changes={'attachments': ['', a['name']]})
    return _out(fresh)


@r.get('/{fid}/attachments/{aid}')
def get_attachment(fid: str, aid: str, u=Depends(current_user)):
    from fastapi.responses import Response
    from ..services.finding_files import attachment_path
    f, _ = _finding(fid, u)
    a = next((a for a in f.get('attachments') or [] if a['attachment_id'] == aid), None)
    p = attachment_path(fid, a) if a else None
    if not p or not p.is_file():
        raise HTTPException(404, 'Picture not found')
    return Response(content=p.read_bytes(), media_type=a['mime'], headers={'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment',
                                                                           'Content-Security-Policy': "sandbox; default-src 'none'", 'Cache-Control': 'no-store'})


@r.delete('/{fid}/attachments/{aid}')
def delete_attachment(fid: str, aid: str, u=Depends(require_write('FINDING_CREATE'))):
    from ..services.finding_files import attachment_path
    f, _ = _finding(fid, u)
    _own(f, u)
    if (f.get('status') or 'DRAFT') not in EDITABLE:
        raise HTTPException(409, 'Pictures can be removed while the finding is a draft or has changes requested')
    a = next((a for a in f.get('attachments') or [] if a['attachment_id'] == aid), None)
    if not a:
        raise HTTPException(404, 'Picture not found')
    fresh = _update(f, u, 'EDITED', {'attachments': [x for x in f['attachments'] if x['attachment_id'] != aid]}, 'FINDING_ATTACHMENT_REMOVED',
                    changes={'attachments': [a['name'], '']})
    p = attachment_path(fid, a)
    if p.is_file():
        p.chmod(0o640)
        p.unlink()
    return _out(fresh)
