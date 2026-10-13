"""Comments on findings, tags, files and evidence. An @mention (the person's email address) notifies that person when
they can see the case; mentions of anyone else are reported back and never notified. Edits and deletions are audited;
a deleted comment leaves a marker in the thread."""
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from ..services.notifications import create_sync as notify
from ..services.team import mentions
from ..websocket.manager import manager

r = APIRouter(prefix='/comments', tags=['comments'])
TARGETS = ('FINDING', 'TAG', 'FILE', 'EVIDENCE')


class CommentIn(BaseModel):
    case_id: str
    target_type: str
    target_id: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=5000)

    @field_validator('text', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class CommentEdit(BaseModel):
    text: str = Field(min_length=1, max_length=5000)

    @field_validator('text', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


def _plain(x: dict) -> dict:
    d = {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in x.items() if k != '_id'}
    d['_id'] = str(x['_id'])
    if d.get('deleted'):
        d['text'] = ''
    return d


def target_label(case_id: str, target_type: str, target_id: str) -> str | None:
    """What the comment is on, in words, if it belongs to the case (else None)."""
    db = get_db()
    if target_type == 'FINDING':
        f = db['findings'].find_one({'_id': ObjectId(target_id), 'case_id': case_id}) if ObjectId.is_valid(target_id) else None
        return f and f'finding "{f["title"]}"'
    if target_type == 'TAG':
        t = db['tags'].find_one({'tag_id': target_id, 'case_id': case_id})
        return t and f'tagged item "{(t.get("snapshot") or {}).get("title") or t["tag_id"]}"'
    if target_type == 'EVIDENCE':
        e = db['evidence'].find_one({'evidence_id': target_id, 'case_id': case_id})
        return e and f'evidence {e["evidence_id"]} ({e.get("filename")})'
    if target_type == 'FILE':
        f = db['fs_entries'].find_one({'_id': ObjectId(target_id)}, {'evidence_id': 1, 'path': 1}) if ObjectId.is_valid(target_id) else None
        if f and db['evidence'].find_one({'evidence_id': f['evidence_id'], 'case_id': case_id}, {'_id': 1}):
            return f'file {f["path"]}'
    return None


@r.get('')
def list_comments(case_id: str, target_type: str | None = None, target_id: str | None = None, u=Depends(current_user)):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id}
    if target_type:
        if target_type not in TARGETS:
            raise HTTPException(400, f'target_type must be one of {", ".join(TARGETS)}')
        q['target_type'] = target_type
    if target_id:
        q['target_id'] = target_id
    rows = list(get_db()['comments'].find(q).sort('created_at', 1).limit(2000))
    return {'data': [_plain(x) for x in rows], 'total': len(rows)}


@r.post('')
def add(x: CommentIn, u=Depends(require_write('FINDING_CREATE'))):
    case = get_case(x.case_id, u)
    if not case:
        raise HTTPException(404, 'Case not found or access denied')
    if x.target_type not in TARGETS:
        raise HTTPException(400, f'target_type must be one of {", ".join(TARGETS)}')
    what = target_label(x.case_id, x.target_type, x.target_id)
    if not what:
        raise HTTPException(404, 'Nothing to comment on: the item is not in this case')
    named, unknown = mentions(x.text, case)
    now = datetime.now(timezone.utc)
    doc = {'case_id': x.case_id, 'target_type': x.target_type, 'target_id': x.target_id, 'target_label': what, 'text': x.text,
           'mentions': [m['user_id'] for m in named], 'author_id': str(u['_id']), 'author_name': u.get('name'), 'created_at': now}
    res = get_db()['comments'].insert_one(doc)
    doc['_id'] = res.inserted_id
    for m in named:
        if m['user_id'] != str(u['_id']):
            notify(m['user_id'], 'You were mentioned', f"{u.get('name')} mentioned you on {what} in {x.case_id}: {x.text[:200]}")
    log(u, 'COMMENT_ADDED', 'comment', res.inserted_id, {'case_id': x.case_id, 'target_type': x.target_type, 'target_id': x.target_id,
                                                         'mentions': [m['email'] for m in named]})
    manager.emit_sync('COMMENT_ADDED', {'case_id': x.case_id, 'target_type': x.target_type, 'target_id': x.target_id})
    return {**_plain(doc), 'mentioned': named, 'not_notified': unknown}


def _comment(cid: str, u) -> tuple[dict, dict]:
    c = get_db()['comments'].find_one({'_id': ObjectId(cid)}) if ObjectId.is_valid(cid) else None
    case = get_case(c['case_id'], u) if c else None
    if not c or not case:
        raise HTTPException(404, 'Comment not found or access denied')
    if c.get('deleted'):
        raise HTTPException(410, 'The comment was deleted')
    return c, case


@r.patch('/{cid}')
def edit(cid: str, x: CommentEdit, u=Depends(require_write('FINDING_CREATE'))):
    c, case = _comment(cid, u)
    if c['author_id'] != str(u['_id']):
        raise HTTPException(403, 'Only the author can edit a comment')
    named, unknown = mentions(x.text, case)
    now = datetime.now(timezone.utc)
    get_db()['comments'].update_one({'_id': c['_id']}, {'$set': {'text': x.text, 'edited_at': now, 'mentions': [m['user_id'] for m in named]},
                                                         '$push': {'previous': {'text': c['text'], 'until': now}}})
    for m in named:
        if m['user_id'] not in (c.get('mentions') or []) and m['user_id'] != str(u['_id']):
            notify(m['user_id'], 'You were mentioned', f"{u.get('name')} mentioned you on {c['target_label']} in {c['case_id']}: {x.text[:200]}")
    log(u, 'COMMENT_EDITED', 'comment', c['_id'], {'case_id': c['case_id'], 'before': c['text'][:1000]})
    return {**_plain(get_db()['comments'].find_one({'_id': c['_id']})), 'mentioned': named, 'not_notified': unknown}


@r.delete('/{cid}')
def delete(cid: str, u=Depends(require_write('FINDING_CREATE'))):
    c, _ = _comment(cid, u)
    if c['author_id'] != str(u['_id']) and u.get('role') != 'ADMIN':
        raise HTTPException(403, 'Only the author (or an administrator) can delete a comment')
    now = datetime.now(timezone.utc)
    get_db()['comments'].update_one({'_id': c['_id']}, {'$set': {'deleted': True, 'deleted_at': now, 'deleted_by_name': u.get('name'), 'text': ''},
                                                         '$unset': {'previous': ''}})
    log(u, 'COMMENT_DELETED', 'comment', c['_id'], {'case_id': c['case_id'], 'target_type': c['target_type'], 'target_id': c['target_id'],
                                                     'text': c['text'][:1000]})
    return {'deleted': True, '_id': cid}
