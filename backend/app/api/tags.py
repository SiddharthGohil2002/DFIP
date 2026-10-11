from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from ..services.sequences import next_sequence
from ..services.tags import ITEM_COLLECTIONS, KEY_VERSION, LABELS, find_item, item_id_of, key_hash, natural_key, resolve, snapshot
from ..websocket.manager import manager

r = APIRouter(prefix='/tags', tags=['tags'])


class TagIn(BaseModel):
    case_id: str
    item_type: str
    item_id: str
    label: str = 'EVIDENCE'
    note: str = Field('', max_length=1000)

    @field_validator('note', mode='before')
    @classmethod
    def strip_note(cls, v):
        return v.strip() if isinstance(v, str) else v


class TagUpdate(BaseModel):
    label: Optional[str] = None
    note: Optional[str] = Field(None, max_length=1000)

    @field_validator('note', mode='before')
    @classmethod
    def strip_note(cls, v):
        return v.strip() if isinstance(v, str) else v


def _serial(tag, resolved=None):
    d = {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in tag.items() if k not in ('_id', 'match')}
    d['_id'] = str(tag['_id'])
    if resolved is not None:
        d['resolved'] = resolved
    return d


def _check_label(label):
    if label not in LABELS:
        raise HTTPException(400, f'Label must be one of {", ".join(LABELS)}')


def _own_tag(tag_id, u):
    tag = get_db()['tags'].find_one({'tag_id': tag_id})
    if not tag or not get_case(tag['case_id'], u):
        raise HTTPException(404, 'Tag not found or access denied')
    return tag


@r.get('')
def list_tags(case_id: str, item_type: Optional[str] = None, label: Optional[str] = None, u=Depends(current_user)):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id}
    if item_type:
        q['item_type'] = item_type
    if label:
        q['label'] = label
    db = get_db()
    out = []
    for tag in db['tags'].find(q).sort('created_at', -1).limit(2000):
        out.append(_serial(tag, resolve(db, tag) is not None))
    return {'data': out, 'total': len(out)}


@r.post('')
def create(x: TagIn, u=Depends(require_write('FINDING_CREATE'))):
    if x.item_type not in ITEM_COLLECTIONS:
        raise HTTPException(400, f'item_type must be one of {", ".join(ITEM_COLLECTIONS)}')
    _check_label(x.label)
    if not get_case(x.case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    doc = find_item(db, x.item_type, x.item_id)
    if doc is None or doc.get('case_id') != x.case_id:
        raise HTTPException(404, 'Item not found in this case')
    match = natural_key(x.item_type, doc)
    kh = key_hash(match)
    existing = db['tags'].find_one({'case_id': x.case_id, 'item_type': x.item_type, 'key_hash': kh}, {'tag_id': 1})
    if existing:
        raise HTTPException(409, f'This item is already tagged ({existing["tag_id"]}); edit that tag instead.')
    now = datetime.now(timezone.utc)
    tag = {
        'tag_id': f'TAG-{next_sequence("tags", floor=db["tags"].count_documents({})):04d}',
        'case_id': x.case_id, 'evidence_id': doc.get('evidence_id'), 'item_type': x.item_type,
        'item_id': item_id_of(x.item_type, doc), 'match': match, 'key_hash': kh, 'key_version': KEY_VERSION,
        'label': x.label, 'note': x.note,
        'snapshot': snapshot(x.item_type, doc), 'created_by': str(u['_id']), 'created_by_name': u.get('name'),
        'created_at': now, 'updated_at': now,
    }
    res = db['tags'].insert_one(tag)
    log(u, 'TAG_ADDED', 'tag', res.inserted_id, {'tag_id': tag['tag_id'], 'case_id': x.case_id, 'item_type': x.item_type,
                                                  'label': x.label, 'item': tag['snapshot']['title']})
    manager.emit_sync('TAGS_UPDATED', {'case_id': x.case_id, 'tag_id': tag['tag_id']})
    return _serial(tag, True)


@r.patch('/{tag_id}')
def update(tag_id: str, x: TagUpdate, u=Depends(require_write('FINDING_CREATE'))):
    tag = _own_tag(tag_id, u)
    changes = {k: v for k, v in x.model_dump().items() if v is not None}
    if 'label' in changes:
        _check_label(changes['label'])
    if not changes:
        raise HTTPException(400, 'Nothing to update')
    changes.update(updated_at=datetime.now(timezone.utc), updated_by=str(u['_id']), updated_by_name=u.get('name'))
    db = get_db()
    db['tags'].update_one({'_id': tag['_id']}, {'$set': changes})
    log(u, 'TAG_UPDATED', 'tag', tag['_id'], {'tag_id': tag_id, 'case_id': tag['case_id'],
                                              **{k: changes[k] for k in ('label', 'note') if k in changes}})
    manager.emit_sync('TAGS_UPDATED', {'case_id': tag['case_id'], 'tag_id': tag_id})
    fresh = db['tags'].find_one({'_id': tag['_id']})
    return _serial(fresh, resolve(db, fresh) is not None)


@r.delete('/{tag_id}')
def remove(tag_id: str, u=Depends(require_write('FINDING_CREATE'))):
    tag = _own_tag(tag_id, u)
    get_db()['tags'].delete_one({'_id': tag['_id']})
    log(u, 'TAG_REMOVED', 'tag', tag['_id'], {'tag_id': tag_id, 'case_id': tag['case_id'], 'item': (tag.get('snapshot') or {}).get('title')})
    manager.emit_sync('TAGS_UPDATED', {'case_id': tag['case_id'], 'tag_id': tag_id})
    return {'tag_id': tag_id, 'deleted': True}
