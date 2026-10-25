"""Physical evidence: the devices and media seized for a case (item, bag and seal numbers, where they are kept, photos)
and their custody: received, checked out and in (with the seal checked), moved, released or destroyed. Every action is
kept on the item and in the audit log; a custody form can be printed for signatures."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from ..core.config import settings
from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from ..services.sequences import next_sequence
from ..websocket.manager import manager

r = APIRouter(prefix='/physical', tags=['physical evidence'])
KINDS = ('Laptop', 'Desktop computer', 'Phone', 'Tablet', 'USB drive', 'Hard disk', 'SSD', 'Memory card', 'Optical disc', 'Paper documents', 'Other')
STATUSES = ('IN_STORAGE', 'CHECKED_OUT', 'RELEASED', 'DESTROYED')
ACTIONS = {  # action: (allowed from, status after)
    'CHECK_OUT': (('IN_STORAGE',), 'CHECKED_OUT'),
    'CHECK_IN': (('CHECKED_OUT',), 'IN_STORAGE'),
    'TRANSFER': (('IN_STORAGE',), 'IN_STORAGE'),
    'RELEASE': (('IN_STORAGE',), 'RELEASED'),
    'DESTROY': (('IN_STORAGE',), 'DESTROYED'),
}
PHOTO_MAX = 20 << 20
PHOTO_TYPES = ((b'\xff\xd8\xff', 'image/jpeg', 'jpg'), (b'\x89PNG\r\n\x1a\n', 'image/png', 'png'))


def _text(v):
    return v.strip() if isinstance(v, str) else v


class ItemIn(BaseModel):
    case_id: str
    description: str = Field(min_length=2, max_length=500)
    kind: str = 'Other'
    make: str = Field('', max_length=120)
    model: str = Field('', max_length=120)
    serial_number: str = Field('', max_length=120)
    bag_number: str = Field('', max_length=60)
    seal_number: str = Field('', max_length=60)
    seized_at: datetime | None = None
    seized_from: str = Field('', max_length=300)
    seized_by: str = Field('', max_length=120)
    location: str = Field(min_length=2, max_length=200)
    notes: str = Field('', max_length=4000)
    evidence_ids: list[str] = []

    @field_validator('description', 'make', 'model', 'serial_number', 'bag_number', 'seal_number', 'seized_from', 'seized_by',
                     'location', 'notes', mode='before')
    @classmethod
    def strip_text(cls, v):
        return _text(v)


class ItemEdit(BaseModel):
    description: str | None = Field(None, min_length=2, max_length=500)
    kind: str | None = None
    make: str | None = Field(None, max_length=120)
    model: str | None = Field(None, max_length=120)
    serial_number: str | None = Field(None, max_length=120)
    bag_number: str | None = Field(None, max_length=60)
    seized_at: datetime | None = None
    seized_from: str | None = Field(None, max_length=300)
    seized_by: str | None = Field(None, max_length=120)
    notes: str | None = Field(None, max_length=4000)
    evidence_ids: list[str] | None = None

    @field_validator('description', 'make', 'model', 'serial_number', 'bag_number', 'seized_from', 'seized_by', 'notes', mode='before')
    @classmethod
    def strip_text(cls, v):
        return _text(v)


class CustodyIn(BaseModel):
    action: str
    person: str = Field('', max_length=120)        # who takes it (check out), who it is released to
    location: str = Field('', max_length=200)      # where it is kept now (check in, transfer)
    purpose: str = Field('', max_length=500)
    seal_intact: bool | None = None                # when it comes back
    seal_number: str = Field('', max_length=60)    # a new seal, if it was resealed
    notes: str = Field('', max_length=2000)

    @field_validator('person', 'location', 'purpose', 'seal_number', 'notes', mode='before')
    @classmethod
    def strip_text(cls, v):
        return _text(v)


class Reason(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _item(item_id: str, u) -> tuple[dict, dict]:
    x = get_db()['physical_items'].find_one({'item_id': item_id})
    case = get_case(x['case_id'], u) if x else None
    if not x or not case:
        raise HTTPException(404, 'Item not found or access denied')
    return x, case


def _check_evidence(case_id: str, ids: list[str]):
    if ids:
        known = {e['evidence_id'] for e in get_db()['evidence'].find({'case_id': case_id, 'evidence_id': {'$in': ids}}, {'evidence_id': 1})}
        missing = sorted(set(ids) - known)
        if missing:
            raise HTTPException(400, f'Evidence not in this case: {", ".join(missing)}')


def _store() -> Path:
    return Path(settings.storage_path).resolve() / 'physical'


@r.get('')
def items(case_id: str, u=Depends(current_user)):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    return {'data': [_plain(x) for x in get_db()['physical_items'].find({'case_id': case_id}).sort('item_id', 1)]}


@r.get('/{item_id}')
def one(item_id: str, u=Depends(current_user)):
    x, _ = _item(item_id, u)
    return _plain(x)


@r.post('')
def create(x: ItemIn, u=Depends(require_write('EVIDENCE_UPLOAD'))):
    if not get_case(x.case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if x.kind not in KINDS:
        raise HTTPException(400, f'kind must be one of {", ".join(KINDS)}')
    _check_evidence(x.case_id, x.evidence_ids)
    db = get_db()
    n = next_sequence('physical-items', floor=db['physical_items'].count_documents({}))
    now = datetime.now(timezone.utc)
    received = {'action': 'RECEIVED', 'at': now, 'by_id': str(u['_id']), 'by_name': u.get('name'), 'location': x.location,
                'seal_number': x.seal_number or None, 'notes': 'Booked into storage'}
    doc = {**x.model_dump(), 'item_id': f'PHY-{n:04d}', 'status': 'IN_STORAGE', 'holder': None, 'photos': [], 'custody': [received],
           'created_by': str(u['_id']), 'created_by_name': u.get('name'), 'created_at': now, 'updated_at': now}
    db['physical_items'].insert_one(doc)
    log(u, 'PHYSICAL_ITEM_CREATED', 'physical_item', doc['item_id'], {'case_id': x.case_id, 'description': x.description,
                                                                     'bag_number': x.bag_number, 'seal_number': x.seal_number, 'location': x.location})
    manager.emit_sync('PHYSICAL_ITEM_UPDATED', {'case_id': x.case_id, 'item_id': doc['item_id']})
    return _plain(doc)


@r.patch('/{item_id}')
def edit(item_id: str, x: ItemEdit, u=Depends(require_write('EVIDENCE_UPLOAD'))):
    """Corrects the description of an item (not its status, location or seal: those change through custody actions)."""
    item, _ = _item(item_id, u)
    updates = {k: v for k, v in x.model_dump().items() if v is not None}
    if 'kind' in updates and updates['kind'] not in KINDS:
        raise HTTPException(400, f'kind must be one of {", ".join(KINDS)}')
    if 'evidence_ids' in updates:
        _check_evidence(item['case_id'], updates['evidence_ids'])
    changes = {k: [_plain(item.get(k)), _plain(v)] for k, v in updates.items() if item.get(k) != v}
    if changes:
        get_db()['physical_items'].update_one({'_id': item['_id']}, {'$set': {**updates, 'updated_at': datetime.now(timezone.utc)}})
        log(u, 'PHYSICAL_ITEM_UPDATED', 'physical_item', item_id, {'case_id': item['case_id'], 'changes': changes})
    return _plain(get_db()['physical_items'].find_one({'_id': item['_id']}))


@r.post('/{item_id}/custody')
def custody(item_id: str, x: CustodyIn, u=Depends(require_write('EVIDENCE_UPLOAD'))):
    item, case = _item(item_id, u)
    if x.action not in ACTIONS:
        raise HTTPException(400, f'action must be one of {", ".join(ACTIONS)}')
    allowed, after = ACTIONS[x.action]
    if item['status'] not in allowed:
        doing = {'CHECK_OUT': 'checking it out', 'CHECK_IN': 'checking it in', 'TRANSFER': 'moving it', 'RELEASE': 'releasing it',
                 'DESTROY': 'destroying it'}[x.action]
        raise HTTPException(409, f'{item_id} is {item["status"].replace("_", " ").lower()}: {doing} is not possible now')
    if x.action in ('RELEASE', 'DESTROY') and (case.get('legal_hold') or {}).get('active'):
        raise HTTPException(423, f'{case["case_id"]} is under legal hold: its physical evidence cannot be released or destroyed')
    need = {'CHECK_OUT': ('person', 'purpose'), 'CHECK_IN': ('location',), 'TRANSFER': ('location',), 'RELEASE': ('person',), 'DESTROY': ('notes',)}
    missing = [f for f in need[x.action] if not getattr(x, f)]
    if missing:
        raise HTTPException(400, f'{x.action.replace("_", " ").capitalize()} needs: {", ".join(missing)}')
    if x.action == 'CHECK_IN' and x.seal_intact is None:
        raise HTTPException(400, 'Say whether the seal was intact when the item came back')
    now = datetime.now(timezone.utc)
    entry = {'action': x.action, 'at': now, 'by_id': str(u['_id']), 'by_name': u.get('name'),
             **{k: v for k, v in x.model_dump().items() if k != 'action' and v not in ('', None)}}
    sets = {'status': after, 'updated_at': now}
    if x.action == 'CHECK_OUT':
        sets['holder'] = {'person': x.person, 'since': now, 'purpose': x.purpose}
    elif x.action in ('CHECK_IN', 'TRANSFER'):
        sets.update(holder=None, location=x.location)
    else:
        sets['holder'] = None
    if x.seal_number:
        sets['seal_number'] = x.seal_number
    get_db()['physical_items'].update_one({'_id': item['_id']}, {'$set': sets, '$push': {'custody': entry}})
    log(u, f'PHYSICAL_{x.action}', 'physical_item', item_id, {'case_id': item['case_id'], **_plain({k: v for k, v in entry.items() if k not in ('by_id',)})})
    if x.action == 'CHECK_IN' and x.seal_intact is False and case.get('investigator_id') and case['investigator_id'] != str(u['_id']):
        from ..services.notifications import create_sync
        create_sync(case['investigator_id'], 'Seal broken', f'{item_id} ({item["description"]}) came back to storage with its seal broken '
                                                            f'(checked in by {u.get("name")}).', 'WARNING')
    manager.emit_sync('PHYSICAL_ITEM_UPDATED', {'case_id': item['case_id'], 'item_id': item_id})
    return _plain(get_db()['physical_items'].find_one({'_id': item['_id']}))


@r.post('/{item_id}/photos')
async def add_photo(item_id: str, file: UploadFile = File(...), caption: str = Form(''), u=Depends(require_write('EVIDENCE_UPLOAD'))):
    """A photo of the item (JPEG or PNG, by its content; up to 20 MB), kept read-only under its SHA-256."""
    item, _ = _item(item_id, u)
    data = await file.read(PHOTO_MAX + 1)
    if len(data) > PHOTO_MAX:
        raise HTTPException(413, 'A photo may be at most 20 MB')
    kind = next(((m, ext) for magic, m, ext in PHOTO_TYPES if data.startswith(magic)), None)
    if not kind:
        raise HTTPException(415, 'Only JPEG and PNG photos are accepted')
    sha = hashlib.sha256(data).hexdigest()
    if any(p['sha256'] == sha for p in item.get('photos') or []):
        raise HTTPException(409, 'This photo is already on the item')
    folder = _store() / item_id
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / f'{sha}.{kind[1]}'
    if not dest.exists():  # named by its SHA-256, so a file already there holds these bytes (and is read-only)
        dest.write_bytes(data)
        dest.chmod(0o440)
    now = datetime.now(timezone.utc)
    photo = {'photo_id': sha[:16], 'sha256': sha, 'size': len(data), 'mime': kind[0], 'file': dest.name, 'caption': caption.strip()[:300],
             'name': Path(file.filename or 'photo').name[:200], 'added_by_name': u.get('name'), 'added_at': now}
    get_db()['physical_items'].update_one({'_id': item['_id']}, {'$push': {'photos': photo}, '$set': {'updated_at': now}})
    log(u, 'PHYSICAL_PHOTO_ADDED', 'physical_item', item_id, {'case_id': item['case_id'], 'sha256': sha, 'size': len(data), 'name': photo['name']})
    return _plain(photo)


def _photo(item: dict, photo_id: str) -> tuple[dict, Path]:
    p = next((p for p in item.get('photos') or [] if p['photo_id'] == photo_id), None)
    if not p:
        raise HTTPException(404, 'Photo not found')
    return p, _store() / item['item_id'] / p['file']


@r.get('/{item_id}/photos/{photo_id}')
def photo(item_id: str, photo_id: str, u=Depends(current_user)):
    item, _ = _item(item_id, u)
    p, path = _photo(item, photo_id)
    if not path.is_file():
        raise HTTPException(410, 'The photo file is missing')
    return Response(content=path.read_bytes(), media_type=p['mime'], headers={
        'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment', 'Content-Security-Policy': "sandbox; default-src 'none'",
        'Cache-Control': 'no-store', 'X-DFIP-SHA256': p['sha256']})


@r.delete('/{item_id}/photos/{photo_id}')
def delete_photo(item_id: str, photo_id: str, x: Reason, u=Depends(require_write('EVIDENCE_UPLOAD'))):
    item, case = _item(item_id, u)
    if (case.get('legal_hold') or {}).get('active'):
        raise HTTPException(423, f'{case["case_id"]} is under legal hold: photos cannot be removed')
    p, path = _photo(item, photo_id)
    get_db()['physical_items'].update_one({'_id': item['_id']}, {'$pull': {'photos': {'photo_id': photo_id}}})
    if path.is_file():
        path.chmod(0o640)
        path.unlink()
    log(u, 'PHYSICAL_PHOTO_REMOVED', 'physical_item', item_id, {'case_id': item['case_id'], 'sha256': p['sha256'], 'reason': x.reason.strip()})
    return {'removed': photo_id}


@r.get('/{item_id}/form')
def form(item_id: str, u=Depends(current_user)):
    """The item's custody form as a PDF: what it is, its seals and photos, every custody action, and lines for the
    signatures of whoever hands it over and receives it."""
    from ..services.custody_form import build
    item, case = _item(item_id, u)
    data = build(item, case, u, _store() / item_id)
    log(u, 'PHYSICAL_FORM_PRINTED', 'physical_item', item_id, {'case_id': item['case_id'], 'sha256': hashlib.sha256(data).hexdigest()})
    return Response(content=data, media_type='application/pdf', headers={
        'Content-Disposition': f'attachment; filename="{item_id}-custody.pdf"', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store'})
