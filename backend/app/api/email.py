"""Email of a case: the mailboxes read, their messages, and one message's text, headers, HTML and attachments.

A message's HTML is returned only by its own endpoint, with its inline pictures (cid: references) turned into data:
URIs from the stored attachments; the browser sanitises it and shows it in a sandbox that runs no scripts and loads
nothing remote. Opening a message is recorded in the audit log, as viewing any evidence content is.
"""
import base64
import re
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.source import member_path
from ..repositories.cases import get_case
from ..security import current_user
from ..services.audit import log

r = APIRouter(prefix='/forensics/email', tags=['email'])
LIST_FIELDS = {'body_text': 0, 'body_html': 0, 'headers': 0}
MAX_INLINE = 4 << 20   # inline pictures turned into data: URIs per message


def _plain(doc):
    out = {k: v for k, v in doc.items() if k != '_id'}
    out['_id'] = str(doc['_id'])
    for k, v in list(out.items()):
        if hasattr(v, 'isoformat'):
            out[k] = v.isoformat()
    return out


def _eids(case_id, u, evidence_id=None):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id}
    if evidence_id:
        q['evidence_id'] = evidence_id
    return [e['evidence_id'] for e in get_db()['evidence'].find(q, {'evidence_id': 1})]


def _rx(search):
    if not search or not search.strip():
        return None
    if len(search) > 200:
        raise HTTPException(400, 'Search for at most 200 characters')
    return {'$regex': re.escape(search.strip()), '$options': 'i'}


def _time(v, name):
    if not v:
        return None
    try:
        t = datetime.fromisoformat(v.replace('Z', '+00:00'))
    except ValueError:
        raise HTTPException(400, f'{name} must be an ISO date or time')
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


@r.get('/stores')
def stores(case_id: str, u=Depends(current_user)):
    """The mailboxes read: path, format (PST, OST, MBOX, THUNDERBIRD, EML/MSG), user, size, SHA-256, message, attachment and
    deleted-message counts, folders and read errors."""
    q = {'evidence_id': {'$in': _eids(case_id, u)}, 'type': 'EMAIL_STORE'}
    return {'data': [_plain(x) for x in get_db()['forensic_artifacts'].find(q).sort([('evidence_id', 1), ('path', 1)])]}


@r.get('/messages')
def messages(case_id: str, evidence_id: str | None = None, store: str | None = None, folder: str | None = None,
             search: str | None = None, address: str | None = None, attachments: bool | None = None, deleted: bool | None = None,
             direction: str | None = None, start: str | None = None, end: str | None = None, order: str = 'desc',
             skip: int = 0, limit: int = 100, u=Depends(current_user)):
    """Messages (without bodies): search matches the subject, sender, recipients, attachment names and the text body;
    address matches a sender or recipient address; direction is sent or received."""
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}}
    if store:
        q['store_path'] = store
    if folder:
        q['folder'] = folder
    if direction:
        if direction not in ('sent', 'received'):
            raise HTTPException(400, 'direction must be sent or received')
        q['direction'] = direction
    if attachments is not None:
        q['attachment_count'] = {'$gt': 0} if attachments else 0
    if deleted is not None:
        q['deleted'] = deleted
    rx = _rx(search)
    if rx:
        q['$or'] = [{f: rx} for f in ('subject', 'from_name', 'from_address', 'to.address', 'to.name', 'cc.address',
                                      'attachments.name', 'body_text', 'message_id')]
    arx = _rx(address)
    if arx:
        q.setdefault('$and', []).append({'$or': [{f: arx} for f in ('from_address', 'to.address', 'cc.address', 'bcc.address')]})
    lo, hi = _time(start, 'start'), _time(end, 'end')
    if lo or hi:
        q['time'] = {**({'$gte': lo} if lo else {}), **({'$lte': hi} if hi else {})}
    if order not in ('asc', 'desc'):
        raise HTTPException(400, 'order must be asc or desc')
    col = get_db()['email_messages']
    data = [_plain(x) for x in col.find(q, LIST_FIELDS).sort([('time', 1 if order == 'asc' else -1), ('number', 1)])
            .skip(max(0, skip)).limit(max(1, min(limit, 500)))]
    return {'data': data, 'total': col.count_documents(q)}


def _message(message_id, u):
    db = get_db()
    m = db['email_messages'].find_one({'_id': ObjectId(message_id)}) if ObjectId.is_valid(message_id) else None
    if not m or not get_case(m['case_id'], u):
        raise HTTPException(404, 'Message not found or access denied')
    return m


@r.get('/messages/{message_id}')
def message(message_id: str, u=Depends(current_user)):
    """One message: text body, transport headers, recipients and attachments (each with the file-index entry that opens it
    in the file viewer). The HTML body comes from /html."""
    m = _message(message_id, u)
    paths = [a['entry_path'] for a in m.get('attachments', []) if a.get('entry_path')]
    entries = {e['path']: str(e['_id']) for e in get_db()['fs_entries'].find(
        {'evidence_id': m['evidence_id'], 'path': {'$in': paths}, 'container': {'$exists': True}}, {'path': 1})} if paths else {}
    for a in m.get('attachments', []):
        a['entry_id'] = entries.get(a.get('entry_path'))
    out = _plain(dict(m, body_html=None))
    log(u, 'EMAIL_VIEWED', 'evidence', m['evidence_id'], {'case_id': m['case_id'], 'message': message_id, 'store': m.get('store_path'),
                                                         'subject': (m.get('subject') or '')[:200]})
    return out


@r.get('/messages/{message_id}/html')
def message_html(message_id: str, u=Depends(current_user)):
    """The HTML body, with cid: pictures inlined as data: URIs (up to 4 MiB), and how many remote references it has (which the
    viewer never loads). The caller must sanitise it before showing it."""
    m = _message(message_id, u)
    body = m.get('body_html')
    if not body:
        raise HTTPException(404, 'This message has no HTML body')
    budget = [MAX_INLINE]
    by_cid = {a['content_id']: a for a in m.get('attachments', []) if a.get('content_id') and a.get('store')}

    def inline(match):
        a = by_cid.get(match.group(2))
        if not a or not (a.get('mime') or '').startswith('image/'):
            return match.group(0)
        try:
            data = member_path({'container': {'store': a['store']}}).read_bytes()
        except (OSError, ValueError):
            return match.group(0)
        if len(data) > budget[0]:
            return match.group(0)
        budget[0] -= len(data)
        return f'{match.group(1)}data:{a["mime"]};base64,{base64.b64encode(data).decode()}'

    html = re.sub(r'''((?:src|background)\s*=\s*["']?)cid:([^"'\s>]+)''', inline, body, flags=re.I)
    remote = len(re.findall(r'''(?:src|background)\s*=\s*["']?\s*(?:https?:)?//''', html, flags=re.I))
    remote += len(re.findall(r'url\(\s*["\']?\s*(?:https?:)?//', html, flags=re.I))
    log(u, 'EMAIL_VIEWED', 'evidence', m['evidence_id'], {'case_id': m['case_id'], 'message': message_id, 'part': 'html'})
    return {'html': html, 'remote_references': remote, 'truncated': bool(m.get('truncated'))}
