"""Chat applications and cloud storage of a case: Skype messages, calls, file transfers, contacts and accounts, the chat
apps found but not parsed (and why), cloud sync accounts and the files they synced."""
import re

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.modules.chat_cloud import TYPES
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics', tags=['chat and cloud'])
_SEARCH = {
    'CHAT_ACCOUNT': ('handle', 'name', 'emails'), 'CHAT_CONTACT': ('handle', 'name', 'display_name', 'emails', 'phone'),
    'CHAT_MESSAGE': ('text', 'author', 'author_name', 'conversation', 'partner'), 'CHAT_CALL': ('host', 'members', 'topic'),
    'CHAT_FILE_TRANSFER': ('file_name', 'file_path', 'partner', 'partner_name'), 'CHAT_APP': ('app', 'path', 'user'),
    'CLOUD_ACCOUNT': ('provider', 'account', 'sync_folder', 'web_url', 'user'), 'CLOUD_FILE': ('path', 'name', 'hash', 'provider'),
}
_SORT = {'CHAT_ACCOUNT': [('handle', 1)], 'CHAT_CONTACT': [('handle', 1)], 'CHAT_MESSAGE': [('time', 1), ('row_id', 1)],
         'CHAT_CALL': [('time', -1)], 'CHAT_FILE_TRANSFER': [('started', -1)], 'CHAT_APP': [('app', 1), ('user', 1)],
         'CLOUD_ACCOUNT': [('provider', 1), ('account', 1)], 'CLOUD_FILE': [('is_folder', -1), ('path', 1)]}


def _plain(doc):
    out = {k: v for k, v in doc.items() if k != '_id'}
    out['_id'] = str(doc['_id'])
    for k, v in list(out.items()):
        if hasattr(v, 'isoformat'):
            out[k] = v.isoformat()
    return out


@r.get('/chat-cloud')
def rows(case_id: str, type: str, search: str | None = None, user: str | None = None, provider: str | None = None,
         conversation: str | None = None, evidence_id: str | None = None, files_only: bool = False, skip: int = 0, limit: int = 200,
         u=Depends(current_user)):
    """Records of one kind: CHAT_ACCOUNT, CHAT_CONTACT, CHAT_MESSAGE, CHAT_CALL, CHAT_FILE_TRANSFER, CHAT_APP, CLOUD_ACCOUNT,
    CLOUD_FILE. provider filters cloud records (OneDrive, Google Drive, Dropbox); conversation filters messages;
    files_only leaves folders out of the cloud files."""
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    eq = {'case_id': case_id, **({'evidence_id': evidence_id} if evidence_id else {})}
    eids = [e['evidence_id'] for e in get_db()['evidence'].find(eq, {'evidence_id': 1})]
    q: dict = {'evidence_id': {'$in': eids}, 'type': type}
    if user:
        q['user'] = user
    if provider:
        q['provider'] = provider
    if conversation:
        q['conversation'] = conversation
    if files_only:
        q['is_folder'] = False
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q['$or'] = [{f: rx} for f in _SEARCH[type]]
    col = get_db()['forensic_artifacts']
    data = [_plain(x) for x in col.find(q).sort(_SORT[type]).skip(max(0, skip)).limit(max(1, min(limit, 1000)))]
    return {'data': data, 'total': col.count_documents(q)}


@r.get('/chat-cloud/conversations')
def conversations(case_id: str, evidence_id: str | None = None, u=Depends(current_user)):
    """Chat conversations with their message counts and first and last message times."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    eq = {'case_id': case_id, **({'evidence_id': evidence_id} if evidence_id else {})}
    eids = [e['evidence_id'] for e in get_db()['evidence'].find(eq, {'evidence_id': 1})]
    out = []
    for x in get_db()['forensic_artifacts'].aggregate([
            {'$match': {'evidence_id': {'$in': eids}, 'type': 'CHAT_MESSAGE'}},
            {'$group': {'_id': {'app': '$app', 'account': '$account', 'conversation': '$conversation'}, 'messages': {'$sum': 1},
                        'first': {'$min': '$time'}, 'last': {'$max': '$time'}}},
            {'$sort': {'last': -1}}, {'$limit': 1000}]):
        out.append({**x['_id'], 'messages': x['messages'], 'first': x['first'].isoformat() if x.get('first') else None,
                    'last': x['last'].isoformat() if x.get('last') else None})
    return {'data': out}
