"""Chat applications and cloud storage sync clients.

Parsed: Skype (classic) `main.db` (accounts, contacts, messages, calls and file transfers), the OneDrive sync
database (`SyncEngineDatabase.db`: every file and folder the client knew, with sizes, change times and hashes),
Google Drive for desktop (`metadata_sqlite_db`) and Dropbox's `info.json` (the account and its local folder).

Detected only: Microsoft Teams, WhatsApp, Telegram, Signal and others whose message stores are encrypted or kept
in browser caches. Their folders are listed with how many files they hold, their size and the newest change, so
an examiner knows the app was used and where to look, with the reason they are not parsed.
"""
from __future__ import annotations
import base64
import binascii
import html
import json
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .browser_artifacts import _open_readonly_copy

MAX_ROWS = 200_000
_UNIX = datetime(1970, 1, 1, tzinfo=timezone.utc)
_USERS = r'^/(?:Users|Documents and Settings)/(?P<user>[^/]+)'

DATABASES = [
    ('SKYPE', re.compile(_USERS + r'/AppData/Roaming/Skype/(?P<account>[^/]+)/main\.db$', re.I)),
    ('ONEDRIVE', re.compile(_USERS + r'/AppData/Local/Microsoft/OneDrive/settings/(?P<account>Personal|Business[0-9]*)/SyncEngineDatabase\.db$', re.I)),
    ('DRIVEFS', re.compile(_USERS + r'/AppData/Local/Google/DriveFS/(?P<account>[^/]+)/metadata_sqlite_db$', re.I)),
    ('DROPBOX', re.compile(_USERS + r'/AppData/Local/Dropbox/info\.json$', re.I)),
]
CANDIDATES = r'(/Skype/[^/]+/main\.db|/SyncEngineDatabase\.db|/DriveFS/[^/]+/metadata_sqlite_db|/Dropbox/info\.json)(-wal|-journal)?$'

ENCRYPTED = 'Messages are kept in an encrypted database whose key the app holds; they are not parsed.'
CACHED = 'Messages are kept in the app\'s browser cache (IndexedDB/LevelDB), which is not parsed.'
# (app, folder pattern under a user profile, why the messages are not parsed)
APPS = [
    ('Microsoft Teams (classic)', r'/AppData/Roaming/Microsoft/Teams/', CACHED),
    ('Microsoft Teams', r'/AppData/Local/Packages/MSTeams_8wekyb3d8bbwe/', CACHED),
    ('WhatsApp', r'/AppData/Local/Packages/5319275A\.WhatsAppDesktop_cv1g1gvanyjgm/', ENCRYPTED),
    ('WhatsApp', r'/AppData/(?:Roaming|Local)/WhatsApp/', ENCRYPTED),
    ('Telegram Desktop', r'/AppData/Roaming/Telegram Desktop/', 'Messages are kept in tdata, encrypted with a local key; they are not parsed.'),
    ('Signal', r'/AppData/Roaming/Signal/', 'Messages are kept in an SQLCipher-encrypted database; they are not parsed.'),
    ('Skype', r'/AppData/Roaming/Microsoft/Skype for Desktop/', CACHED),
    ('Slack', r'/AppData/Roaming/Slack/', CACHED),
    ('Discord', r'/AppData/Roaming/discord/', CACHED),
    ('Zoom', r'/AppData/Roaming/Zoom/', 'Zoom keeps its chat history in encrypted databases; they are not parsed.'),
]
APP_PATTERNS = [(name, re.compile(_USERS + pattern, re.I), reason) for name, pattern, reason in APPS]
APP_CANDIDATES = '|'.join(p for _, p, _ in APPS)

SKYPE_TRANSFER = {0: 'new', 1: 'connecting', 2: 'waiting for acceptance', 3: 'transferring', 4: 'transferring (relay)',
                  5: 'paused', 6: 'paused by the other side', 7: 'cancelled', 8: 'completed', 9: 'failed', 10: 'not sent',
                  11: 'offered to another device', 12: 'cancelled by the other side'}
SKYPE_MESSAGE = {61: 'message', 68: 'file sent', 30: 'call started', 39: 'call ended', 50: 'contact request',
                 51: 'contact request accepted', 53: 'contact blocked', 2: 'topic changed', 4: 'chat created', 10: 'members added',
                 12: 'member removed', 13: 'left the chat', 110: 'birthday notice', 201: 'picture shared', 202: 'video shared', 253: 'file shared'}


def classify(path: str) -> tuple[str, dict] | None:
    for kind, rx in DATABASES:
        m = rx.match(path)
        if m:
            return kind, m.groupdict()
    return None


def app_of(path: str) -> tuple[str, str, str, str] | None:
    """(app, user, reason, the app's folder) when the path is inside a detected-only app's folder."""
    for name, rx, reason in APP_PATTERNS:
        m = rx.match(path)
        if m:
            return name, m.group('user'), reason, path[:m.end()].rstrip('/')
    return None


def unix_s(v):
    if not isinstance(v, (int, float)) or v <= 0:
        return None
    try:
        return _UNIX + timedelta(seconds=v)
    except (OverflowError, ValueError):
        return None


def unix_ms(v):
    return unix_s(v / 1000) if isinstance(v, (int, float)) and v > 0 else None


def _rows(con, table, limit=MAX_ROWS):
    try:
        return [dict(r) for r in con.execute(f'SELECT * FROM "{table}" LIMIT ?', (limit,))]
    except sqlite3.Error:
        return []


def skype_text(body: str | None) -> str | None:
    """A Skype body_xml as plain text (emoticons keep their text, links their address)."""
    if not body:
        return body
    s = re.sub(r'(?is)<(quote|legacyquote)\b.*?</\1>', lambda m: re.sub(r'<[^>]+>', '', m.group(0)), body)
    s = re.sub(r'<[^>]+>', '', s)
    return html.unescape(s).strip()


class _Copy:
    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        self.con, self.scratch = _open_readonly_copy(self.path)
        return self.con

    def __exit__(self, *exc):
        self.con.close()
        shutil.rmtree(self.scratch, ignore_errors=True)


# -- Skype ----------------------------------------------------------------------------------------------------------
def parse_skype(path: Path) -> dict:
    out = {'accounts': [], 'contacts': [], 'messages': [], 'calls': [], 'transfers': [], 'errors': []}
    with _Copy(path) as con:
        for a in _rows(con, 'Accounts', 100):
            out['accounts'].append({'handle': a.get('skypename'), 'name': a.get('fullname'), 'emails': a.get('emails'),
                                    'country': a.get('country'), 'city': a.get('city'),
                                    'created': unix_s(a.get('registration_timestamp')), 'last_online': unix_s(a.get('lastonline_timestamp'))})
        for c in _rows(con, 'Contacts'):
            out['contacts'].append({'handle': c.get('skypename') or c.get('pstnnumber'), 'name': c.get('fullname'),
                                    'display_name': c.get('displayname') or c.get('given_displayname'),
                                    'emails': c.get('emails'), 'phone': c.get('phone_mobile') or c.get('phone_home') or c.get('phone_office'),
                                    'country': c.get('country'), 'city': c.get('city'), 'authorized': bool(c.get('is_permanent')),
                                    'last_online': unix_s(c.get('lastonline_timestamp')), 'row_id': c.get('id')})
        convos = {c['id']: c for c in _rows(con, 'Conversations')}
        for m in _rows(con, 'Messages'):
            conv = convos.get(m.get('convo_id')) or {}
            partner = m.get('dialog_partner') or conv.get('identity')
            out['messages'].append({
                'time': unix_s(m.get('timestamp')), 'author': m.get('author'), 'author_name': m.get('from_dispname'),
                'conversation': conv.get('displayname') or conv.get('given_displayname') or partner or m.get('chatname'),
                'partner': partner, 'chat': m.get('chatname'), 'kind': SKYPE_MESSAGE.get(m.get('type'), f'type {m.get("type")}'),
                'text': skype_text(m.get('body_xml')), 'edited': unix_s(m.get('edited_timestamp')), 'row_id': m.get('id')})
        members: dict[str, list] = {}
        for cm in _rows(con, 'CallMembers'):
            members.setdefault(cm.get('call_name'), []).append(cm.get('identity'))
        for c in _rows(con, 'Calls'):
            out['calls'].append({'time': unix_s(c.get('begin_timestamp')), 'duration_seconds': c.get('duration'),
                                 'host': c.get('host_identity'), 'incoming': bool(c.get('is_incoming')),
                                 'conference': bool(c.get('is_conference')), 'topic': c.get('topic'),
                                 'members': [x for x in members.get(c.get('name'), []) if x], 'row_id': c.get('id')})
        for t in _rows(con, 'Transfers'):
            size = t.get('filesize')
            out['transfers'].append({
                'direction': {1: 'received', 2: 'sent'}.get(t.get('type'), f'type {t.get("type")}'),
                'partner': t.get('partner_handle'), 'partner_name': t.get('partner_dispname'),
                'status': SKYPE_TRANSFER.get(t.get('status'), f'status {t.get("status")}'),
                'file_name': t.get('filename'), 'file_path': t.get('filepath'),
                'size': int(size) if str(size or '').isdigit() else None,
                'started': unix_s(t.get('starttime')), 'accepted': unix_s(t.get('accepttime')), 'finished': unix_s(t.get('finishtime')),
                'row_id': t.get('id')})
    return out


# -- OneDrive -------------------------------------------------------------------------------------------------------
def _hash_kind(digest) -> tuple[str | None, str | None]:
    """(algorithm, hex) of a OneDrive localHashDigest: hex SHA-1 (personal) or base64 QuickXorHash (business)."""
    if isinstance(digest, bytes):
        digest = digest.decode('ascii', 'replace')
    if not isinstance(digest, str) or not digest:
        return None, None
    if re.fullmatch(r'[0-9A-Fa-f]{40}', digest):
        return 'SHA-1', digest.lower()
    try:
        raw = base64.b64decode(digest, validate=True)
        if len(raw) == 20:
            return 'QuickXorHash', raw.hex()
    except (binascii.Error, ValueError):
        pass
    return 'unknown', None


def parse_onedrive(path: Path) -> dict:
    out = {'files': [], 'scopes': [], 'errors': []}
    with _Copy(path) as con:
        folders = {f['resourceID']: f for f in _rows(con, 'od_ClientFolder_Records')}
        out['scopes'] = [{'scope_id': s.get('scopeID'), 'web_url': s.get('webURL'), 'remote_path': s.get('remotePath'),
                          'tenant': s.get('tenantID')} for s in _rows(con, 'od_ScopeInfo_Records', 1000)]
        files = _rows(con, 'od_ClientFile_Records')
        if not files and not folders:
            out['errors'].append('No od_ClientFile_Records or od_ClientFolder_Records (an older OneDrive database layout)')

    def path_of(rid, depth=0):
        f = folders.get(rid)
        if not f or depth > 128:
            return ''
        return f'{path_of(f.get("parentResourceID"), depth + 1)}/{f.get("folderName") or ""}'

    for f in folders.values():
        out['files'].append({'path': path_of(f['resourceID']), 'name': f.get('folderName'), 'is_folder': True,
                             'status': f.get('folderStatus'), 'resource_id': f.get('resourceID')})
    for f in files:
        algo, digest = _hash_kind(f.get('localHashDigest'))
        out['files'].append({
            'path': f'{path_of(f.get("parentResourceID"))}/{f.get("fileName") or ""}', 'name': f.get('fileName'), 'is_folder': False,
            'size': f.get('size'), 'modified': unix_s(f.get('lastChange')), 'created_on_disk': unix_s(f.get('diskCreationTime')),
            'accessed_on_disk': unix_s(f.get('diskLastAccessTime')), 'status': f.get('fileStatus'),
            'shared': bool(f.get('sharedItem')) if f.get('sharedItem') is not None else None,
            'hash_algorithm': algo, 'hash': digest, 'hash_raw': f.get('localHashDigest') if algo == 'unknown' else None,
            'resource_id': f.get('resourceID')})
    return out


# -- Google Drive for desktop (DriveFS) ------------------------------------------------------------------------------
def parse_drivefs(path: Path) -> dict:
    out = {'files': [], 'errors': []}
    with _Copy(path) as con:
        items = {i['stable_id']: i for i in _rows(con, 'items') if 'stable_id' in i}
        parents = {}
        for p in _rows(con, 'stable_parents'):
            parents.setdefault(p.get('item_stable_id'), p.get('parent_stable_id'))
        if not items:
            out['errors'].append('No items table (an unknown DriveFS layout)')

    def path_of(sid, depth=0):
        i = items.get(sid)
        if not i or depth > 128:
            return ''
        return f'{path_of(parents.get(sid), depth + 1)}/{i.get("local_title") or ""}'

    for sid, i in items.items():
        out['files'].append({
            'path': path_of(sid), 'name': i.get('local_title'), 'is_folder': bool(i.get('is_folder')), 'size': i.get('file_size'),
            'modified': unix_ms(i.get('modified_date')), 'viewed': unix_ms(i.get('viewed_by_me_date')),
            'shared_with_me': unix_ms(i.get('shared_with_me_date')), 'trashed': bool(i.get('trashed')),
            'owner': bool(i.get('is_owner')) if i.get('is_owner') is not None else None, 'mime': i.get('mime_type'),
            'resource_id': i.get('id')})
    return out


# -- Dropbox --------------------------------------------------------------------------------------------------------
def parse_dropbox_info(path: Path) -> dict:
    out = {'accounts': [], 'errors': []}
    try:
        data = json.loads(path.read_bytes()[:1 << 20].decode('utf-8', 'replace'))
    except (ValueError, OSError) as exc:
        return {'accounts': [], 'errors': [f'info.json: {exc}']}
    for kind, acc in (data.items() if isinstance(data, dict) else []):
        if isinstance(acc, dict):
            out['accounts'].append({'account_type': kind, 'sync_folder': acc.get('path'), 'team': acc.get('is_team'),
                                    'subscription': acc.get('subscription_type'), 'host_id': acc.get('host')})
    return out
