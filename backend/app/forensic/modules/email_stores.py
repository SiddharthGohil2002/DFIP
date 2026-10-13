"""Email: Outlook PST/OST files, MBOX files, Thunderbird folders, and single EML and MSG files. See app/forensic/mail.py.

Messages go to `email_messages` (with their text and HTML bodies and transport headers). Every attachment and inline
picture is saved under storage/analysis/members/mail/<evidence>/<run>/ by its SHA-256 and becomes a file-index
member (path: the mailbox, '!/', the folder, the message number and the attachment's name), hashed and typed like any
other file, so hash sets, YARA, content search and found data cover attachments too.
"""
from __future__ import annotations
import hashlib
import re
import shutil
from datetime import datetime, timezone

from .. import mail
from ..source import BlobRef, members_root, open_entry
from ..timeline import _with_nk
from .base import Module
from .fileproc import process_blob

_USER = re.compile(r'^/(?:Users|Documents and Settings)/([^/]+)/', re.I)
THUNDERBIRD = re.compile(r'/Thunderbird/Profiles/[^/]+/(?:Mail|ImapMail)/(?P<account>[^/]+)/(?P<folder>.+)$', re.I)
_NOT_MBOX = re.compile(r'\.(msf|dat|json|html?|sqlite|mab|txt|js|xml|ini|log|lock|bak)$', re.I)
CANDIDATES = r'(\.(pst|ost|mbox|mbx|eml|msg)$|/Thunderbird/Profiles/[^/]+/(Mail|ImapMail)/)'
MAX_LOOSE = 5000           # single .eml/.msg files read per evidence
MAX_EVENTS = 100_000
BATCH = 500


def mail_root():
    return members_root() / 'mail'


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


def kind_of(path: str) -> tuple[str, str] | None:
    """(format, folder) of a mailbox file found in the file index, or None."""
    low = path.lower()
    if low.endswith('.pst'):
        return 'PST', ''
    if low.endswith('.ost'):
        return 'OST', ''
    if low.endswith(('.mbox', '.mbx')):
        return 'MBOX', path.rsplit('/', 1)[-1].rsplit('.', 1)[0]
    if low.endswith('.eml'):
        return 'EML', path.rsplit('/', 2)[-2] if path.count('/') > 1 else ''
    if low.endswith('.msg'):
        return 'MSG', path.rsplit('/', 2)[-2] if path.count('/') > 1 else ''
    m = THUNDERBIRD.search(path)
    if m and not _NOT_MBOX.search(path) and '.' not in path.rsplit('/', 1)[-1]:
        folder = re.sub(r'\.sbd/', '/', m.group('folder'))
        return 'THUNDERBIRD', f'{m.group("account")}/{folder}'
    return None


class EmailModule(Module):
    name = 'email'
    label = 'Email'
    description = ('Messages, folders and attachments in Outlook PST/OST files, MBOX files, Thunderbird profiles and single EML/MSG '
                   'files. Attachments are hashed and typed like other files, so hash sets, YARA and content search cover them.')
    requires = ('fs_index',)
    weight = 15
    collections = ('email_messages', 'forensic_artifacts', 'fs_entries', 'timeline_events')

    def clear(self, db, evidence_id: str):
        super().clear(db, evidence_id)
        shutil.rmtree(mail_root() / evidence_id, ignore_errors=True)

    def run(self, ctx):
        import magic
        self.mime_of, self.describe = magic.Magic(mime=True), magic.Magic()
        self.ctx = ctx
        self.src = ctx.source()
        self.out = mail_root() / ctx.eid / ctx.run_id
        self.out.mkdir(parents=True, exist_ok=True)
        self.events = 0
        self.copies = 0
        for key in ('email_stores', 'email_messages', 'email_attachments', 'email_deleted', 'timeline_events'):
            ctx.count(key, 0)
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False, 'is_dir': False, 'size': {'$gt': 0},
             'container': {'$exists': False}, 'path': {'$regex': CANDIDATES, '$options': 'i'}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'partition_offset': 1}))
        stores, loose = [], []
        for e in sorted(entries, key=lambda x: x['path']):
            k = kind_of(e['path'])
            if k:
                (loose if k[0] in ('EML', 'MSG') else stores).append((e, k))
        if len(loose) > MAX_LOOSE:
            ctx.warn(f'Only the first {MAX_LOOSE:,} of {len(loose):,} EML/MSG files were read')
            loose = loose[:MAX_LOOSE]
        total = len(stores) + len(loose)
        for n, (e, (fmt, folder)) in enumerate(stores):
            ctx.progress(n / max(1, total), e['path'][-60:])
            self._store(e, fmt, folder)
        if loose:
            self._loose(loose, len(stores), total)

    # -- one mailbox file ------------------------------------------------------------------------------------------------
    def _copy(self, e):
        self.copies += 1
        local = self.ctx.work / 'email' / f'{self.copies:05d}' / e['path'].rsplit('/', 1)[-1]
        size, sha256 = self.src.copy_to(BlobRef(self.ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']), local)
        return local, size, sha256

    def _store(self, e, fmt, folder):
        ctx = self.ctx
        try:
            local, size, sha256 = self._copy(e)
        except Exception as exc:
            ctx.warn(f'{e["path"]}: could not be copied out: {exc}')
            return
        stats = {'messages': 0, 'attachments': 0, 'deleted': 0, 'folders': {}}
        errors = []
        try:
            if fmt in ('MBOX', 'THUNDERBIRD'):
                if not mail.looks_like_mbox(local):
                    return  # a Thunderbird file that is not a mail folder (filters, settings without an extension)
                messages = mail.parse_mbox(local, folder, self._saver(e))
            else:
                messages = mail.parse_pst(local, self._saver(e), warn=lambda m: errors.append(m))
            batch = []
            for msg in messages:
                batch.append(self._message(e, fmt, msg, stats))
                if len(batch) >= BATCH:
                    self._flush(batch)
                    batch = []
                    ctx.checkpoint()
            self._flush(batch)
        except Exception as exc:  # a damaged mailbox keeps what was read before the damage
            errors.append(f'stopped reading: {str(exc)[:300]}')
        finally:
            shutil.rmtree(local.parent, ignore_errors=True)
        for err in errors[:10]:
            ctx.warn(f'{e["path"]}: {err}')
        self._store_row(e['path'], fmt, size, sha256, stats, errors)

    def _loose(self, loose, done, total):
        ctx = self.ctx
        stats = {'messages': 0, 'attachments': 0, 'deleted': 0, 'folders': {}}
        errors, batch = [], []
        for n, (e, (fmt, folder)) in enumerate(loose):
            ctx.progress((done + n) / max(1, total), e['path'][-60:])
            try:
                local, size, sha256 = self._copy(e)
                parse = mail.parse_eml if fmt == 'EML' else mail.parse_msg
                msg = parse(local, folder, self._saver(e))
                shutil.rmtree(local.parent, ignore_errors=True)
            except Exception as exc:
                errors.append(f'{e["path"]}: {str(exc)[:200]}')
                continue
            msg['message_file'] = e['path']
            msg['message_file_sha256'] = sha256
            batch.append(self._message(e, fmt, msg, stats))
            if len(batch) >= BATCH:
                self._flush(batch)
                batch = []
        self._flush(batch)
        for err in errors[:10]:
            ctx.warn(err)
        self._store_row('(single message files)', 'EML/MSG', None, None, stats, errors, files=len(loose))

    def _store_row(self, path, fmt, size, sha256, stats, errors, files=None):
        ctx = self.ctx
        if not stats['messages'] and not errors:
            return
        m = _USER.match(path)
        client = {'PST': 'Outlook', 'OST': 'Outlook', 'THUNDERBIRD': 'Thunderbird'}.get(fmt)
        ctx.insert('forensic_artifacts', [{
            'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': 'EMAIL_STORE', 'path': path, 'source_path': path, 'format': fmt,
            'client': client, 'user': m.group(1) if m else None, 'size': size, 'sha256': sha256, 'files': files,
            'messages': stats['messages'], 'attachments': stats['attachments'], 'deleted_messages': stats['deleted'],
            'folders': [{'name': k, 'messages': v} for k, v in sorted(stats['folders'].items())], 'errors': errors[:50],
            'timestamp': datetime.now(timezone.utc), 'nk': _nk('EMAIL_STORE', path)}])
        ctx.count('email_stores')

    # -- messages and attachments ----------------------------------------------------------------------------------------
    def _saver(self, e):
        def save(data: bytes, name: str, mime):
            sha = hashlib.sha256(data).hexdigest()
            dest = self.out / sha
            if not dest.exists():
                dest.write_bytes(data)
            return {'sha256': sha, 'store': str(dest.relative_to(members_root()))}
        return save

    def _message(self, e, fmt, msg, stats) -> dict:
        ctx = self.ctx
        store_path = msg.get('message_file') or e['path']
        m = _USER.match(store_path)
        stats['messages'] += 1
        stats['deleted'] += bool(msg.get('deleted'))
        stats['folders'][msg['folder'] or '/'] = stats['folders'].get(msg['folder'] or '/', 0) + 1
        nk = _nk('EMAIL', store_path, msg['folder'], msg['index'], msg.get('message_id'))
        number = msg['index'] + 1
        members = []
        for a in msg['attachments']:
            if not a.get('stored'):
                continue
            stats['attachments'] += 0 if a.get('inline') else 1
            # A PST holds folders; an MBOX or Thunderbird file is one folder; an EML or MSG file is one message.
            inner = {'PST': f'{msg["folder"]}/message {number}/{a["name"]}'.lstrip('/'), 'OST': f'{msg["folder"]}/message {number}/{a["name"]}'.lstrip('/'),
                     'EML': a['name'], 'MSG': a['name']}.get(fmt, f'message {number}/{a["name"]}')
            doc = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'path': f'{store_path}!/{inner}', 'name': a['name'].rsplit('/', 1)[-1],
                   'inode': e.get('inode'), 'volume_id': e.get('volume_id'), 'partition_offset': e.get('partition_offset'),
                   'is_dir': False, 'is_virtual': False, 'deleted': False, 'size': a['size'],
                   'mtime': msg.get('sent') or msg.get('received'), 'atime': None, 'ctime': None, 'crtime': None,
                   'container': {'kind': 'email', 'parent': store_path, 'member': inner, 'depth': 1, 'encrypted': False,
                                 'packed_size': None, 'modified': msg.get('sent') or msg.get('received'), 'store': a['store'],
                                 'note': 'inline picture' if a.get('inline') else None, 'message_nk': nk}}
            doc.update(process_blob(open_entry(self.src, ctx.eid, doc), doc['name'], 'email attachment', self.mime_of, self.describe,
                                    checkpoint=ctx.checkpoint, warn=lambda w, p=doc['path']: ctx.warn(f'{p}: {w}')))
            a['entry_path'] = doc['path']
            a.pop('stored', None)
            members.append(doc)
        if members:
            ctx.insert('fs_entries', members)
            ctx.count('email_attachments', sum(1 for d in members if not d['container']['note']))
        when = msg.get('sent') or msg.get('received')
        doc = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'store_path': store_path, 'store_format': fmt,
               'user': m.group(1) if m else None, 'time': when, 'nk': nk, 'number': number,
               **{k: v for k, v in msg.items() if k not in ('index', 'message_file')}}
        if when and self.events < MAX_EVENTS:
            self.events += 1
            names = [a['name'] for a in msg['attachments'] if not a.get('inline')]
            to = ', '.join(x.get('address') or x.get('name') or '' for x in (msg.get('to') or [])[:3])
            who = msg.get('from_address') or msg.get('from_name') or 'unknown sender'
            att = f'; {len(names)} attachment{"s" if len(names) != 1 else ""} ({", ".join(names[:3])})' if names else ''
            deleted = ' [deleted]' if msg.get('deleted') else ''
            doc['_event'] = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': when,
                             'type': 'EMAIL_SENT' if msg['direction'] == 'sent' else 'EMAIL_RECEIVED',
                             'description': f'Email {msg["direction"]}{deleted}: "{msg.get("subject") or "(no subject)"}" from {who} to {to or "?"}{att}'[:1000],
                             'path': store_path, 'source': f'EMAIL_{fmt}', 'source_file': store_path, 'user': doc['user']}
        return doc

    def _flush(self, batch):
        if not batch:
            return
        ctx = self.ctx
        events = [d.pop('_event') for d in batch if '_event' in d]
        ctx.insert('email_messages', batch)
        events = _with_nk(events)
        ctx.insert('timeline_events', events)
        ctx.count('email_messages', len(batch))
        ctx.count('email_deleted', sum(1 for d in batch if d.get('deleted')))
        ctx.count('timeline_events', len(events))
