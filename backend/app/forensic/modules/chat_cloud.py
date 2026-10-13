"""Chat applications and cloud storage sync: Skype (classic) databases, the OneDrive, Google Drive and Dropbox clients, and
the chat apps whose messages are encrypted (detected and described, not parsed). See app/forensic/chat_cloud.py.

A synced file's hash (OneDrive keeps SHA-1 for personal accounts) is looked up among the file hashes of this
evidence, so a file in the cloud is linked to the same content on the disk, in an archive or attached to an email.
"""
from __future__ import annotations
import hashlib
import shutil
import uuid
from datetime import datetime, timezone

from .. import chat_cloud as cc
from ..source import BlobRef
from ..timeline import _with_nk
from .base import Module

TYPES = ('CHAT_ACCOUNT', 'CHAT_CONTACT', 'CHAT_MESSAGE', 'CHAT_CALL', 'CHAT_FILE_TRANSFER', 'CHAT_APP', 'CLOUD_ACCOUNT', 'CLOUD_FILE')
COUNT_KEYS = {'CHAT_ACCOUNT': 'chat_accounts', 'CHAT_CONTACT': 'chat_contacts', 'CHAT_MESSAGE': 'chat_messages', 'CHAT_CALL': 'chat_calls',
              'CHAT_FILE_TRANSFER': 'chat_file_transfers', 'CHAT_APP': 'chat_apps', 'CLOUD_ACCOUNT': 'cloud_accounts',
              'CLOUD_FILE': 'cloud_files'}
PROVIDERS = {'ONEDRIVE': 'OneDrive', 'DRIVEFS': 'Google Drive', 'DROPBOX': 'Dropbox'}
MAX_APP_ENTRIES = 500_000
BATCH = 1000


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


class ChatCloudModule(Module):
    name = 'chat_cloud'
    label = 'Chat and cloud storage'
    description = ('Skype (classic) messages, calls, file transfers and contacts; the files OneDrive and Google Drive for desktop '
                   'synced, and Dropbox accounts; Teams, WhatsApp, Telegram, Signal and other chat apps found on the disk (their '
                   'messages are encrypted or cached and are not parsed).')
    requires = ('fs_index',)
    follows = ('fileproc', 'containers', 'email')  # synced files are matched to file hashes when those ran
    weight = 6
    collections = ('forensic_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        for key in list(COUNT_KEYS.values()) + ['timeline_events']:
            ctx.count(key, 0)
        self.src = ctx.source()
        self.rows, self.events, files = [], [], []
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False, 'is_dir': False,
             'container': {'$exists': False}, 'path': {'$regex': cc.CANDIDATES, '$options': 'i'}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1}))
        by_path = {e['path'].lower(): e for e in entries}
        found = [(e, hit) for e in sorted(entries, key=lambda x: x['path']) if e.get('size') and (hit := cc.classify(e['path']))]
        for n, (e, (kind, groups)) in enumerate(found):
            ctx.progress(n / max(1, len(found) + 1), kind.lower())
            ctx.checkpoint()
            local = ctx.work / 'chat_cloud' / f'{n:03d}' / e['path'].rsplit('/', 1)[-1]
            try:
                size, sha256 = self.src.copy_to(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']), local)
                for suffix in ('-wal', '-journal'):
                    side = by_path.get(f'{e["path"]}{suffix}'.lower())
                    if side and side.get('size'):
                        self.src.copy_to(BlobRef(ctx.eid, side.get('volume_id') or 'p0', inode=side['inode']),
                                         local.parent / f'{local.name}{suffix}')
                files.append({'path': e['path'], 'size': size, 'sha256': sha256})
                if kind == 'SKYPE':
                    self._skype(e, local, groups)
                else:
                    self._cloud(kind, e, local, groups)
            except Exception as exc:  # one damaged database must not lose the others
                ctx.warn(f'{e["path"]}: could not be read: {str(exc)[:200]}')
            finally:
                shutil.rmtree(local.parent, ignore_errors=True)
        self._apps()
        self._match_hashes()
        for i in range(0, len(self.rows), BATCH):
            ctx.insert('forensic_artifacts', self.rows[i:i + BATCH])
        events = _with_nk(self.events)
        for i in range(0, len(events), BATCH):
            ctx.insert('timeline_events', events[i:i + BATCH])
        for r in self.rows:
            ctx.count(COUNT_KEYS[r['type']])
        ctx.count('timeline_events', len(events))
        ctx.set_fact('files', files)

    def _row(self, type_, source_path, identity, **fields):
        ctx = self.ctx
        row = {'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': type_,
               'source_path': source_path, 'source_file': source_path, 'timestamp': datetime.now(timezone.utc),
               'nk': _nk(type_, source_path, *identity), **fields}
        self.rows.append(row)
        return row

    def _event(self, row, when, kind, description, path=None):
        if when is None:
            return
        self.events.append({'case_id': row['case_id'], 'evidence_id': row['evidence_id'], 'timestamp': when, 'type': kind,
                            'description': description[:1000], 'path': path, 'source': row['source'],
                            'source_file': row['source_path'], 'user': row.get('user')})

    # -- Skype ------------------------------------------------------------------------------------------------------
    def _skype(self, e, local, groups):
        parsed = cc.parse_skype(local)
        for err in parsed['errors'][:5]:
            self.ctx.warn(f'{e["path"]}: {err}')
        base = {'app': 'Skype', 'source': 'SKYPE', 'user': groups['user'], 'account': groups['account']}
        p = e['path']
        self._row('CHAT_APP', p, ('Skype',), app='Skype', source='SKYPE', user=groups['user'], account=groups['account'],
                  path=p.rsplit('/', 1)[0], parsed=True, reason=None,
                  messages=len(parsed['messages']), files=None, size=None, last_change=None)
        for a in parsed['accounts']:
            self._row('CHAT_ACCOUNT', p, (a['handle'],), **base, **a)
        for c in parsed['contacts']:
            self._row('CHAT_CONTACT', p, (c['row_id'],), **base, **c)
        for m in parsed['messages']:
            r = self._row('CHAT_MESSAGE', p, (m['row_id'],), **base, **m)
            who = m.get('author_name') or m.get('author')
            text = f': {m["text"][:300]}' if m.get('text') else ''
            self._event(r, m['time'], 'CHAT_MESSAGE', f'Skype {m["kind"]} from {who} in "{m["conversation"]}" ({groups["account"]}){text}')
        for c in parsed['calls']:
            r = self._row('CHAT_CALL', p, (c['row_id'],), **base, **c)
            mins = f'{c["duration_seconds"] // 60} min {c["duration_seconds"] % 60} s' if isinstance(c.get('duration_seconds'), int) else 'unknown length'
            self._event(r, c['time'], 'CHAT_CALL', f'Skype call ({"incoming" if c["incoming"] else "outgoing"}, {mins}) '
                                                   f'with {", ".join(c["members"]) or c.get("host") or "unknown"} ({groups["account"]})')
        for t in parsed['transfers']:
            r = self._row('CHAT_FILE_TRANSFER', p, (t['row_id'],), **base, **t)
            arrow = 'to' if t['direction'] == 'sent' else 'from'
            self._event(r, t.get('finished') or t.get('started'), 'CHAT_FILE_TRANSFER',
                        f'Skype file {t["direction"]} {arrow} {t.get("partner_name") or t.get("partner")}: {t.get("file_name")} ({t["status"]})',
                        t.get('file_path'))

    # -- cloud storage -------------------------------------------------------------------------------------------------
    def _cloud(self, kind, e, local, groups):
        ctx, p, user = self.ctx, e['path'], groups['user']
        provider = PROVIDERS[kind]
        account = groups.get('account')
        if kind == 'DROPBOX':
            parsed = cc.parse_dropbox_info(local)
            for err in parsed['errors']:
                ctx.warn(f'{p}: {err}')
            for a in parsed['accounts']:
                self._row('CLOUD_ACCOUNT', p, (a['account_type'],), provider=provider, source='DROPBOX', user=user,
                          account=a['account_type'], sync_folder=a.get('sync_folder'), files=None,
                          note='Dropbox keeps its file list in encrypted databases; only the account and its folder are shown.',
                          **{k: v for k, v in a.items() if k not in ('account_type', 'sync_folder')})
            return
        parsed = cc.parse_onedrive(local) if kind == 'ONEDRIVE' else cc.parse_drivefs(local)
        for err in parsed['errors'][:5]:
            ctx.warn(f'{p}: {err}')
        sync_folder = None
        if kind == 'ONEDRIVE' and account == 'Personal':
            sync_folder = f'C:\\Users\\{user}\\OneDrive'
        scopes = parsed.get('scopes') or []
        self._row('CLOUD_ACCOUNT', p, (account,), provider=provider, source=kind, user=user, account=account, sync_folder=sync_folder,
                  web_url=next((s['web_url'] for s in scopes if s.get('web_url')), None),
                  files=sum(1 for f in parsed['files'] if not f['is_folder']), folders=sum(1 for f in parsed['files'] if f['is_folder']))
        local_root = f'/Users/{user}/OneDrive' if sync_folder else None
        for f in parsed['files']:
            r = self._row('CLOUD_FILE', p, (f.get('resource_id'), f['path']), provider=provider, source=kind, user=user, account=account,
                          local_path=f'{local_root}{f["path"]}' if local_root else None, **f)
            if not f['is_folder']:
                when = f.get('modified')
                size = f' ({f["size"]:,} bytes)' if isinstance(f.get('size'), int) else ''
                self._event(r, when, 'CLOUD_FILE', f'{provider} file changed ({account}, {user}): {f["path"]}{size}', f['path'])

    # -- apps detected, not parsed ------------------------------------------------------------------------------------
    def _apps(self):
        ctx = self.ctx
        found: dict[tuple, dict] = {}
        cursor = ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_virtual': False, 'container': {'$exists': False},
             'path': {'$regex': cc.APP_CANDIDATES, '$options': 'i'}},
            {'path': 1, 'size': 1, 'mtime': 1, 'is_dir': 1, 'deleted': 1}).limit(MAX_APP_ENTRIES)
        for e in cursor:
            hit = cc.app_of(e['path'])
            if not hit:
                continue
            app, user, reason, folder = hit
            item = found.setdefault((app, user, folder), {'files': 0, 'size': 0, 'last_change': None, 'deleted': 0, 'reason': reason})
            if e.get('is_dir'):
                continue
            item['files'] += 1
            item['deleted'] += bool(e.get('deleted'))
            item['size'] += max(0, e.get('size') or 0)
            if e.get('mtime') and (item['last_change'] is None or e['mtime'] > item['last_change']):
                item['last_change'] = e['mtime']
        for (app, user, folder), item in sorted(found.items()):
            r = self._row('CHAT_APP', folder, (app, user), app=app, source='APP_FOLDER', user=user, path=folder,
                          parsed=False, reason=item['reason'], files=item['files'], deleted_files=item['deleted'], size=item['size'],
                          last_change=item['last_change'])
            self._event(r, item['last_change'], 'CHAT_APP', f'{app} data last changed ({user}): {item["files"]} files in {folder}', folder)

    def _match_hashes(self):
        """Synced files with a SHA-1: the same content elsewhere on this evidence (the disk, archives, email attachments)."""
        ctx = self.ctx
        wanted = {r['hash'] for r in self.rows if r['type'] == 'CLOUD_FILE' and r.get('hash_algorithm') == 'SHA-1' and r.get('hash')}
        if not wanted:
            return
        same: dict[str, list] = {}
        for f in ctx.db['fs_entries'].find({'evidence_id': ctx.eid, 'sha1': {'$in': list(wanted)}}, {'path': 1, 'sha1': 1, 'deleted': 1}).limit(10_000):
            same.setdefault(f['sha1'], []).append({'path': f['path'], 'deleted': bool(f.get('deleted'))})
        for r in self.rows:
            if r['type'] == 'CLOUD_FILE' and r.get('hash') in same:
                r['same_content'] = same[r['hash']][:50]
