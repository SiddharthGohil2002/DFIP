"""More from browser profiles: searches, cookies, bookmarks, form history, saved logins and deleted history rows.
See app/forensic/browser_depth.py (the parsers) and sqlite_recover.py (deleted rows)."""
from __future__ import annotations
import hashlib
import shutil
import uuid
from datetime import datetime, timezone

from .. import browser_depth as bd
from ..source import BlobRef, TskImageSource
from ..timeline import _with_nk
from .base import Module

TYPES = ('BROWSER_SEARCH', 'BROWSER_COOKIE', 'BROWSER_BOOKMARK', 'BROWSER_AUTOFILL', 'BROWSER_LOGIN', 'BROWSER_RECOVERED')
COUNT_KEYS = {'BROWSER_SEARCH': 'browser_searches', 'BROWSER_COOKIE': 'browser_cookies', 'BROWSER_BOOKMARK': 'browser_bookmarks',
              'BROWSER_AUTOFILL': 'browser_autofill', 'BROWSER_LOGIN': 'browser_logins', 'BROWSER_RECOVERED': 'browser_recovered'}
OUTPUTS = {'searches': 'BROWSER_SEARCH', 'cookies': 'BROWSER_COOKIE', 'bookmarks': 'BROWSER_BOOKMARK', 'autofill': 'BROWSER_AUTOFILL',
           'logins': 'BROWSER_LOGIN', 'recovered': 'BROWSER_RECOVERED'}
IDENTITY = {'BROWSER_SEARCH': ('source_table', 'row_id', 'term', 'url', 'recovered'), 'BROWSER_COOKIE': ('host', 'name', 'path'),
            'BROWSER_BOOKMARK': ('folder', 'url', 'title'), 'BROWSER_AUTOFILL': ('kind', 'field', 'value'),
            'BROWSER_LOGIN': ('site', 'action_url', 'username', 'never_save'),
            'BROWSER_RECOVERED': ('file', 'file_offset', 'wal_frame', 'source_table', 'row_id')}
BATCH = 1000


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


class BrowserDepthModule(Module):
    name = 'browser_depth'
    label = 'Browser searches, cookies, bookmarks, logins and deleted history'
    description = ('Search terms, cookies, bookmarks, form history (autofill), sites with saved logins (user names, never '
                   'passwords) and deleted history rows still in the database files, for Chrome, Edge, Brave, Opera, Vivaldi '
                   'and Firefox profiles.')
    requires = ('fs_index',)
    weight = 8
    collections = ('forensic_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        for key in list(COUNT_KEYS.values()) + ['browser_profiles', 'timeline_events']:
            ctx.count(key, 0)
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False, 'is_dir': False,
             'container': {'$exists': False}, 'path': {'$regex': bd.CANDIDATES, '$options': 'i'}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1}))
        by_path = {e['path'].lower(): e for e in entries}
        found = []
        for e in sorted(entries, key=lambda x: x['path']):
            info = bd.classify(e['path'])
            if info and e.get('size'):
                found.append((e, info))
        self.src = TskImageSource(ctx.image)
        self.rows, self.events, files, profiles = [], [], [], {}
        for n, (e, info) in enumerate(found):
            ctx.progress(n / max(1, len(found)), f'{info["browser"]} {info["file"]}')
            ctx.checkpoint()
            local = self._copy(e, n, by_path, files)
            if local is None:
                continue
            prof = profiles.setdefault(info['profile_path'], {'browser': info['browser'], 'user': info['user'], 'profile': info['profile'],
                                                              'path': info['profile_path'], 'files': []})
            prof['files'].append(info['file'])
            try:
                parsed = bd.PARSERS[(info['family'], info['part'])](local)
            except Exception as exc:  # one damaged database must not lose the others
                ctx.warn(f'{e["path"]}: could not be read: {str(exc)[:200]}')
                continue
            finally:
                shutil.rmtree(local.parent, ignore_errors=True)
            for err in parsed.get('errors', [])[:5]:
                ctx.warn(f'{e["path"]}: {err}')
            for key, type_ in OUTPUTS.items():
                for item in parsed.get(key) or []:
                    self._add(type_, e, info, item)
        for i in range(0, len(self.rows), BATCH):
            ctx.insert('forensic_artifacts', self.rows[i:i + BATCH])
        events = _with_nk(self.events)
        for i in range(0, len(events), BATCH):
            ctx.insert('timeline_events', events[i:i + BATCH])
        for r in self.rows:
            ctx.count(COUNT_KEYS[r['type']])
        ctx.count('browser_profiles', len(profiles))
        ctx.count('timeline_events', len(events))
        ctx.set_fact('profiles', list(profiles.values()))
        ctx.set_fact('files', files)

    def _copy(self, e, n, by_path, files):
        ctx = self.ctx
        local = ctx.work / 'browser_depth' / f'{n:03d}' / e['path'].rsplit('/', 1)[-1]
        try:
            size, sha256 = self.src.copy_to(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']), local)
        except Exception as exc:
            ctx.warn(f'{e["path"]}: could not be copied out: {exc}')
            return None
        for suffix in ('-wal', '-journal'):
            side = by_path.get(f'{e["path"]}{suffix}'.lower())
            if side and side.get('size'):
                self.src.copy_to(BlobRef(ctx.eid, side.get('volume_id') or 'p0', inode=side['inode']), local.parent / f'{local.name}{suffix}')
        files.append({'path': e['path'], 'size': size, 'sha256': sha256})
        return local

    def _add(self, type_, e, info, item):
        ctx = self.ctx
        identity = tuple(item.get(k) for k in IDENTITY[type_])
        row = {'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': type_,
               'browser': info['browser'], 'user': info['user'], 'profile': info['profile'], 'source_path': e['path'],
               'source_file': e['path'], 'source': f'{info["family"]}_{info["part"].upper()}', 'timestamp': datetime.now(timezone.utc),
               'nk': _nk(type_, e['path'], *identity), **item}
        self.rows.append(row)
        who = f'{info["browser"]}, {info["user"]}'
        if type_ == 'BROWSER_SEARCH' and not (item.get('recovered') and item.get('source_table') in ('urls', 'moz_places')):
            engine = f', {item["engine"]}' if item.get('engine') else ''
            note = ' (recovered from a deleted history row)' if item.get('recovered') else ''
            self._event(row, item.get('time'), 'BROWSER_SEARCH', f'Searched ({who}{engine}): {item["term"]}{note}', item.get('url'))
        elif type_ == 'BROWSER_RECOVERED':
            title = f' "{item["title"]}"' if item.get('title') else ''
            self._event(row, item.get('last_visit_time'), 'BROWSER_RECOVERED',
                        f'Deleted history entry recovered ({who}, {item["recovered_from"]}): {item["url"]}{title}', item['url'])
        elif type_ == 'BROWSER_BOOKMARK':
            self._event(row, item.get('added'), 'BROWSER_BOOKMARK', f'Bookmark added ({who}): {item.get("title") or ""} {item.get("url")}'.strip(),
                        item.get('url'))
        elif type_ == 'BROWSER_LOGIN' and item.get('password_saved'):
            user = f' as {item["username"]}' if item.get('username') else ''
            self._event(row, item.get('created'), 'BROWSER_LOGIN', f'Login saved ({who}): {item.get("site")}{user}', item.get('site'))
        elif type_ == 'BROWSER_AUTOFILL' and item.get('kind') != 'saved card':
            n = item.get('times_used')
            self._event(row, item.get('last_used'), 'BROWSER_AUTOFILL',
                        f'Typed into a form ({who}): {item.get("field")} = {item.get("value")}{f" (used {n} times)" if n and n > 1 else ""}')

    def _event(self, row, when, kind, description, path=None):
        if when is None:
            return
        self.events.append({'case_id': row['case_id'], 'evidence_id': row['evidence_id'], 'timestamp': when, 'type': kind,
                            'description': description[:1000], 'path': path, 'source': row['source'], 'source_file': row['source_path'],
                            'user': row.get('user')})
