"""More Windows user activity: Jump Lists, the Windows Timeline (ActivitiesCache.db), Explorer thumbnail caches, SRUM
(network and application usage) and the Windows Search index. See the parsers: app/forensic/jumplists.py,
activities.py, thumbcache.py, srum.py and winsearch.py.

Thumbnails are stored under storage/analysis/thumbs/<evidence>/<run>/ by their SHA-256 (never by a name from the
evidence) and viewed like recovered files. Search index entries are checked against the file index (still on the disk,
deleted, or gone), and thumbnails are linked to the indexed file whose thumbnail cache ID they carry.
"""
from __future__ import annotations
import hashlib
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import activities as act
from .. import jumplists as jl
from .. import srum as sr
from .. import thumbcache as tc
from .. import winsearch as ws
from ..source import BlobRef
from ..timeline import _with_nk
from .base import Module

_USER = r'^/Users/(?P<user>[^/]+)'
TARGETS = [
    ('AUTOMATIC', re.compile(_USER + r'/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/(?P<app>[0-9a-f]{1,16})\.automaticDestinations-ms$', re.I)),
    ('CUSTOM', re.compile(_USER + r'/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/(?P<app>[0-9a-f]{1,16})\.customDestinations-ms$', re.I)),
    ('ACTIVITIES', re.compile(_USER + r'/AppData/Local/ConnectedDevicesPlatform/(?P<account>[^/]+)/ActivitiesCache\.db$', re.I)),
    ('THUMBCACHE', re.compile(_USER + r'/AppData/Local/Microsoft/Windows/Explorer/thumbcache_(?P<size>(?!idx)[^/.]+)\.db$', re.I)),
    ('SRUM', re.compile(r'^/Windows/System32/sru/SRUDB\.dat$', re.I)),
    ('SEARCH_EDB', re.compile(r'^/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows\.edb$', re.I)),
    ('SEARCH_DB', re.compile(r'^/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows\.db$', re.I)),
]
_CANDIDATES = (r'(automaticDestinations-ms|customDestinations-ms|ActivitiesCache\.db(-wal)?|/thumbcache_[^/]+\.db|/sru/SRUDB\.dat'
               r'|/Search/Data/Applications/Windows/Windows\.(edb|db)(-wal)?)$')
TYPES = ('JUMPLIST_ENTRY', 'TIMELINE_ACTIVITY', 'THUMBNAIL', 'SRUM_NETWORK', 'SRUM_APP_USAGE', 'SRUM_CONNECTIVITY', 'SEARCH_INDEX_ENTRY')
COUNT_KEYS = {'JUMPLIST_ENTRY': 'jumplist_entries', 'TIMELINE_ACTIVITY': 'timeline_activities', 'THUMBNAIL': 'thumbnails',
              'SRUM_NETWORK': 'srum_network_records', 'SRUM_APP_USAGE': 'srum_app_records', 'SRUM_CONNECTIVITY': 'srum_connectivity_records',
              'SEARCH_INDEX_ENTRY': 'search_index_entries'}
WELL_KNOWN_SIDS = {'S-1-5-18': 'SYSTEM', 'S-1-5-19': 'LOCAL SERVICE', 'S-1-5-20': 'NETWORK SERVICE'}
MAX_THUMBNAILS = 20_000
BATCH = 1000


def thumbs_root() -> Path:
    from ...core.config import settings
    return Path(settings.storage_path).resolve() / 'analysis' / 'thumbs'


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


def fs_path(windows_path: str | None) -> str | None:
    """C:\\Users\\alice\\x.txt -> /Users/alice/x.txt (only the C: drive is this image's system volume)."""
    m = re.match(r'^[Cc]:\\(.*)$', windows_path or '')
    return '/' + m.group(1).replace('\\', '/') if m else None


class UserActivityModule(Module):
    name = 'user_activity'
    label = 'Jump lists, Timeline, thumbnails, SRUM and search index'
    description = ('Jump Lists (recent and pinned items per application), the Windows Timeline (ActivitiesCache.db), Explorer '
                   'thumbnail caches (pictures that may no longer exist), SRUM network and application usage, and the Windows '
                   'Search index (files Windows indexed, including deleted ones).')
    requires = ('fs_index',)
    follows = ('computer',)
    weight = 10
    collections = ('forensic_artifacts', 'timeline_events')

    def clear(self, db, evidence_id: str):
        super().clear(db, evidence_id)
        shutil.rmtree(thumbs_root() / evidence_id, ignore_errors=True)

    def run(self, ctx):
        self.ctx = ctx
        for key in list(COUNT_KEYS.values()) + ['jumplists', 'search_entries_not_on_disk', 'timeline_events']:
            ctx.count(key, 0)
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False, 'is_dir': False,
             'container': {'$exists': False}, 'path': {'$regex': _CANDIDATES, '$options': 'i'}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1}))
        by_path = {e['path'].lower(): e for e in entries}
        self.src = ctx.source()
        accounts = dict(ctx.fact('computer', 'accounts', {}) or {})
        self.sid_names = dict(WELL_KNOWN_SIDS, **accounts)
        self.rows, self.events, self.files = [], [], []
        found = []
        for e in sorted(entries, key=lambda x: x['path']):
            for kind, rx in TARGETS:
                m = rx.match(e['path'])
                if m and e.get('size'):
                    found.append((kind, e, m.groupdict()))
                    break
        search = []
        for n, (kind, e, groups) in enumerate(found):
            ctx.progress(n / max(1, len(found)), kind.lower())
            local = self._copy(e, n, by_path)
            if local is None:
                continue
            try:
                if kind in ('AUTOMATIC', 'CUSTOM'):
                    self._jumplist(kind, e, local, groups)
                elif kind == 'ACTIVITIES':
                    self._activities(e, local, groups)
                elif kind == 'THUMBCACHE':
                    self._thumbcache(e, local, groups)
                elif kind == 'SRUM':
                    self._srum(e, local)
                else:
                    search += self._search(kind, e, local)
            except Exception as exc:  # one damaged database must not lose the others
                ctx.warn(f'{e["path"]}: could not be read: {str(exc)[:200]}')
            finally:
                shutil.rmtree(local.parent, ignore_errors=True)
        self._link_search(search)
        for i in range(0, len(self.rows), BATCH):
            ctx.insert('forensic_artifacts', self.rows[i:i + BATCH])
        events = _with_nk(self.events)
        for i in range(0, len(events), BATCH):
            ctx.insert('timeline_events', events[i:i + BATCH])
        for r in self.rows:
            ctx.count(COUNT_KEYS[r['type']])
        ctx.count('jumplists', len({r['source_path'] for r in self.rows if r['type'] == 'JUMPLIST_ENTRY'}))
        ctx.count('timeline_events', len(events))
        ctx.set_fact('files', self.files)

    # -- plumbing ------------------------------------------------------------------------
    def _copy(self, e, n, by_path):
        ctx = self.ctx
        local = ctx.work / 'user_activity' / f'{n:03d}' / e['path'].rsplit('/', 1)[-1]
        try:
            size, sha256 = self.src.copy_to(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']), local)
        except Exception as exc:
            ctx.warn(f'{e["path"]}: could not be copied out: {exc}')
            return None
        for suffix in ('-wal', '-journal'):  # SQLite logs, replayed when the copy is opened
            side = by_path.get(f'{e["path"]}{suffix}'.lower())
            if side and side.get('size'):
                self.src.copy_to(BlobRef(ctx.eid, side.get('volume_id') or 'p0', inode=side['inode']), local.parent / f'{local.name}{suffix}')
        self.files.append({'path': e['path'], 'size': size, 'sha256': sha256})
        return local

    def _row(self, type_, e, identity, **fields):
        ctx = self.ctx
        row = {'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': type_, 'source_path': e['path'],
               'source_file': e['path'], 'timestamp': datetime.now(timezone.utc), 'nk': _nk(type_, e['path'], *identity), **fields}
        self.rows.append(row)
        return row

    def _event(self, row, when, kind, description, path=None):
        if when is None:
            return
        self.events.append({'case_id': row['case_id'], 'evidence_id': row['evidence_id'], 'timestamp': when, 'type': kind,
                            'description': description, 'path': path, 'source': row['source'], 'source_file': row['source_path'],
                            'user': row.get('user')})

    # -- Jump Lists ------------------------------------------------------------------------
    def _jumplist(self, kind, e, local, groups):
        app_id = groups['app'].lower()
        app = jl.app_name(app_id)
        label = app or f'AppID {app_id}'
        user = groups.get('user')
        parsed = jl.parse_automatic(local) if kind == 'AUTOMATIC' else jl.parse_custom(local)
        for err in parsed['errors'][:5]:
            self.ctx.warn(f'{e["path"]}: {err}')
        for i, item in enumerate(parsed['entries']):
            lnk = item.get('lnk') or {}
            target = item.get('path') or lnk.get('target_path') or lnk.get('relative_path')
            fields = {('destlist_path' if k == 'path' else k): v for k, v in item.items() if k not in ('lnk', 'offset')}
            r = self._row('JUMPLIST_ENTRY', e, (item.get('entry_number'), item.get('offset'), i), source='JUMPLIST', user=user,
                          jumplist_kind='automatic' if kind == 'AUTOMATIC' else 'custom', app_id=app_id, application=app,
                          target=target, lnk=lnk or None, format_version=parsed.get('version'), **fields)
            if kind == 'AUTOMATIC' and item.get('last_used'):
                what = 'Folder opened' if (lnk.get('file_attributes') or 0) & 0x10 else 'Opened'
                self._event(r, item['last_used'], 'JUMPLIST_OPENED',
                            f'{what} (Jump list, {label}{", " + user if user else ""}): {target}', target)

    # -- Windows Timeline -----------------------------------------------------------------
    def _activities(self, e, local, groups):
        parsed = act.parse_activities_cache(local)
        for err in parsed['errors'][:5]:
            self.ctx.warn(f'{e["path"]}: {err}')
        if parsed['capped']:
            self.ctx.warn(f'{e["path"]}: only the first {act.MAX_ROWS:,} activities were read')
        user = groups.get('user')
        for a in parsed['activities']:
            r = self._row('TIMELINE_ACTIVITY', e, (a['table'], a['activity_id'], a.get('operation_type'), a['start_time']),
                          source='ACTIVITIES_CACHE', user=user, account_folder=groups.get('account'), **a)
            app = a.get('app_display_name') or a.get('app') or 'an application'
            what = a.get('display_text') or ''
            if a.get('description') and a['description'] != what:
                what = f'{what}: {a["description"]}' if what else a['description']
            if a['activity_type'] == 6 and a.get('duration_seconds') is not None:
                what = f'{what} (in use {a["duration_seconds"]} s)' if what else f'in use {a["duration_seconds"]} s'
            if a['activity_type'] == 10 and a.get('clipboard_text'):
                what = f'"{a["clipboard_text"][:120]}"'
            prefix = 'Timeline entry deleted by the user' if a.get('operation_type') == 3 else a['activity_label']
            self._event(r, a['start_time'], 'TIMELINE_ACTIVITY',
                        f'{prefix} (Windows Timeline, {app}{", " + user if user else ""}){": " + what if what else ""}', a.get('description'))

    # -- thumbnails --------------------------------------------------------------------------
    def _thumbcache(self, e, local, groups):
        ctx = self.ctx
        parsed = tc.parse_thumbcache(local)
        for err in parsed['errors'][:5]:
            ctx.warn(f'{e["path"]}: {err}')
        out = thumbs_root() / ctx.eid / ctx.run_id
        out.mkdir(parents=True, exist_ok=True)
        stored = sum(1 for r in self.rows if r['type'] == 'THUMBNAIL')
        for item in parsed['entries']:
            if stored >= MAX_THUMBNAILS:
                ctx.warn(f'Only the first {MAX_THUMBNAILS:,} thumbnails were kept')
                break
            data = tc.read_data(local, item)
            sha = hashlib.sha256(data).hexdigest()
            dest = out / f'{sha}.{item["image_type"] or "bin"}'
            if not dest.exists():
                dest.write_bytes(data)
            stored += 1
            self._row('THUMBNAIL', e, (item['hash'], item['offset']), source='THUMBCACHE', user=groups.get('user'),
                      cache_size=groups.get('size'), cache_version=parsed.get('version'), windows=parsed.get('windows'),
                      entry_hash=item['hash'], identifier=item['identifier'], width=item['width'], height=item['height'],
                      size=item['data_size'], image_type=item['image_type'], sha256=sha, offset=item['data_offset'],
                      path=str(dest), filename=dest.name, original_path=f'{e["path"]} (entry {item["hash"]})')

    # -- SRUM -----------------------------------------------------------------------------------
    def _srum(self, e, local):
        parsed = sr.parse_srum(local, self.sid_names)
        for err in parsed['errors'][:5]:
            self.ctx.warn(f'{e["path"]}: {err}')
        if parsed['capped']:
            self.ctx.warn(f'{e["path"]}: only the first {sr.MAX_ROWS:,} SRUM records were read')
        for row in parsed['rows']:
            kind = row.pop('type')
            self._row(kind, e, (row.get('record'),), source='SRUM', **row)

    # -- Windows Search -------------------------------------------------------------------------
    def _search(self, kind, e, local):
        parsed = ws.parse_windows_edb(local) if kind == 'SEARCH_EDB' else ws.parse_windows_db(local)
        for err in parsed['errors'][:5]:
            self.ctx.warn(f'{e["path"]}: {err}')
        if parsed['capped']:
            self.ctx.warn(f'{e["path"]}: only the first {ws.MAX_ROWS:,} index entries were read')
        rows = []
        for item in parsed['entries']:
            rows.append(self._row('SEARCH_INDEX_ENTRY', e, (item.get('work_id'), item.get('path')), source='WINDOWS_SEARCH',
                                  database=parsed['format'], **item))
        return rows

    def _link_search(self, rows):
        """Each index entry: is its file still on this disk (deleted, or gone)? Thumbnails get the path of their file."""
        if not rows:
            return
        ctx = self.ctx
        wanted = {}
        for r in rows:
            p = fs_path(r.get('path'))
            if p:
                wanted.setdefault(p, []).append(r)
        state = {}
        paths = list(wanted)
        for i in range(0, len(paths), BATCH):
            for f in ctx.db['fs_entries'].find({'evidence_id': ctx.eid, 'path': {'$in': paths[i:i + BATCH]}, 'is_virtual': False},
                                               {'path': 1, 'deleted': 1}):
                prev = state.get(f['path'])
                state[f['path']] = 'on disk' if (prev == 'on disk' or not f.get('deleted')) else 'deleted'
        for p, rs in wanted.items():
            for r in rs:
                r['file_state'] = state.get(p, 'not on the disk')
        for r in rows:
            r.setdefault('file_state', None)  # on another drive: not checked
            if r['file_state'] in ('deleted', 'not on the disk'):
                ctx.count('search_entries_not_on_disk')
                when = r.get('gather_time') or r.get('modified')
                self._event(r, when, 'SEARCH_INDEXED', f'Indexed by Windows Search: {r["path"]} ({r["file_state"]} now)', r['path'])
        by_id = {r['thumbnail_cache_id']: r for r in rows if r.get('thumbnail_cache_id')}
        for t in self.rows:
            if t.get('type') == 'THUMBNAIL' and t.get('entry_hash') in by_id:
                s = by_id[t['entry_hash']]
                t.update(indexed_path=s.get('path'), indexed_file_state=s.get('file_state'))
