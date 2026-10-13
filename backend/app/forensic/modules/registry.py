"""Registry activity: what each user did (NTUSER.DAT, UsrClass.dat) and what ran or is set to run on the computer
(Amcache.hve, SYSTEM, SOFTWARE). See app/forensic/user_registry.py for what is read from each hive.

Every hive is copied out of the evidence with its .LOG1/.LOG2 transaction logs; a dirty hive (its two sequence
numbers differ) has the logs applied before it is read, so changes Windows had not yet written are included.
User hives are attributed to their owner through the profile list in SOFTWARE (folder -> SID).
"""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime, timezone

from .. import user_registry as ur
from ..registry import control_sets, open_hive
from ..source import BlobRef
from ..system_info import parse_software
from ..timeline import _parse_iso, _with_nk
from .base import Module

HIVES = [
    ('NTUSER', re.compile(r'^/(?:Users|Documents and Settings)/(?P<user>[^/]+)/NTUSER\.DAT$', re.I)),
    ('USRCLASS', re.compile(r'^/Users/(?P<user>[^/]+)/AppData/Local/Microsoft/Windows/UsrClass\.dat$', re.I)),
    ('USRCLASS', re.compile(r'^/Documents and Settings/(?P<user>[^/]+)/Local Settings/Application Data/Microsoft/Windows/UsrClass\.dat$', re.I)),
    ('AMCACHE', re.compile(r'^/Windows/AppCompat/Programs/Amcache\.hve$', re.I)),
    ('SYSTEM', re.compile(r'^/Windows/System32/config/SYSTEM$', re.I)),
    ('SOFTWARE', re.compile(r'^/Windows/System32/config/SOFTWARE$', re.I)),
]
_CANDIDATES = r'(NTUSER\.DAT|UsrClass\.dat|Amcache\.hve|/config/SYSTEM|/config/SOFTWARE)(\.LOG[12])?$'
TYPES = ('USERASSIST', 'SHELLBAG', 'TYPED_PATH', 'TYPED_URL', 'EXPLORER_SEARCH', 'RECENT_DOC', 'RUN_MRU', 'PERSISTENCE',
         'INSTALLED_PROGRAM', 'AMCACHE_FILE', 'SHIMCACHE_ENTRY', 'BAM_ENTRY', 'RDP_CONNECTION', 'NETWORK_DRIVE')
COUNT_KEYS = {'USERASSIST': 'userassist_entries', 'SHELLBAG': 'folders_browsed', 'TYPED_PATH': 'typed_paths', 'TYPED_URL': 'typed_urls',
              'EXPLORER_SEARCH': 'explorer_searches', 'RECENT_DOC': 'recent_docs', 'RUN_MRU': 'run_dialog_entries',
              'PERSISTENCE': 'persistence_entries', 'INSTALLED_PROGRAM': 'installed_programs', 'AMCACHE_FILE': 'amcache_entries',
              'SHIMCACHE_ENTRY': 'shimcache_entries', 'BAM_ENTRY': 'bam_entries', 'RDP_CONNECTION': 'rdp_connections',
              'NETWORK_DRIVE': 'network_drives'}


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


class RegistryModule(Module):
    name = 'registry'
    label = 'Registry activity'
    description = ('Programs run (UserAssist, Amcache, ShimCache, BAM), folders browsed (ShellBags), Explorer searches and typed '
                   'paths, recent documents, Run dialog commands, autostart entries and services, installed programs, remote '
                   'desktop connections and network drives, from every user hive and the system hives.')
    requires = ('fs_index',)
    weight = 15
    collections = ('forensic_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        for key in list(COUNT_KEYS.values()) + ['registry_hives', 'persistence_flagged', 'timeline_events']:
            ctx.count(key, 0)
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False, 'is_dir': False,
             'container': {'$exists': False}, 'path': {'$regex': _CANDIDATES, '$options': 'i'}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1}))
        by_path = {e['path'].lower(): e for e in entries}
        src = ctx.source()
        hives = []
        for e in entries:
            for kind, rx in HIVES:
                m = rx.match(e['path'])
                if m:
                    hives.append(self._copy(src, e, kind, m.groupdict().get('user'), by_path, len(hives)))
                    break
        hives = [h for h in hives if h]
        ctx.count('registry_hives', len(hives))
        if not hives:
            return
        software = next((h for h in hives if h['kind'] == 'SOFTWARE'), None)
        profiles = {}
        if software:
            for p in parse_software(software['local']).get('profiles', []):
                folder = (p.get('profile_path') or '').replace('/', '\\').rstrip('\\').rsplit('\\', 1)[-1].lower()
                if folder:
                    profiles[folder] = (p['sid'], p.get('profile_path'))
        self.rows, self.events = [], []
        for h in hives:
            sid, profile = profiles.get((h.get('user') or '').lower(), (None, None))
            h.update(sid=sid, profile=profile or (f'C:\\Users\\{h["user"]}' if h.get('user') else None))
            try:
                getattr(self, f'_parse_{h["kind"].lower()}')(h)
            except Exception as exc:
                ctx.warn(f'{h["path"]}: could not be read: {str(exc)[:200]}')
        accounts = {sid: folder for folder, (sid, _) in profiles.items()}
        for r in self.rows:  # BAM rows carry a SID: name its user
            if r.get('sid') and not r.get('user'):
                r['user'] = accounts.get(r['sid'])
        ctx.insert('forensic_artifacts', self.rows)
        events = _with_nk(self.events)
        ctx.insert('timeline_events', events)
        for r in self.rows:
            ctx.count(COUNT_KEYS[r['type']])
        ctx.count('persistence_flagged', sum(1 for r in self.rows if r['type'] == 'PERSISTENCE' and r.get('flags')))
        ctx.count('timeline_events', len(events))
        ctx.set_fact('hives', [{k: v for k, v in h.items() if k != 'local'} for h in hives])

    # -- hives ---------------------------------------------------------------------
    def _copy(self, src, e, kind, user, by_path, n):
        ctx = self.ctx
        folder = ctx.work / 'registry' / f'{n:02d}-{kind.lower()}'
        local = folder / e['path'].rsplit('/', 1)[-1]
        try:
            size, sha256 = src.copy_to(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']), local)
        except Exception as exc:
            ctx.warn(f'{e["path"]}: could not be copied out: {exc}')
            return None
        logs = {}
        for suffix in ('LOG1', 'LOG2'):
            le = by_path.get(f'{e["path"]}.{suffix}'.lower())
            if le and le.get('size'):
                lp = folder / f'{local.name}.{suffix}'
                src.copy_to(BlobRef(ctx.eid, le.get('volume_id') or 'p0', inode=le['inode']), lp)
                logs[suffix] = lp
        read, note = ur.replay_logs(local, logs.get('LOG1'), logs.get('LOG2'), folder / f'{local.name}.restored')
        if not note.startswith('clean'):
            ctx.warn(f'{e["path"]}: {note}')
        return {'kind': kind, 'user': user, 'path': e['path'], 'inode': e['inode'], 'volume_id': e.get('volume_id'),
                'size': size, 'sha256': sha256, 'local': read, 'transaction_logs': sorted(logs), 'state': note}

    def _row(self, h, type_, identity, **fields):
        ctx = self.ctx
        row = {'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': type_,
               'source': 'REGISTRY', 'hive': h['path'], 'hive_kind': h['kind'], 'source_path': h['path'], 'source_file': h['path'],
               'user': h.get('user'), 'sid': h.get('sid'), 'timestamp': datetime.now(timezone.utc),
               'nk': _nk(type_, h['path'], *identity), **fields}
        self.rows.append(row)
        return row

    def _event(self, row, when, kind, description, path=None):
        dt = _parse_iso(when)
        if dt and dt.year > 1601:
            self.events.append({'case_id': row['case_id'], 'evidence_id': row['evidence_id'], 'timestamp': dt, 'type': kind,
                                'description': description, 'path': path, 'source': 'REGISTRY', 'source_file': row['hive'],
                                'user': row.get('user')})

    def _who(self, h):
        return f', {h["user"]}' if h.get('user') else ''

    # -- per hive ------------------------------------------------------------------
    def _parse_ntuser(self, h):
        local, who = h['local'], self._who(h)
        by = f' ({h["user"]})' if h.get('user') else ''
        for e in ur.userassist(local, h['profile']):
            r = self._row(h, 'USERASSIST', (e['raw_name'],), **e)
            self._event(r, e['last_run'], 'PROGRAM_RUN_USERASSIST', f'Program run (UserAssist{who}): {e["program"]} (run count {e["run_count"]})',
                        e['program'])
        for type_, fn, label in (('TYPED_PATH', ur.typed_paths, 'Path typed in Explorer'), ('TYPED_URL', ur.typed_urls, 'Address typed'),
                                 ('EXPLORER_SEARCH', ur.word_wheel_query, 'Explorer search')):
            for e in fn(local):
                r = self._row(h, type_, (e['value_name'],), **e)
                if e['order'] == 0:  # the key was last written when its most recent entry was added
                    text = f'"{e["value"]}"' if type_ == 'EXPLORER_SEARCH' else e['value']
                    self._event(r, e['key_last_write'], type_, f'{label}{by}: {text}', e['value'])
        for e in ur.recent_docs(local):
            r = self._row(h, 'RECENT_DOC', (e['key_path'], e['value_name']), **e)
            if e['order'] == 0 and not e['extension']:
                self._event(r, e['key_last_write'], 'RECENT_DOC_OPENED', f'File opened (RecentDocs{who}): {e["value"]}', e['value'])
        for e in ur.run_mru(local):
            r = self._row(h, 'RUN_MRU', (e['value_name'],), **e)
            if e['order'] == 0:
                self._event(r, e['key_last_write'], 'RUN_DIALOG', f'Run dialog command{by}: {e["value"]}')
        for e in ur.ntuser_autostart(local):
            self._persistence(h, e, scope='user')
        for e in ur.rdp_connections(local):
            r = self._row(h, 'RDP_CONNECTION', (e['server'],), **e)
            self._event(r, e['key_last_write'], 'RDP_CONNECTION', f'Remote desktop connection{by} to {e["server"]}'
                        + (f' as {e["username_hint"]}' if e.get('username_hint') else ''))
        for e in ur.network_drives(local):
            r = self._row(h, 'NETWORK_DRIVE', (e['drive'],), **e)
            self._event(r, e['key_last_write'], 'NETWORK_DRIVE_MAPPED', f'Network drive {e["drive"]}: mapped to {e["remote_path"]}{who}')
        for e in ur.user_installed_programs(local):
            self._installed(h, e)
        self._shellbags(h, 'ntuser')

    def _parse_usrclass(self, h):
        self._shellbags(h, 'usrclass')

    def _shellbags(self, h, which):
        who = self._who(h)
        try:
            bags = ur.shellbags(h['local'], which)
        except StopIteration:
            return
        for e in bags:
            r = self._row(h, 'SHELLBAG', (e['key_path'], e['value_name']), **e)
            if e.get('mru_position') == 0:  # the key's last write is when its most recently browsed child was browsed
                self._event(r, e['key_last_write'], 'FOLDER_BROWSED', f'Folder browsed (ShellBags{who}): {e["path"]}', e['path'])

    def _parse_amcache(self, h):
        for e in ur.amcache(h['local']):
            r = self._row(h, 'AMCACHE_FILE', (e['path'], e['sha1']), **e)
            self._event(r, e['key_last_write'], 'PROGRAM_FIRST_SEEN',
                        f'Program recorded (Amcache): {e["path"]}' + (f', SHA-1 {e["sha1"]}' if e.get('sha1') else ''), e['path'])

    def _parse_system(self, h):
        for e in ur.shimcache(h['local']):
            self._row(h, 'SHIMCACHE_ENTRY', (e['position'], e['path']), **e)
        for e in ur.bam(h['local']):
            r = self._row(h, 'BAM_ENTRY', (e['sid'], e['device_path']), **e)
            r['user'] = None
            self._event(r, e['last_run'], 'PROGRAM_RUN_BAM', f'Program run (BAM): {e["path"]}', e['path'])
        sets = control_sets(open_hive(h['local']))
        for e in ur.services(h['local'], sets[0] if sets else 'ControlSet001'):
            self._persistence(h, e, scope='computer')

    def _parse_software(self, h):
        for e in ur.software_autostart(h['local']):
            self._persistence(h, e, scope='computer')
        for e in ur.installed_programs(h['local']):
            self._installed(h, e)

    def _persistence(self, h, e, scope):
        flags = ur.persistence_flags(e)
        r = self._row(h, 'PERSISTENCE', (e['location'], e['name']), scope=scope, flags=flags, **e)
        if e['kind'] != 'Service' or flags:  # every service is listed; only flagged ones go on the timeline
            self._event(r, e['key_last_write'], 'AUTOSTART_ENTRY',
                        f'Autostart entry written ({e["kind"]}{self._who(h)}): {e["name"]} = {e["command"]}', e['command'])

    def _installed(self, h, e):
        r = self._row(h, 'INSTALLED_PROGRAM', (e['key_path'], e['key_name']), **e)
        self._event(r, e['key_last_write'], 'PROGRAM_INSTALLED',
                    f'Program installed or updated: {e["name"]}' + (f' {e["version"]}' if e.get('version') else ''), e.get('install_location'))
