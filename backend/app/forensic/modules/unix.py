"""Linux and macOS (module `unix`): the computer and its accounts, shell history, logins and log events (wtmp, btmp,
auth.log, syslog), scheduled jobs and services (cron, systemd, launchd), recently used files (GNOME), and on macOS
Safari's history and downloads, the download quarantine database and known Wi-Fi networks.

Each volume is checked for the system it holds (a disk's file systems, or a package's roots): Linux by /etc/passwd or
/etc/os-release, macOS by SystemVersion.plist or its preferences. Parsers are in forensic/unix.py.
"""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import unix
from ..source import BlobRef
from ..timeline import browser_events
from .base import Module

MAX_FILE = 64 << 20
MAX_LINES = 200_000          # log records kept per evidence
LOG_FILES = r'^/(?:var/log|private/var/log)/(?P<name>(?:auth\.log|secure|syslog|messages)(?:\.\d+)?(?:\.gz)?)$'


class UnixModule(Module):
    name = 'unix'
    label = 'Linux and macOS'
    description = ('Linux and macOS computers: accounts, shell history, logins and log events, cron, systemd and launchd jobs, '
                   'recently used files, Safari, downloads (quarantine) and Wi-Fi networks.')
    requires = ('fs_index',)
    weight = 6
    collections = ('forensic_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        self.src = ctx.source()
        self.zone = ctx.fact('tz_probe', 'zone')
        for key in ('unix_systems', 'shell_commands', 'unix_events', 'scheduled_jobs', 'recent_documents', 'wifi_networks',
                    'quarantine_events', 'browser_history', 'browser_downloads', 'timeline_events'):
            ctx.count(key, 0)
        systems = []
        for fs in ctx.fact('fs_index', 'filesystems', []) or []:
            vid = fs['volume_id']
            kind = fs.get('os') if fs.get('os') in ('linux', 'macos') else self._detect(vid)
            if kind:
                self.vid, self.kind, self.docs, self.events = vid, kind, [], []
                (self._linux if kind == 'linux' else self._macos)()
                ctx.insert('forensic_artifacts', self.docs)
                ctx.insert('timeline_events', self.events)
                ctx.count('timeline_events', len(self.events))
                ctx.count('unix_systems')
                systems.append({'volume_id': vid, 'os': kind})
        ctx.set_fact('systems', systems)

    # -- helpers -----------------------------------------------------------------------
    def _detect(self, vid):
        if self.src.find(vid, '/etc/passwd') or self.src.find(vid, '/etc/os-release'):
            return 'linux'
        if self.src.find(vid, '/System/Library/CoreServices/SystemVersion.plist') or \
                self.src.find(vid, '/Library/Preferences/SystemConfiguration/preferences.plist'):
            return 'macos'
        return None

    def _read(self, path: str) -> bytes | None:
        handle = self.src.find(self.vid, path)
        return self._read_handle(handle) if handle else None

    def _read_handle(self, handle) -> bytes | None:
        try:
            blob = self.src.open(BlobRef(self.ctx.eid, self.vid, inode=handle))
            return blob.read(0, min(blob.size, MAX_FILE))
        except (OSError, ValueError) as exc:
            self.ctx.warn(f'{handle}: could not be read: {exc}')
            return None

    def _local(self, entry) -> Path | None:
        """A copy of a database (with its -wal and -journal) for sqlite3."""
        local = self.ctx.work / 'unix' / uuid.uuid4().hex / entry['path'].rsplit('/', 1)[-1]
        try:
            self.src.copy_to(BlobRef(self.ctx.eid, self.vid, inode=entry['inode']), local)
        except (OSError, ValueError) as exc:
            self.ctx.warn(f'{entry["path"]}: could not be read: {exc}')
            return None
        for suffix in ('-wal', '-journal'):
            side = self._files(f'^{re.escape(entry["path"] + suffix)}$')
            if side:
                self.src.copy_to(BlobRef(self.ctx.eid, self.vid, inode=side[0]['inode']), local.parent / (local.name + suffix))
        return local

    def _files(self, pattern: str, flags: str = '') -> list[dict]:
        return list(self.ctx.db['fs_entries'].find({'evidence_id': self.ctx.eid, 'volume_id': self.vid, 'deleted': False, 'is_dir': False,
                                                    'path': {'$regex': pattern, '$options': flags}},
                                                   {'path': 1, 'inode': 1, 'size': 1, 'mtime': 1}).sort('path', 1))

    def _doc(self, type_, nk: str, **fields) -> dict:
        doc = {'artifact_id': str(uuid.uuid4()), 'case_id': self.ctx.case_id, 'evidence_id': self.ctx.eid, 'type': type_,
               'timestamp': datetime.now(timezone.utc), 'source': 'UNIX', 'os_family': 'macOS' if self.kind == 'macos' else 'Linux',
               'volume_id': self.vid, 'nk': hashlib.sha1(f'{type_}|{self.vid}|{nk}'.encode()).hexdigest(), **fields}
        self.docs.append(doc)
        return doc

    def _event(self, when, type_, description, **fields):
        if when:
            self.events.append({'case_id': self.ctx.case_id, 'evidence_id': self.ctx.eid, 'timestamp': when, 'type': type_,
                                'description': description[:1000], 'source': 'UNIX', 'volume_id': self.vid, **fields})

    @staticmethod
    def _user_of(path: str) -> str | None:
        m = re.match(r'^/(?:home|Users)/([^/]+)/', path)
        return m.group(1) if m else 'root' if path.startswith('/root/') else None

    # -- Linux ---------------------------------------------------------------------------
    def _linux(self):
        ctx = self.ctx
        rel = unix.os_release(self._read('/etc/os-release') or self._read('/usr/lib/os-release') or b'')
        hostname = (self._read('/etc/hostname') or b'').decode(errors='replace').strip() or None
        zone = (self._read('/etc/timezone') or b'').decode(errors='replace').strip() or unix.tzif_posix(self._read('/etc/localtime') or b'')
        accounts = unix.passwd(self._read('/etc/passwd') or b'', self._read('/etc/group') or b'', self._read('/etc/shadow') or b'')
        wtmp = []
        for e in self._files(r'^/var/log/wtmp(\.\d+)?$'):
            wtmp += unix.utmp(self._read_handle(e['inode']) or b'')
        shutdowns = [r['time'] for r in wtmp if r['kind'] == 'shutdown']
        self._doc('COMPUTER_INFO', 'computer', computer_name=hostname, hostname=hostname, time_zone=zone, interfaces=[],
                  last_shutdown=max(shutdowns) if shutdowns else None,
                  os={'product_name': rel.get('PRETTY_NAME') or rel.get('NAME'), 'version': rel.get('VERSION_ID'), 'build': rel.get('BUILD_ID')})
        last_login = {}
        for r in wtmp:
            if r['kind'] == 'login' and r['user']:
                last_login[r['user']] = max(last_login.get(r['user']) or r['time'], r['time'])
        for a in accounts:
            self._doc('USER_ACCOUNT', a['username'], last_logon=last_login.get(a['username']), **a)
        ctx.count('user_accounts', len(accounts))
        self._history(r'^/(?:home/[^/]+|root)/\.(bash|zsh)_history$')
        self._utmp_events(wtmp, failed=False)
        for e in self._files(r'^/var/log/btmp(\.\d+)?$'):
            self._utmp_events(unix.utmp(self._read_handle(e['inode']) or b'', failed=True), failed=True)
        self._logs()
        # Scheduled jobs and services.
        jobs = []
        for e in self._files(r'^/etc/(crontab|cron\.d/[^/]+)$'):
            jobs += unix.crontab(self._read_handle(e['inode']) or b'', e['path'])
        for e in self._files(r'^/var/spool/cron/(crontabs/)?[^/]+$'):
            jobs += unix.crontab(self._read_handle(e['inode']) or b'', e['path'], user=e['path'].rsplit('/', 1)[-1])
        wanted = {p['path'].rsplit('/', 1)[-1] for p in ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'volume_id': self.vid, 'path': {'$regex': r'^/etc/systemd/system/[^/]+\.(wants|requires)/[^/]+$'}}, {'path': 1})}
        for e in self._files(r'^/(?:etc/systemd/system|home/[^/]+/\.config/systemd/user)/[^/]+\.service$'):
            unit = unix.systemd_unit(self._read_handle(e['inode']) or b'', e['path'], e['path'].rsplit('/', 1)[-1] in wanted)
            if unit:
                jobs.append(unit)
        for e in self._files(r'^/(?:home/[^/]+|root)/\.ssh/authorized_keys2?$'):
            for n, line in enumerate((self._read_handle(e['inode']) or b'').decode(errors='replace').splitlines(), 1):
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    comment = parts[-1] if len(parts) >= 3 else None
                    jobs.append({'mechanism': 'ssh key', 'name': comment or f'key {n}', 'command': f'{parts[0]} key {comment or ""}'.strip(),
                                 'user': self._user_of(e['path']), 'schedule': 'whenever the key logs in', 'source_path': e['path'],
                                 'flags': [{'code': 'SSH_KEY', 'severity': 'low', 'label': 'Lets the holder of this key log in'}]})
        self._jobs(jobs)
        # Recently used files (GNOME/GTK).
        for e in self._files(r'^/home/[^/]+/\.local/share/recently-used\.xbel$'):
            user = self._user_of(e['path'])
            try:
                items = unix.recently_used(self._read_handle(e['inode']) or b'')
            except Exception as exc:
                ctx.warn(f'{e["path"]}: {exc}')
                continue
            for it in items:
                app = (it['applications'] or [{}])[0]
                d = self._doc('RECENT_DOCUMENT', f'{user}|{it["href"]}', user=user, source_path=e['path'], application=app.get('name'), **it)
                self._event(d['visited'] or d['modified'], 'RECENT_DOCUMENT', f'{user} opened {it["path"]}' + (f' with {app["name"]}' if app.get('name') else ''),
                            path=it['path'])
            ctx.count('recent_documents', len(items))

    def _history(self, pattern):
        for e in self._files(pattern):
            shell = 'zsh' if e['path'].endswith(('.zsh_history', '.history')) else 'bash'
            user = self._user_of(e['path'])
            for c in unix.shell_history(self._read_handle(e['inode']) or b'', shell):
                self._doc('SHELL_COMMAND', f'{e["path"]}|{c["order"]}', user=user, shell=shell, source_path=e['path'],
                          notable=any(f['severity'] == 'high' for f in c['flags']), **c)
                flagged = ' [' + '; '.join(f['label'] for f in c['flags']) + ']' if c['flags'] else ''
                self._event(c['time'], 'SHELL_COMMAND', f'{user} ran: {c["command"][:300]}{flagged}', path=e['path'], user=user)
                self.ctx.count('shell_commands')

    def _utmp_events(self, records, failed):
        label = {'login': 'Logged in', 'logout': 'Logged out', 'boot': 'System booted', 'shutdown': 'System shut down',
                 'failed_login': 'Failed login'}
        source = 'btmp' if failed else 'wtmp'
        for r in records:
            fields = {k: r.get(k) for k in ('user', 'terminal', 'host', 'pid', 'logout', 'duration_seconds')}
            self._doc('UNIX_EVENT', f'{source}|{r["record"]}', kind=r['kind'], label=label[r['kind']], log=source, time=r['time'],
                      notable=r['kind'] in ('failed_login', 'login'), **fields)
            who = f'{r["user"]}' + (f' from {r["host"]}' if r.get('host') else '') + (f' on {r["terminal"]}' if r.get('terminal') else '')
            self._event(r['time'], 'UNIX_EVENT', f'{label[r["kind"]]}: {who} ({source})', user=r.get('user'))
            self.ctx.count('unix_events')

    def _logs(self):
        kept = 0
        files = self._files(LOG_FILES)
        for e in files:
            name = re.match(LOG_FILES, e['path']).group('name')
            mtime = e.get('mtime')
            mtime = mtime.replace(tzinfo=timezone.utc) if isinstance(mtime, datetime) and mtime.tzinfo is None else mtime
            records = unix.log_lines(self._read_handle(e['inode']) or b'', name, self.zone, mtime)
            usb = {}
            for r in records:
                f = r['fields']
                if r['kind'] in ('usb_serial', 'usb_product') and f.get('bus') in usb:  # details of the device just connected
                    usb[f['bus']].update({k: v for k, v in f.items() if k != 'bus'})
                    continue
                if r['kind'] in ('usb_serial', 'usb_product'):
                    continue
                if kept >= MAX_LINES:
                    self.ctx.warn(f'Only the first {MAX_LINES:,} recognised log lines were kept')
                    return
                d = self._doc('UNIX_EVENT', f'{e["path"]}|{r["line"]}', kind=r['kind'], label=r['label'], log=name, log_path=e['path'], time=r['time'],
                              host=r['host'], program=r['program'], pid=r['pid'], user=f.get('user'), ip=f.get('ip'), fields=f, text=r['text'],
                              notable=r['kind'] in ('ssh_login', 'ssh_failed', 'sudo', 'su', 'user_added', 'usb_connected', 'password_changed'))
                if r['kind'] == 'usb_connected':
                    usb[f.get('bus')] = d['fields']
                kept += 1
                self.ctx.count('unix_events')
            for d in self.docs:
                if d['type'] == 'UNIX_EVENT' and d.get('log_path') == e['path']:
                    f = d['fields']
                    what = {'ssh_login': f'{f.get("user")} from {f.get("ip")} ({f.get("method")})', 'ssh_failed': f'{f.get("user")} from {f.get("ip")}',
                            'sudo': f'{f.get("user")} as {f.get("target")}: {f.get("command")}', 'cron_run': f'{f.get("user")}: {f.get("command")}',
                            'usb_connected': f'{f.get("product") or ""} {f.get("vid")}:{f.get("pid")} serial {f.get("serial") or "?"}'.strip(),
                            'user_added': f'{f.get("user")} (UID {f.get("uid")})'}.get(d['kind'], d['text'][-200:])
                    d['summary'] = what
                    self._event(d['time'], 'UNIX_EVENT', f'{d["label"]}: {what} ({d["log"]})', user=d.get('user'))

    def _jobs(self, jobs):
        for j in jobs:
            d = self._doc('SCHEDULED_JOB', f'{j["source_path"]}|{j["name"]}', **j)
            d['notable'] = any(f['severity'] in ('high', 'medium') for f in j['flags'])
            self.ctx.count('scheduled_jobs')

    # -- macOS -----------------------------------------------------------------------------
    def _macos(self):
        ctx = self.ctx
        comp = unix.mac_computer(self._read('/Library/Preferences/SystemConfiguration/preferences.plist') or b'',
                                 self._read('/System/Library/CoreServices/SystemVersion.plist') or b'')
        self._doc('COMPUTER_INFO', 'computer', time_zone=self.zone, interfaces=[], last_shutdown=None, **comp)
        users = []
        for e in self._files(r'^/private/var/db/dslocal/nodes/Default/users/[^/]+\.plist$'):
            u = unix.mac_user(self._read_handle(e['inode']) or b'')
            if u and u['uid'] >= 500 and not (u['username'] or '').startswith('_'):
                users.append(u)
        admins = set()
        group = unix.plist(self._read('/private/var/db/dslocal/nodes/Default/groups/admin.plist') or b'')
        for name in group.get('users') or []:
            admins.add(name)
        for u in users:
            u['admin'] = u['username'] in admins
            self._doc('USER_ACCOUNT', u['username'], **u)
        ctx.count('user_accounts', len(users))
        self._history(r'^/(?:Users/[^/]+|private/var/root)/(\.(bash|zsh)_history|\.zsh_sessions/[^/]+\.history)$')
        jobs = []
        for e in self._files(r'^/(?:Library|System/Library|Users/[^/]+/Library)/Launch(Agents|Daemons)/[^/]+\.plist$'):
            if e['path'].startswith('/System/'):
                continue  # Apple's own
            j = unix.launchd(self._read_handle(e['inode']) or b'', e['path'])
            if j:
                jobs.append(j)
        self._jobs(jobs)
        # Safari.
        rows = []
        for e in self._files(r'^/Users/[^/]+/Library/Safari/History\.db$'):
            local = self._local(e)
            if not local:
                continue
            latest = {}
            for v in unix.safari_history(local):
                cur = latest.get(v['url'])
                if not cur or (v['time'] and v['time'] > cur['time']):
                    latest[v['url']] = v
            for url, v in latest.items():
                rows.append(self._doc('BROWSER_HISTORY', f'{e["path"]}|{url}', browser='Safari', url=url, title=v['title'],
                                      last_visit_time=v['time'].isoformat() if v['time'] else None, visit_count=v['visit_count'],
                                      source_path=e['path'], source_file=e['path']))
        for e in self._files(r'^/Users/[^/]+/Library/Safari/Downloads\.plist$'):
            for i, d in enumerate(unix.safari_downloads(self._read_handle(e['inode']) or b'')):
                rows.append(self._doc('BROWSER_DOWNLOAD', f'{e["path"]}|{i}', browser='Safari', url=d['url'], target_path=d['target_path'],
                                      start_time=d['start_time'].isoformat() if d['start_time'] else None,
                                      end_time=d['end_time'].isoformat() if d['end_time'] else None, total_bytes=d['total_bytes'],
                                      state='COMPLETE' if d['end_time'] else None, source_path=e['path'], source_file=e['path']))
        for r in rows:
            r['source'] = 'SAFARI'
        self.events += [dict(ev, volume_id=self.vid) for ev in browser_events(rows)]
        ctx.count('browser_history', sum(r['type'] == 'BROWSER_HISTORY' for r in rows))
        ctx.count('browser_downloads', sum(r['type'] == 'BROWSER_DOWNLOAD' for r in rows))
        # Downloads LaunchServices quarantined (any program), and Wi-Fi networks.
        for e in self._files(r'^/Users/[^/]+/Library/Preferences/com\.apple\.LaunchServices\.QuarantineEventsV2$'):
            local = self._local(e)
            if not local:
                continue
            user = self._user_of(e['path'])
            try:
                events = unix.quarantine(local)
            except Exception as exc:
                ctx.warn(f'{e["path"]}: {exc}')
                continue
            for q in events:
                self._doc('QUARANTINE_EVENT', q['event_id'] or f'{q["time"]}|{q["url"]}', user=user, source_path=e['path'], **q)
                self._event(q['time'], 'QUARANTINE_EVENT', f'{q["agent"] or "A program"} downloaded {q["url"]}'
                            + (f' (from {q["origin_url"]})' if q.get('origin_url') else ''), user=user, url=q['url'])
            ctx.count('quarantine_events', len(events))
        for path, legacy in (('/Library/Preferences/com.apple.wifi.known-networks.plist', False),
                             ('/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist', True)):
            data = self._read(path)
            if not data:
                continue
            for n in unix.wifi_networks(data, legacy):
                self._doc('WIFI_NETWORK', n['ssid'], source_path=path, **n)
                self._event(n['last_joined'], 'WIFI_NETWORK', f'Joined Wi-Fi network {n["ssid"]}', ssid=n['ssid'])
                ctx.count('wifi_networks')
