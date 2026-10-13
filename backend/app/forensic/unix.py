"""Linux and macOS evidence: accounts, shell history, logins, logs, scheduled jobs and services, recently used files, and
macOS's Safari, download quarantine and Wi-Fi records. Each parser takes the file's bytes (or a local copy) and returns
plain records; nothing in the evidence is run or rendered.

Times: syslog lines without a year (`Sep  1 14:05:12`) are local times of the computer, read in its time zone, the
year taken from the log file's modification time (a month after it belongs to the year before); RFC 3339 lines carry
their offset. wtmp, btmp, shell history (`#1788274800`, `: 1788274800:0;`) and plists keep UTC times. Safari and
macOS store seconds since 2001-01-01 (Mac absolute time).
"""
from __future__ import annotations
import gzip
import plistlib
import re
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defusedxml import ElementTree as ET

from .timezone import local_to_utc

MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
UTC = timezone.utc
MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}


def _utc(ts) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(ts), UTC) if ts and int(ts) > 0 else None
    except (ValueError, OverflowError, OSError):
        return None


def mac_time(v) -> datetime | None:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    try:
        return MAC_EPOCH + timedelta(seconds=float(v)) if v else None
    except (TypeError, ValueError, OverflowError):
        return None


def text(data: bytes, name: str = '') -> str:
    if name.endswith('.gz') or data[:2] == b'\x1f\x8b':
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            return ''
    return data.decode('utf-8', errors='replace')


# ------------------------------------------------------------------------------------------------ system
def os_release(data: bytes) -> dict:
    out = {}
    for line in text(data).splitlines():
        m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"\'')
    return out


def tzif_posix(data: bytes) -> str | None:
    """The POSIX TZ string a TZif (v2+) file ends with, such as EST5EDT,M3.2.0,M11.1.0."""
    if not data.startswith(b'TZif') or data[4:5] not in (b'2', b'3', b'4'):
        return None
    lines = data.rstrip(b'\n').rsplit(b'\n', 1)
    footer = lines[-1].decode('ascii', errors='replace').strip() if len(lines) == 2 else ''
    return footer or None


def zone_from_link(target: str) -> str | None:
    m = re.search(r'zoneinfo/(.+)$', target or '')
    return m.group(1) if m else None


# ------------------------------------------------------------------------------------------------ accounts
def passwd(data: bytes, group: bytes = b'', shadow: bytes = b'') -> list[dict]:
    groups, admins = {}, set()
    for line in text(group).splitlines():
        f = line.split(':')
        if len(f) >= 4:
            for member in filter(None, f[3].split(',')):
                groups.setdefault(member, []).append(f[0])
                if f[0] in ('sudo', 'wheel', 'admin'):
                    admins.add(member)
    shadows = {}
    for line in text(shadow).splitlines():
        f = line.split(':')
        if len(f) >= 3:
            state = 'locked' if f[1].startswith(('!', '*')) else 'none' if f[1] == '' else 'set'
            changed = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(days=int(f[2])) if f[2].isdigit() else None
            shadows[f[0]] = {'password_state': state, 'password_last_set': changed}  # never the hash
    out = []
    for line in text(data).splitlines():
        f = line.split(':')
        if len(f) < 7 or not f[2].lstrip('-').isdigit():
            continue
        name, uid, gid = f[0], int(f[2]), int(f[3]) if f[3].isdigit() else None
        flags = []
        if uid == 0 and name != 'root':
            flags.append({'code': 'UID0', 'severity': 'high', 'label': 'A second account with user ID 0 (full root rights)'})
        if 0 < uid < 1000 and f[6].rsplit('/', 1)[-1] in ('bash', 'sh', 'zsh', 'dash') and name not in ('sync',):
            flags.append({'code': 'SYSTEM_SHELL', 'severity': 'medium', 'label': 'A system account that can log in with a shell'})
        out.append({'username': name, 'uid': uid, 'gid': gid, 'full_name': f[4].split(',')[0] or None, 'profile_path': f[5], 'shell': f[6],
                    'groups': sorted(groups.get(name, [])), 'admin': name in admins or uid == 0, 'flags': flags,
                    **shadows.get(name, {}), 'source': 'passwd'})
    return out


def mac_user(data: bytes) -> dict | None:
    """A macOS local account from /private/var/db/dslocal/nodes/Default/users/<name>.plist."""
    try:
        p = plistlib.loads(data)
    except Exception:
        return None
    first = lambda k: (p.get(k) or [None])[0] if isinstance(p.get(k), list) else p.get(k)
    uid = first('uid')
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return None
    return {'username': first('name'), 'uid': uid, 'gid': int(first('gid') or 0), 'full_name': first('realname'), 'profile_path': first('home'),
            'shell': first('shell'), 'uuid': first('generateduid'), 'groups': [], 'admin': False, 'flags': [], 'source': 'macOS directory'}


# ------------------------------------------------------------------------------------------------ shell history
EXFIL = re.compile(r'\b(scp|rsync|sftp|ftp|curl\s+[^|;]*(-T|--upload-file|-F|--data-binary|-d\s*@)|wget\s+[^|;]*--post-file|nc\s|ncat\s|rclone|aws\s+s3\s+cp|gsutil\s+cp)\b')
ANTI = re.compile(r'(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|shred\b|\bwipe\b|srm\b|rm\s+[^;|]*(\.(bash|zsh)_history|\.zsh_sessions)'
                  r'|>\s*~?/?\S*_history|truncate\s+-s\s*0)')
PRIV = re.compile(r'(useradd\s+[^;|]*-o\b|useradd\s+[^;|]*-u\s*0\b|usermod\s+[^;|]*-u\s*0\b|chmod\s+[^;|]*[ugo]?\+s\b|chmod\s+[0-7]?[4-7][0-7]{3}\b|visudo|/etc/sudoers)')
PERSIST = re.compile(r'(crontab\s+(-e|-u\s+\S+\s+-e|[^-\s])|systemctl\s+enable|launchctl\s+load|authorized_keys|/etc/rc\.local|LaunchAgents|LaunchDaemons)')


def command_flags(cmd: str) -> list[dict]:
    flags = []
    for code, rx, label, sev in (('EXFIL', EXFIL, 'Copies data to another computer', 'high'),
                                 ('ANTI_FORENSICS', ANTI, 'Erases history or wipes files', 'high'),
                                 ('PRIVILEGE', PRIV, 'Changes accounts or privileges', 'high'),
                                 ('PERSISTENCE', PERSIST, 'Sets up something that runs again', 'medium')):
        if rx.search(cmd):
            flags.append({'code': code, 'severity': sev, 'label': label})
    return flags


def shell_history(data: bytes, shell: str) -> list[dict]:
    """bash (with #<epoch> lines when HISTTIMEFORMAT was set) or zsh (extended `: <epoch>:<seconds>;command`) history."""
    out, when = [], None
    lines = text(data).splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if shell == 'bash' and re.fullmatch(r'#\d{9,11}', line.strip()):
            when = _utc(line.strip()[1:])
            continue
        m = re.match(r'^: (\d{9,11}):(\d+);(.*)$', line) if shell == 'zsh' else None
        cmd, t = (m.group(3), _utc(m.group(1))) if m else (line, when)
        while shell == 'zsh' and cmd.endswith('\\') and i < len(lines):  # a command over several lines
            cmd = cmd[:-1] + '\n' + lines[i]
            i += 1
        when = None
        if not cmd.strip():
            continue
        out.append({'order': len(out) + 1, 'command': cmd[:4000], 'time': t, 'flags': command_flags(cmd)})
    return out


# ------------------------------------------------------------------------------------------------ logs
_SYSLOG = re.compile(r'^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<t>\d\d:\d\d:\d\d) (?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$')
_RFC3339 = re.compile(r'^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$')
AUTH_RULES = [
    ('ssh_login', 'Logged in over SSH', re.compile(r'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')),
    ('ssh_failed', 'Failed SSH login', re.compile(r'Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')),
    ('ssh_invalid_user', 'SSH login for an unknown user', re.compile(r'Invalid user (?P<user>\S*) from (?P<ip>\S+)')),
    ('sudo', 'Ran a command as another user (sudo)', re.compile(r'^\s*(?P<user>\S+) : (?:.*?; )?TTY=\S+ ; PWD=(?P<pwd>.*?) ; USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$')),
    ('sudo_failed', 'sudo refused', re.compile(r'^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers)')),
    ('su', 'Switched user (su)', re.compile(r'(?:Successful su for (?P<target>\S+) by (?P<user>\S+)'
                                            r'|pam_unix\(su(?:-l)?:session\): session opened for user (?P<target2>[^\s(]+)(?:\(uid=\d+\))? by (?P<user2>[^\s(]*))')),
    ('user_added', 'Account created', re.compile(r'new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)')),
    ('group_added', 'Group created', re.compile(r'new group: name=(?P<group>[^,]+)')),
    ('user_changed', 'Account changed', re.compile(r'(?:change user|add|delete) \'?(?P<user>[^\' ]+)\'? (?:to|from) group \'?(?P<group>[^\' ]+)')),
    ('password_changed', 'Password changed', re.compile(r'password changed for (?P<user>\S+)')),
]
SYSLOG_RULES = [
    ('cron_run', 'Scheduled job ran (cron)', re.compile(r'^\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)$')),
    # Kernel lines carry the bus address (usb 1-1) the device's later lines repeat; a [ uptime ] may come first.
    ('usb_connected', 'USB device connected', re.compile(r'usb (?P<bus>[\d.-]+): New USB device found, idVendor=(?P<vid>[0-9a-f]{4}), idProduct=(?P<pid>[0-9a-f]{4})')),
    ('usb_serial', 'USB device serial number', re.compile(r'usb (?P<bus>[\d.-]+): SerialNumber: (?P<serial>\S+)')),
    ('usb_product', 'USB device name', re.compile(r'usb (?P<bus>[\d.-]+): Product: (?P<product>.+)$')),
    ('service_started', 'Service started', re.compile(r'^Started (?P<service>.+?)\.?$')),
    ('shutdown', 'System shutting down', re.compile(r'(?:System is (?:powering down|rebooting)|Reached target (?:System )?(?:Power-Off|Shutdown|Reboot))')),
]


def log_lines(data: bytes, name: str, zone: str | None, mtime: datetime | None) -> list[dict]:
    """Recognised auth.log, secure, syslog and messages lines: {time, host, program, pid, kind, label, fields, line, text}."""
    rules = AUTH_RULES if re.search(r'(auth|secure)', name) else SYSLOG_RULES
    year_ref = mtime or datetime.now(UTC)
    out = []
    for n, line in enumerate(text(data, name).splitlines(), 1):
        m = _RFC3339.match(line)
        if m:
            try:
                when = datetime.fromisoformat(m.group('ts').replace('Z', '+00:00')).astimezone(UTC)
            except ValueError:
                continue
        else:
            m = _SYSLOG.match(line)
            if not m:
                continue
            mon, day = MONTHS.get(m.group('mon')), int(m.group('day'))
            if not mon:
                continue
            year = year_ref.year - (1 if mon > year_ref.month else 0)
            try:
                local = datetime.strptime(f'{year}-{mon:02d}-{day:02d} {m.group("t")}', '%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
            when = local_to_utc(local, zone) if zone else local.replace(tzinfo=UTC)
        msg = m.group('msg')
        for kind, label, rx in rules:
            hit = rx.search(msg)
            if hit:
                fields = {k.rstrip('2'): v for k, v in hit.groupdict().items() if v}
                out.append({'time': when, 'host': m.group('host'), 'program': m.group('prog'), 'pid': m.group('pid'), 'kind': kind,
                            'label': label, 'fields': fields, 'line': n, 'text': line[:1000]})
                break
    return out


UTMP_TYPES = {1: 'RUN_LVL', 2: 'BOOT_TIME', 5: 'INIT_PROCESS', 6: 'LOGIN_PROCESS', 7: 'USER_PROCESS', 8: 'DEAD_PROCESS'}
UTMP_SIZE = 384


def utmp(data: bytes, failed: bool = False) -> list[dict]:
    """wtmp (logins, logouts, boots, shutdowns) or btmp (failed logins) records, Linux x86-64 layout."""
    out = []
    for off in range(0, len(data) - UTMP_SIZE + 1, UTMP_SIZE):
        rec = data[off:off + UTMP_SIZE]
        typ, pid = struct.unpack_from('<hxxi', rec, 0)
        line = rec[8:40].split(b'\0', 1)[0].decode(errors='replace')
        user = rec[44:76].split(b'\0', 1)[0].decode(errors='replace')
        host = rec[76:332].split(b'\0', 1)[0].decode(errors='replace')
        sec, usec = struct.unpack_from('<ii', rec, 340)
        when = _utc(sec)
        if when is None:
            continue
        when += timedelta(microseconds=max(0, usec))
        if failed:
            kind = 'failed_login'
        elif typ == 7:
            kind = 'login'
        elif typ == 8:
            kind = 'logout'
        elif typ == 2:
            kind = 'boot'
        elif typ == 1 and user == 'shutdown':
            kind = 'shutdown'
        else:
            continue
        out.append({'time': when, 'kind': kind, 'user': user or None, 'terminal': line or None, 'host': host or None, 'pid': pid,
                    'utmp_type': UTMP_TYPES.get(typ, typ), 'record': off // UTMP_SIZE})
    # A logout record closes the session opened on the same terminal.
    open_by_line = {}
    for r in out:
        if r['kind'] == 'login':
            open_by_line[r['terminal']] = r
        elif r['kind'] == 'logout' and r['terminal'] in open_by_line:
            start = open_by_line.pop(r['terminal'])
            start['logout'] = r['time']
            start['duration_seconds'] = int((r['time'] - start['time']).total_seconds())
            r['user'] = r['user'] or start['user']
    return out


# ------------------------------------------------------------------------------------------------ scheduled jobs
SUSPICIOUS_PATH = re.compile(r'(^|[\s\'"=])(/tmp/|/var/tmp/|/dev/shm/|/Users/Shared/|/private/tmp/)|/\.[^/\s]+/|(curl|wget)[^|;]*\|\s*(ba|z)?sh|base64\s+(-d|--decode)|\bnc\s+-e|/dev/tcp/|python[0-9.]*\s+-c|bash\s+-i')


def job_flags(command: str, path: str = '') -> list[dict]:
    flags = []
    if SUSPICIOUS_PATH.search(command or ''):
        flags.append({'code': 'SUSPICIOUS_COMMAND', 'severity': 'high',
                      'label': 'Runs from a temporary or hidden folder, or downloads and runs code'})
    if re.search(r'/(home|Users)/[^/]+/', command or '') and not path.startswith(('/home/', '/Users/')):
        flags.append({'code': 'USER_FOLDER', 'severity': 'medium', 'label': "A system-wide job runs a program from a user's folder"})
    return flags


def crontab(data: bytes, path: str, user: str | None = None) -> list[dict]:
    """Jobs of /etc/crontab and /etc/cron.d (with a user column) or a user's crontab."""
    system = user is None
    out = []
    for n, line in enumerate(text(data).splitlines(), 1):
        s = line.strip()
        if not s or s.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', s):
            continue
        parts = s.split()
        if parts[0].startswith('@'):
            schedule, rest = parts[0], parts[1:]
        else:
            schedule, rest = ' '.join(parts[:5]), parts[5:]
        if system and rest:
            who, rest = rest[0], rest[1:]
        else:
            who = user
        command = ' '.join(rest)
        if not command:
            continue
        out.append({'mechanism': 'cron', 'name': f'{Path(path).name}:{n}', 'schedule': schedule, 'user': who, 'command': command,
                    'source_path': path, 'flags': job_flags(command, path)})
    return out


def systemd_unit(data: bytes, path: str, enabled: bool) -> dict | None:
    sections, cur = {}, None
    for line in text(data).splitlines():
        s = line.strip()
        if not s or s.startswith(('#', ';')):
            continue
        if s.startswith('[') and s.endswith(']'):
            cur = sections.setdefault(s[1:-1], {})
        elif cur is not None and '=' in s:
            k, v = s.split('=', 1)
            cur.setdefault(k.strip(), v.strip())
    svc = sections.get('Service') or {}
    command = svc.get('ExecStart')
    if not command:
        return None
    return {'mechanism': 'systemd', 'name': Path(path).name, 'description': (sections.get('Unit') or {}).get('Description'), 'command': command,
            'user': svc.get('User') or 'root', 'schedule': 'at boot' if enabled else 'when started', 'enabled': enabled, 'source_path': path,
            'flags': job_flags(command, path)}


def launchd(data: bytes, path: str) -> dict | None:
    try:
        p = plistlib.loads(data)
    except Exception:
        return None
    if not isinstance(p, dict):
        return None
    args = p.get('ProgramArguments') or ([p['Program']] if p.get('Program') else [])
    command = ' '.join(str(a) for a in args)
    when = 'at load' if p.get('RunAtLoad') else f'every {p["StartInterval"]} s' if p.get('StartInterval') else \
        'on a calendar' if p.get('StartCalendarInterval') else 'when started'
    return {'mechanism': 'launchd', 'name': p.get('Label') or Path(path).stem, 'command': command, 'user': p.get('UserName'),
            'schedule': when, 'keep_alive': bool(p.get('KeepAlive')), 'enabled': not p.get('Disabled', False), 'source_path': path,
            'flags': job_flags(command, path)}


# ------------------------------------------------------------------------------------------------ recent files
def recently_used(data: bytes) -> list[dict]:
    """GNOME/GTK recently-used.xbel: files opened, with when and by which program (defusedxml: no entities)."""
    root = ET.fromstring(data)
    out = []
    for b in root.iter('bookmark'):
        href = b.get('href') or ''
        apps = []
        for app in b.iter():
            if app.tag.endswith('application'):
                apps.append({'name': app.get('name'), 'exec': app.get('exec'), 'count': int(app.get('count') or 0),
                             'modified': _iso_time(app.get('modified'))})
        mime = next((x.get('type') for x in b.iter() if x.tag.endswith('mime-type')), None)
        from urllib.parse import unquote, urlparse
        u = urlparse(href)
        out.append({'href': href, 'path': unquote(u.path) if u.scheme == 'file' else href, 'mime': mime, 'added': _iso_time(b.get('added')),
                    'modified': _iso_time(b.get('modified')), 'visited': _iso_time(b.get('visited')), 'applications': apps})
    return out


def _iso_time(v):
    try:
        return datetime.fromisoformat(v.replace('Z', '+00:00')).astimezone(UTC) if v else None
    except ValueError:
        return None


# ------------------------------------------------------------------------------------------------ macOS
def plist(data: bytes) -> dict:
    try:
        p = plistlib.loads(data)
        return p if isinstance(p, dict) else {}
    except Exception:
        return {}


def mac_computer(prefs: bytes, version: bytes) -> dict:
    p, v = plist(prefs), plist(version)
    system = ((p.get('System') or {}).get('System') or {})
    hostnames = ((p.get('System') or {}).get('Network') or {}).get('HostNames') or {}
    return {'computer_name': system.get('ComputerName'), 'hostname': system.get('HostName') or hostnames.get('LocalHostName'),
            'os': {'product_name': f'{v.get("ProductName") or "macOS"} {v.get("ProductVersion") or ""}'.strip(),
                   'version': v.get('ProductVersion'), 'build': v.get('ProductBuildVersion')}}


def safari_history(db: Path) -> list[dict]:
    con = sqlite3.connect(f'file:{db}?mode=ro&immutable=1', uri=True)
    try:
        rows = con.execute('SELECT i.url, v.title, v.visit_time, i.visit_count FROM history_visits v JOIN history_items i ON i.id = v.history_item '
                           'ORDER BY v.visit_time').fetchall()
    finally:
        con.close()
    return [{'url': u, 'title': t, 'time': mac_time(vt), 'visit_count': c} for u, t, vt, c in rows]


def safari_downloads(data: bytes) -> list[dict]:
    out = []
    for d in plist(data).get('DownloadHistory') or []:
        out.append({'url': d.get('DownloadEntryURL'), 'target_path': d.get('DownloadEntryPath'),
                    'start_time': mac_time(d.get('DownloadEntryDateAddedKey')), 'end_time': mac_time(d.get('DownloadEntryDateFinishedKey')),
                    'total_bytes': d.get('DownloadEntryProgressTotalToLoad'), 'removed': bool(d.get('DownloadEntryRemoveWhenDoneKey'))})
    return out


def quarantine(db: Path) -> list[dict]:
    """com.apple.LaunchServices.QuarantineEventsV2: what was downloaded, by which program, from where."""
    con = sqlite3.connect(f'file:{db}?mode=ro&immutable=1', uri=True)
    try:
        rows = con.execute('SELECT LSQuarantineEventIdentifier, LSQuarantineTimeStamp, LSQuarantineAgentBundleIdentifier, LSQuarantineAgentName, '
                           'LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName, LSQuarantineSenderAddress '
                           'FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp').fetchall()
    finally:
        con.close()
    return [{'event_id': r[0], 'time': mac_time(r[1]), 'agent_bundle': r[2], 'agent': r[3], 'url': r[4], 'origin_url': r[5],
             'sender': r[6] or r[7], 'sender_address': r[7]} for r in rows]


def wifi_networks(data: bytes, legacy: bool = False) -> list[dict]:
    p = plist(data)
    out = []
    if legacy:
        for key, n in (p.get('KnownNetworks') or {}).items():
            out.append({'ssid': n.get('SSIDString') or key, 'security': n.get('SecurityType'), 'added': mac_time(n.get('AddedAt')),
                        'last_joined': mac_time(n.get('LastConnected')), 'auto_join': not n.get('AutoJoinDisabled', False)})
        return out
    for key, n in p.items():
        if not isinstance(n, dict):
            continue
        ssid = n.get('SSID')
        ssid = ssid.decode('utf-8', errors='replace') if isinstance(ssid, bytes) else ssid or key.replace('wifi.network.ssid.', '')
        joined = [t for t in (mac_time(n.get('JoinedByUserAt')), mac_time(n.get('JoinedBySystemAt'))) if t]
        out.append({'ssid': ssid, 'security': n.get('SupportedSecurityTypes'), 'added': mac_time(n.get('AddedAt')),
                    'last_joined': max(joined) if joined else None, 'auto_join': not n.get('AutoJoinDisabled', False),
                    'hidden': bool(n.get('Hidden'))})
    return out
