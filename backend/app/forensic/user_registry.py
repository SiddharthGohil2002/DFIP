"""What the registry says the users did and what runs on the computer.

Per user (NTUSER.DAT and UsrClass.dat): programs run from Explorer (UserAssist), folders browsed (ShellBags),
Explorer searches (WordWheelQuery), paths and addresses typed (TypedPaths, TypedURLs), recently opened files
(RecentDocs), Run dialog commands (RunMRU), autostart entries, remote desktop connections and network drives.
For the computer: program execution traces (Amcache, ShimCache, BAM), installed programs, and persistence
(Run and RunOnce keys, services, Image File Execution Options debuggers, Winlogon). regipy plugins are used where
they exist; RecentDocs, RunMRU and the SOFTWARE autostart keys are read here. Every parser returns plain dicts and
never guesses: a missing key gives no rows.
"""
from __future__ import annotations
import logging
import re
import struct
from datetime import datetime, timezone

from .registry import open_hive, values

logging.getLogger('regipy').setLevel(logging.ERROR)  # plugins log every key they look for and do not find

# Windows known folders that UserAssist names (and others) start with; %USERPROFILE% is the hive owner's profile.
KNOWN_FOLDERS = {
    '{374DE290-123F-4565-9164-39C4925E467B}': '%USERPROFILE%\\Downloads',
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}': '%USERPROFILE%\\Desktop',
    '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}': '%USERPROFILE%\\Documents',
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}': '%USERPROFILE%',
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}': 'C:\\Windows\\System32',
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}': 'C:\\Windows\\SysWOW64',
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}': 'C:\\Windows',
    '{6D809377-6AF0-444B-8957-A3773F02200E}': 'C:\\Program Files',
    '{905E63B6-C1BF-494E-B29C-65B732D3D21A}': 'C:\\Program Files',
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}': 'C:\\Program Files (x86)',
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}': 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs',
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}': '%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs',
    '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}': '%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned',
    '%SYSTEM32%': 'C:\\Windows\\System32',
    '%WINDIR%': 'C:\\Windows',
    '%PROGRAMFILES%': 'C:\\Program Files',
}
EXPLORER = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer'
SOFTWARE_AUTOSTART = [  # (key, kind)
    ('\\Microsoft\\Windows\\CurrentVersion\\Run', 'Run'),
    ('\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'RunOnce'),
    ('\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', 'Run (32-bit)'),
    ('\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'RunOnce (32-bit)'),
    ('\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run', 'Policies Run'),
]
WINLOGON_DEFAULTS = {'shell': 'explorer.exe', 'userinit': 'c:\\windows\\system32\\userinit.exe,'}
START_TYPES = {0: 'Boot', 1: 'System', 2: 'Automatic', 3: 'Manual', 4: 'Disabled'}
_USER_PLACES = re.compile(r'\\(users|documents and settings)\\[^\\]+\\|\\programdata\\|\\temp\\|\\\$recycle\.bin\\|\\appdata\\', re.I)
_ENCODED = re.compile(r'(^|\s)-e(nc(odedcommand)?)?\s', re.I)


def _iso(v):
    if v is None:
        return None
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()
    return str(v)


def _utc(v):
    """A shell item's FAT date and time (which Windows records in UTC), as an ISO time with its zone."""
    if not v:
        return None
    try:
        dt = v if isinstance(v, datetime) else datetime.fromisoformat(str(v))
    except ValueError:
        return str(v)
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def plugin(hive_path, name: str):
    """Entries of one regipy plugin on a hive, or [] when the plugin found nothing."""
    from regipy.plugins.plugin import PLUGINS
    cls = next(p for p in PLUGINS if p.NAME == name)
    p = cls(open_hive(hive_path), as_json=True)
    p.run()
    return p.entries or []


def resolve_known_folder(name: str, profile: str | None) -> str:
    """'{374DE290-...}\\SecureDelete.exe' -> 'C:\\Users\\alice\\Downloads\\SecureDelete.exe' (known folders resolved)."""
    for prefix, path in KNOWN_FOLDERS.items():
        if name.upper().startswith(prefix.upper()):
            base = path.replace('%USERPROFILE%', profile) if profile else path
            if '%USERPROFILE%' in base:
                return name
            return base + name[len(prefix):]
    return name


def device_to_path(path: str) -> str:
    """'\\Device\\HarddiskVolume3\\Users\\...' -> '\\Users\\...' (the volume letter is not recorded with it)."""
    return re.sub(r'^\\Device\\HarddiskVolume\d+', '', path or '', flags=re.I)


def flag_command(command: str) -> list[str]:
    """Why an autostart command deserves a look (empty when nothing stands out)."""
    reasons = []
    c = (command or '').strip()
    if _USER_PLACES.search(c):
        reasons.append('runs from a user profile, ProgramData or a temporary folder')
    if 'powershell' in c.lower() and (_ENCODED.search(c + ' ') or re.search(r'-w(indowstyle)?\s+hidden|bypass', c, re.I)):
        reasons.append('PowerShell with an encoded command, a hidden window or a bypassed execution policy')
    if re.search(r'\b(mshta|rundll32|regsvr32|wscript|cscript)(\.exe)?\b', c, re.I):
        reasons.append('started through a script host or system binary often used to hide programs')
    return reasons


def _mru_order(raw) -> list[int]:
    b = raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw) if isinstance(raw, str) else b''
    order = []
    for i in range(0, len(b) - 3, 4):
        n = struct.unpack_from('<I', b, i)[0]
        if n == 0xFFFFFFFF:
            break
        order.append(n)
    return order


def _utf16_name(raw) -> str | None:
    b = raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw) if isinstance(raw, str) else None
    if not b:
        return None
    end = next((i for i in range(0, len(b) - 1, 2) if b[i:i + 2] == b'\0\0'), len(b) - len(b) % 2)
    return b[:end].decode('utf-16-le', errors='replace') or None


def _key(reg, path):
    try:
        return reg.get_key(path)
    except Exception:
        return None


def _last_write(key):
    return _iso(key.header.last_modified and _filetime(key.header.last_modified)) if key is not None else None


def _filetime(ft: int):
    from datetime import timedelta
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10) if ft else None


# ------------------------------------------------------------------ NTUSER.DAT
def userassist(path, profile):
    seen, rows = set(), []
    for e in plugin(path, 'user_assist'):
        key = (e.get('name'), e.get('timestamp'), e.get('run_counter'))
        if key in seen:  # regipy lists an entry once per UserAssist layout it checks
            continue
        if str(e.get('name') or '').startswith(('UEME_CTLCUACount', 'UEME_CTLSESSION')):
            continue  # Windows XP control values (a counter and the session), not programs
        seen.add(key)
        rows.append({'raw_name': e.get('name'), 'program': resolve_known_folder(e.get('name') or '', profile),
                     'run_count': e.get('run_counter'), 'focus_count': e.get('focus_count'),
                     'focus_time_ms': e.get('total_focus_time_ms'), 'last_run': _iso(e.get('timestamp'))})
    return rows


def typed_paths(path):
    out = plugin(path, 'typed_paths')
    if not out:
        return []
    rows = []
    for i, entry in enumerate(out.get('entries') or []):
        for name, value in entry.items():
            rows.append({'value': value, 'order': i, 'value_name': name, 'key_last_write': _iso(out.get('last_write'))})
    return rows


def typed_urls(path):
    out = plugin(path, 'typed_urls')
    if not out:
        return []
    return [{'value': v, 'order': i, 'value_name': n, 'key_last_write': _iso(out.get('last_write'))}
            for i, entry in enumerate(out.get('entries') or []) for n, v in entry.items()]


def word_wheel_query(path):
    return [{'value': e.get('name'), 'order': e.get('order'), 'value_name': str(e.get('mru_id')),
             'key_last_write': _iso(e.get('last_write'))} for e in plugin(path, 'word_wheel_query')]


def recent_docs(path):
    """RecentDocs (and its per-extension subkeys): file names in most-recent-first order."""
    reg = open_hive(path)
    root = _key(reg, f'{EXPLORER}\\RecentDocs')
    if root is None:
        return []
    rows = []
    for key, ext in [(root, None)] + [(s, s.name) for s in root.iter_subkeys()]:
        vals = values(key)
        order = _mru_order(vals.get('MRUListEx'))
        for pos, n in enumerate(order):
            name = _utf16_name(vals.get(str(n)))
            if name:
                rows.append({'value': name, 'extension': ext, 'order': pos, 'value_name': str(n),
                             'key_last_write': _last_write(key), 'key_path': f'{EXPLORER}\\RecentDocs' + (f'\\{ext}' if ext else '')})
    return rows


def run_mru(path):
    """Commands typed in the Run dialog (Win+R), most recent first."""
    reg = open_hive(path)
    key = _key(reg, f'{EXPLORER}\\RunMRU')
    if key is None:
        return []
    vals = values(key)
    order = vals.get('MRUList') or ''
    rows = []
    for pos, letter in enumerate(order):
        cmd = vals.get(letter)
        if isinstance(cmd, str):
            rows.append({'value': cmd[:-2] if cmd.endswith('\\1') else cmd, 'order': pos, 'value_name': letter,
                         'key_last_write': _last_write(key)})
    return rows


def ntuser_autostart(path):
    rows = []
    out = plugin(path, 'ntuser_persistence')
    for key_path, info in (out.items() if isinstance(out, dict) else []):
        kind = key_path.rstrip('\\').rsplit('\\', 1)[-1]
        for v in info.get('values') or []:
            rows.append({'kind': kind, 'location': key_path, 'name': v.get('name'), 'command': v.get('value'),
                         'key_last_write': _iso(info.get('timestamp'))})
    return rows


def rdp_connections(path):
    return [{'server': e.get('server'), 'username_hint': e.get('username_hint'), 'key_last_write': _iso(e.get('last_connection'))}
            for e in plugin(path, 'terminal_services_history')]


def network_drives(path):
    return [{'drive': e.get('drive_letter'), 'remote_path': e.get('network_path'), 'key_last_write': _iso(e.get('last_write'))}
            for e in plugin(path, 'network_drives_plugin')]


def user_installed_programs(path):
    return _installed(plugin(path, 'installed_programs_ntuser'), 'user')


# ------------------------------------------------------------------ UsrClass.dat (and NTUSER.DAT on Windows XP)
def shellbags(path, which: str):
    """Folders the user opened in Explorer. which: 'usrclass' or 'ntuser'."""
    name = 'usrclass_shellbag_plugin' if which == 'usrclass' else 'ntuser_shellbag_plugin'
    rows = []
    for e in plugin(path, name):
        p = re.sub(r'\\{2,}', r'\\', e.get('path') or '')
        display = re.sub(r'^(My Computer|This PC)\\', '', p)
        rows.append({'path': display, 'full_path': p, 'shell_type': e.get('shell_type'), 'value': e.get('value'),
                     'created': _utc(e.get('creation_time')), 'modified': _utc(e.get('modification_time')),
                     'accessed': _utc(e.get('access_time')), 'key_last_write': _iso(e.get('last_write')),
                     'mru_position': e.get('mru_order_location'), 'node_slot': e.get('node_slot') or None,
                     'key_path': e.get('reg_path'), 'value_name': e.get('value_name')})
    return rows


# ------------------------------------------------------------------ Amcache.hve
def amcache(path):
    rows = []
    for e in plugin(path, 'amcache'):
        p = e.get('lower_case_long_path') or e.get('full_path')
        rows.append({'path': p, 'name': e.get('name') or (p or '').rsplit('\\', 1)[-1] or None, 'sha1': e.get('sha1') or e.get('file_id'),
                     'size': e.get('size') or e.get('file_size'), 'publisher': e.get('publisher') or e.get('company_name'),
                     'version': e.get('version') or e.get('file_version'), 'product': e.get('product_name'),
                     'link_date': e.get('link_date') or _iso(e.get('linker_compile_time')),
                     'key_last_write': _iso(e.get('timestamp') or e.get('last_modified_timestamp'))})
    return rows


# ------------------------------------------------------------------ SYSTEM
def shimcache(path):
    """The current control set's AppCompatCache (regipy's plugin reads every control set, listing entries twice)."""
    from regipy.plugins.system.external.ShimCacheParser import get_shimcache_entries
    from .registry import control_sets
    reg = open_hive(path)
    sets = control_sets(reg)
    key = _key(reg, f'\\{sets[0]}\\Control\\Session Manager\\AppCompatCache') if sets else None
    if key is None:
        return []
    data = key.get_value('AppCompatCache')
    if not data:
        return []
    return [{'path': re.sub(r'^\\\?\?\\', '', e.get('path') or ''),  # without the NT namespace prefix \??\
             'last_modified': _iso(e.get('last_mod_date')), 'position': i, 'executed': e.get('exec_flag'),
             'control_set': sets[0]} for i, e in enumerate(get_shimcache_entries(data, as_json=True))]


def bam(path):
    return [{'path': device_to_path(e.get('executable')), 'device_path': e.get('executable'), 'sid': e.get('sid'),
             'last_run': _iso(e.get('timestamp'))} for e in plugin(path, 'background_activity_moderator')
            if e.get('executable') and str(e.get('executable')).startswith('\\')]


def services(path, control_set: str):
    """Services that start on their own (boot, system or automatic), with what they run."""
    reg = open_hive(path)
    root = _key(reg, f'\\{control_set}\\Services')
    if root is None:
        return []
    rows = []
    for s in root.iter_subkeys():
        vals = values(s)
        start = vals.get('Start')
        image = vals.get('ImagePath')
        if not isinstance(start, int) or start > 2 or not image:
            continue
        dll = None
        params = _key(reg, f'\\{control_set}\\Services\\{s.name}\\Parameters')
        if params is not None:
            dll = values(params).get('ServiceDll')
        rows.append({'kind': 'Service', 'location': f'\\{control_set}\\Services\\{s.name}', 'name': s.name,
                     'command': image, 'service_dll': dll, 'display_name': vals.get('DisplayName'),
                     'start_type': START_TYPES.get(start, str(start)), 'account': vals.get('ObjectName'),
                     'key_last_write': _last_write(s)})
    return rows


# ------------------------------------------------------------------ SOFTWARE
def software_autostart(path):
    reg = open_hive(path)
    rows = []
    for key_path, kind in SOFTWARE_AUTOSTART:
        key = _key(reg, key_path)
        if key is None:
            continue
        for name, value in values(key).items():
            if isinstance(value, str) and value.strip():
                rows.append({'kind': kind, 'location': key_path, 'name': name or '(default)', 'command': value,
                             'key_last_write': _last_write(key)})
    wl = _key(reg, '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
    if wl is not None:
        for name, value in values(wl).items():
            default = WINLOGON_DEFAULTS.get((name or '').lower())
            if default is not None and isinstance(value, str):
                rows.append({'kind': 'Winlogon', 'location': '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'name': name,
                             'command': value, 'key_last_write': _last_write(wl),
                             'not_default': value.strip().lower() != default})
    for e in plugin(path, 'image_file_execution_options'):
        if e.get('Debugger'):
            rows.append({'kind': 'IFEO debugger', 'location': f'\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{e.get("name")}',
                         'name': e.get('name'), 'command': e.get('Debugger'), 'key_last_write': _iso(e.get('timestamp'))})
    return rows


def _installed(entries, scope):
    rows = []
    for e in entries:
        if not e.get('DisplayName'):
            continue  # components and updates without a name are not listed as programs
        rows.append({'name': e.get('DisplayName'), 'version': e.get('DisplayVersion'), 'publisher': e.get('Publisher'),
                     'install_date': e.get('InstallDate'), 'install_location': e.get('InstallLocation'),
                     'uninstall_string': e.get('UninstallString'), 'key_name': e.get('service_name'),
                     'key_path': e.get('registry_path'), 'key_last_write': _iso(e.get('timestamp')), 'scope': scope})
    return rows


def installed_programs(path):
    return _installed(plugin(path, 'installed_programs_software'), 'computer')


def persistence_flags(row: dict) -> list[str]:
    reasons = flag_command(row.get('command') or '') + flag_command(row.get('service_dll') or '')
    if row.get('kind') == 'IFEO debugger':
        reasons.insert(0, 'a debugger set for a program runs instead of it (a common backdoor, for example on sethc.exe)')
    if row.get('not_default'):
        reasons.insert(0, 'differs from the Windows default')
    return list(dict.fromkeys(reasons))


# ------------------------------------------------------------------ transaction logs
def replay_logs(hive, log1, log2, out):
    """Applies .LOG1/.LOG2 transaction logs to a dirty hive: (path to read, note)."""
    from regipy.registry import RegistryHive
    try:
        h = RegistryHive(str(hive))
        dirty = h.header.primary_sequence_num != h.header.secondary_sequence_num
    except Exception as exc:
        return hive, f'could not check whether the hive is dirty: {exc}'
    if not dirty:
        return hive, 'clean: transaction logs not needed'
    if not log1 and not log2:
        return hive, 'dirty, and no transaction logs were found: recent changes may be missing'
    try:
        from regipy.recovery import apply_transaction_logs
        restored, applied = apply_transaction_logs(str(hive), str(log1 or log2), secondary_log_path=str(log2) if log1 and log2 else None,
                                                   restored_hive_path=str(out))
        return out, f'dirty: {applied} transaction log entries applied'
    except Exception as exc:
        return hive, f'dirty, but the transaction logs could not be applied: {exc}'
