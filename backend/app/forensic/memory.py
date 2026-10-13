"""Memory images read with Volatility 3: the plugins DFIP runs, their output (the JSON renderer: rows with `__children`)
turned into records, and what stands out (processes named or placed like system programs that are not, the wrong
parent, code injected into a process, encoded PowerShell, programs and services in user folders, network
connections of programs that rarely make any).

Volatility runs as a separate process (modules/memory.py); nothing here runs anything found in the image.
"""
from __future__ import annotations
import base64
import ipaddress
import re
from datetime import datetime, timezone

# The plugins DFIP runs, in this order.
PLUGINS = {
    'info': 'windows.info',
    'pstree': 'windows.pstree',
    'cmdline': 'windows.cmdline',
    'netscan': 'windows.netscan',
    'malfind': 'windows.malware.malfind',
    'svcscan': 'windows.svcscan',
    'dlllist': 'windows.dlllist',
}
MAX_DLL_PIDS = 25           # dlllist only for the processes that stand out (most first)
MAX_DLLS = 20_000
HEXDUMP_BYTES = 64
DISASM_LINES = 12

SYSTEM_PATHS = {  # name: the folders it runs from (lower case, without the drive)
    'smss.exe': ('\\windows\\system32\\',), 'csrss.exe': ('\\windows\\system32\\',), 'wininit.exe': ('\\windows\\system32\\',),
    'winlogon.exe': ('\\windows\\system32\\',), 'services.exe': ('\\windows\\system32\\',), 'lsass.exe': ('\\windows\\system32\\',),
    'lsaiso.exe': ('\\windows\\system32\\',), 'svchost.exe': ('\\windows\\system32\\', '\\windows\\syswow64\\'),
    'spoolsv.exe': ('\\windows\\system32\\',), 'taskhostw.exe': ('\\windows\\system32\\',), 'dllhost.exe': ('\\windows\\system32\\', '\\windows\\syswow64\\'),
    'conhost.exe': ('\\windows\\system32\\',), 'rundll32.exe': ('\\windows\\system32\\', '\\windows\\syswow64\\'),
    'explorer.exe': ('\\windows\\',), 'searchindexer.exe': ('\\windows\\system32\\',), 'wmiprvse.exe': ('\\windows\\system32\\wbem\\', '\\windows\\syswow64\\wbem\\'),
    'sihost.exe': ('\\windows\\system32\\',), 'fontdrvhost.exe': ('\\windows\\system32\\',), 'dwm.exe': ('\\windows\\system32\\',),
    'ctfmon.exe': ('\\windows\\system32\\',), 'runtimebroker.exe': ('\\windows\\system32\\',), 'cmd.exe': ('\\windows\\system32\\', '\\windows\\syswow64\\'),
    'powershell.exe': ('\\windows\\system32\\windowspowershell\\', '\\windows\\syswow64\\windowspowershell\\'),
}
EXPECTED_PARENTS = {'svchost.exe': ('services.exe',), 'services.exe': ('wininit.exe',), 'lsass.exe': ('wininit.exe',),
                    'lsaiso.exe': ('wininit.exe',), 'wininit.exe': ('smss.exe',), 'spoolsv.exe': ('services.exe',)}
SINGLE_INSTANCE = ('lsass.exe', 'services.exe', 'wininit.exe', 'lsaiso.exe')
SHELLS = ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'bitsadmin.exe',
          'certutil.exe')
DOCUMENT_APPS = ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'onenote.exe', 'acrord32.exe', 'acrobat.exe')
QUIET_PROGRAMS = ('notepad.exe', 'calc.exe', 'mspaint.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'cmd.exe', 'powershell.exe', 'wscript.exe',
                  'cscript.exe', 'dllhost.exe')
# Windows programs whose names are one letter from another's (Windows 7's task host, for one).
KNOWN_NAMES = ('taskhost.exe', 'taskeng.exe', 'lsm.exe', 'wlms.exe', 'msmpeng.exe', 'nissrv.exe', 'sppsvc.exe')
# Temporary and download folders, the desktop, shared and recycled folders, and a program straight in AppData or ProgramData
# (installed programs live in a folder of their own there, as OneDrive, Teams or Defender do).
USER_FOLDERS = re.compile(r'\\(windows\\temp|temp|tmp|downloads|desktop|users\\public|\$recycle\.bin|perflogs)\\'
                          r'|\\appdata\\(local|roaming)\\[^\\]+$|\\programdata\\[^\\]+$', re.I)
ENCODED = re.compile(r'(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{16,})', re.I)
SEVERITY_SCORE = {'high': 3, 'medium': 2, 'low': 1}


# --------------------------------------------------------------------------------------------- Volatility output
def rows(data, depth: int = 0, parent: dict | None = None):
    """Every row of a plugin's JSON output, with its depth and parent row (pstree nests children)."""
    for r in data or []:
        yield r, depth, parent
        yield from rows(r.get('__children'), depth + 1, r)


def _time(v) -> datetime | None:
    if not v or not isinstance(v, str):
        return None
    try:
        t = datetime.fromisoformat(v.replace('Z', '+00:00'))
    except ValueError:
        return None
    if t.year < 1970:  # 1601-01-01: an unset Windows time
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _int(v) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None


def _addr(v) -> str | None:
    """An address as hex text (kernel addresses do not fit a signed 64-bit integer)."""
    n = _int(v)
    return f'{n:#x}' if n is not None else None


def _text(v) -> str | None:
    return v.strip() if isinstance(v, str) and v.strip() and v.strip() != 'N/A' else None


def windows_name(major, minor, build, server: bool) -> str | None:
    """The Windows release a kernel version belongs to."""
    if major is None:
        return None
    if (major, minor) == (10, 0):
        if server:
            return 'Windows Server 2025' if (build or 0) >= 26100 else 'Windows Server 2022' if (build or 0) >= 20348 else \
                'Windows Server 2019' if (build or 0) >= 17763 else 'Windows Server 2016'
        return 'Windows 11' if (build or 0) >= 22000 else 'Windows 10'
    names = {(6, 3): ('Windows 8.1', 'Windows Server 2012 R2'), (6, 2): ('Windows 8', 'Windows Server 2012'),
             (6, 1): ('Windows 7', 'Windows Server 2008 R2'), (6, 0): ('Windows Vista', 'Windows Server 2008'),
             (5, 2): ('Windows XP x64', 'Windows Server 2003'), (5, 1): ('Windows XP', 'Windows XP')}
    pair = names.get((major, minor))
    return pair[1 if server else 0] if pair else f'Windows NT {major}.{minor}'


def info(data) -> dict:
    """windows.info: the kernel, the Windows version and build, the processors and the time the memory was captured."""
    v = {r.get('Variable'): r.get('Value') for r, _, _ in rows(data)}
    major, minor = _int(v.get('NtMajorVersion')), _int(v.get('NtMinorVersion'))
    mm = str(v.get('Major/Minor') or '')
    build = _int(mm.split('.', 1)[1]) if '.' in mm else None
    product = str(v.get('NtProductType') or '')
    server = product in ('NtProductServer', 'NtProductLanManNt')
    is64 = str(v.get('Is64Bit')).lower() == 'true'
    captured = v.get('SystemTime')
    t = None
    if isinstance(captured, str):
        try:
            t = datetime.fromisoformat(captured.strip())
            t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
        except ValueError:
            t = None
    return {'os': 'Windows', 'windows': windows_name(major, minor, build, server), 'version': f'{major}.{minor}' if major is not None else None,
            'build': build, 'product_type': product or None, 'server': server, 'architecture': 'x64' if is64 else 'x86',
            'pae': str(v.get('IsPAE')).lower() == 'true', 'processors': _int(v.get('KeNumberProcessors')), 'system_time': t,
            'system_root': _text(v.get('NtSystemRoot')), 'kernel_base': _addr(v.get('Kernel Base')), 'dtb': _addr(v.get('DTB')),
            'symbols': _text(v.get('Symbols')), 'layer': _text(v.get('memory_layer')), 'variables': {str(k): str(x)[:300] for k, x in v.items() if k}}


def processes(pstree, cmdline=None) -> list[dict]:
    """windows.pstree (with windows.cmdline where pstree had no command line): one record per process."""
    args = {r.get('PID'): _text(r.get('Args')) for r, _, _ in rows(cmdline)}
    out = []
    for r, depth, parent in rows(pstree):
        pid = _int(r.get('PID'))
        name = _text(r.get('ImageFileName')) or ''
        cmd = _text(r.get('Cmd')) or args.get(pid)
        out.append({'pid': pid, 'ppid': _int(r.get('PPID')), 'name': name, 'offset': _addr(r.get('Offset(V)') or r.get('Offset(P)')),
                    'threads': _int(r.get('Threads')), 'handles': _int(r.get('Handles')), 'session': _int(r.get('SessionId')),
                    'wow64': bool(r.get('Wow64')), 'created': _time(r.get('CreateTime')), 'exited': _time(r.get('ExitTime')),
                    'path': _text(r.get('Path')), 'audit': _text(r.get('Audit')), 'cmdline': cmd, 'depth': depth})
    return out


def connections(data) -> list[dict]:
    """windows.netscan: TCP and UDP endpoints and connections with their owning process."""
    out = []
    for r, _, _ in rows(data):
        foreign = _text(r.get('ForeignAddr'))
        out.append({'proto': _text(r.get('Proto')), 'local_addr': _text(r.get('LocalAddr')), 'local_port': _int(r.get('LocalPort')),
                    'foreign_addr': foreign, 'foreign_port': _int(r.get('ForeignPort')), 'state': _text(r.get('State')),
                    'pid': _int(r.get('PID')), 'owner': _text(r.get('Owner')), 'created': _time(r.get('Created')), 'offset': _addr(r.get('Offset')),
                    'external': is_public(foreign)})
    return out


def is_public(addr: str | None) -> bool:
    try:
        return ipaddress.ip_address((addr or '').split('%')[0]).is_global
    except ValueError:
        return False


def injections(data) -> list[dict]:
    """windows.malware.malfind: private memory a process can execute that no file on disk backs, with its first bytes."""
    out = []
    for r, _, _ in rows(data):
        start, end = _int(r.get('Start VPN')), _int(r.get('End VPN'))
        hexdump = ' '.join((_text(r.get('Hexdump')) or '').split()[:HEXDUMP_BYTES])
        disasm = '\n'.join((r.get('Disasm') or '').strip('"').splitlines()[:DISASM_LINES]) if isinstance(r.get('Disasm'), str) else None
        out.append({'pid': _int(r.get('PID')), 'process': _text(r.get('Process')), 'start': _addr(start), 'end': _addr(end),
                    'size': end - start + 1 if start is not None and end is not None else None, 'tag': _text(r.get('Tag')),
                    'protection': _text(r.get('Protection')), 'commit_charge': _int(r.get('CommitCharge')), 'private': bool(r.get('PrivateMemory')),
                    'notes': _text(r.get('Notes')), 'hexdump': hexdump or None, 'disasm': disasm or None,
                    'mz': hexdump.lower().startswith('4d 5a')})
    return out


def services(data) -> list[dict]:
    """windows.svcscan: services and drivers as the service control manager holds them."""
    out = []
    for r, _, _ in rows(data):
        out.append({'name': _text(r.get('Name')), 'display': _text(r.get('Display')), 'binary': _text(r.get('Binary')),
                    'binary_registry': _text(r.get('Binary (Registry)')), 'dll': _text(r.get('Dll')), 'state': _text(r.get('State')),
                    'start': _text(r.get('Start')), 'service_type': _text(r.get('Type')), 'pid': _int(r.get('PID')), 'order': _int(r.get('Order')),
                    'offset': _addr(r.get('Offset'))})
    return out


def dlls(data) -> list[dict]:
    """windows.dlllist: the modules loaded in the processes asked about."""
    out = []
    for r, _, _ in rows(data):
        out.append({'pid': _int(r.get('PID')), 'process': _text(r.get('Process')), 'base': _addr(r.get('Base')), 'size': _int(r.get('Size')),
                    'name': _text(r.get('Name')), 'path': _text(r.get('Path')), 'load_count': _int(r.get('LoadCount')),
                    'load_time': _time(r.get('LoadTime'))})
    return out


# --------------------------------------------------------------------------------------------- what stands out
def _flag(rec: dict, code: str, label: str, severity: str):
    flags = rec.setdefault('flags', [])
    if not any(f['code'] == code for f in flags):
        flags.append({'code': code, 'label': label, 'severity': severity})


def _finish(rec: dict):
    rec.setdefault('flags', [])
    rec['score'] = sum(SEVERITY_SCORE[f['severity']] for f in rec['flags'])
    rec['notable'] = any(f['severity'] in ('high', 'medium') for f in rec['flags'])


def lookalike(name: str) -> str | None:
    """The system program a name imitates: one letter changed, added, dropped or swapped, or digits for letters."""
    n = name.lower()
    if n in SYSTEM_PATHS or n in KNOWN_NAMES:
        return None
    plain = n.translate(str.maketrans('013', 'oie'))
    for real in SYSTEM_PATHS:
        if plain == real or _one_edit(n, real):
            return real
    return None


def _one_edit(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1 or len(b) < 7:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def decode_powershell(cmdline: str | None) -> str | None:
    m = ENCODED.search(cmdline or '') if cmdline and re.search(r'powershell|pwsh', cmdline, re.I) else None
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1) + '=' * (-len(m.group(1)) % 4)).decode('utf-16-le', errors='replace')[:4000]
    except (ValueError, UnicodeDecodeError):
        return None


def _folder(path: str | None) -> str | None:
    """The path without its drive, lower case, for comparing with the expected folders."""
    if not path:
        return None
    p = path.replace('/', '\\').lower()
    p = re.sub(r'^(\\\\\?\\|\\\?\?\\)', '', p)
    p = re.sub(r'^[a-z]:', '', p)
    p = re.sub(r'^\\systemroot\\', lambda m: '\\windows\\', p)
    p = re.sub(r'^\\device\\harddiskvolume\d+', '', p)
    return p


def assess(procs: list[dict], conns: list[dict], injected: list[dict], svcs: list[dict]) -> None:
    """Flags (code, label, severity) on processes, connections, injected regions and services, with a score and
    `notable` (any high or medium flag)."""
    by_pid = {p['pid']: p for p in procs if p.get('pid') is not None}
    running = [p for p in procs if not p.get('exited')]
    for p in procs:
        path = p.get('path') or p.get('audit')
        folder = _folder(path)
        name = (p.get('name') or '').lower()
        base = folder.rsplit('\\', 1)[-1] if folder else ''
        if base.startswith(name) and len(name) >= 14:  # Windows keeps 15 characters of the name; the path has all of it
            name = base
        parent = by_pid.get(p.get('ppid'))
        p['parent_name'] = parent.get('name') if parent else None
        real = lookalike(name)
        if real:
            _flag(p, 'LOOKALIKE_NAME', f'Named like {real}', 'high')
        if name in SYSTEM_PATHS and folder and not any(folder.startswith(f) for f in SYSTEM_PATHS[name]):
            _flag(p, 'SYSTEM_NAME_WRONG_FOLDER', f'A Windows program\'s name, run from {path}', 'high')
        if name in EXPECTED_PARENTS and parent and (parent.get('name') or '').lower() not in EXPECTED_PARENTS[name]:
            _flag(p, 'WRONG_PARENT', f'Started by {parent.get("name")} (expected {", ".join(EXPECTED_PARENTS[name])})', 'high')
        if name in SINGLE_INSTANCE and not p.get('exited') and sum(1 for q in running if (q.get('name') or '').lower() == name) > 1:
            _flag(p, 'SECOND_INSTANCE', f'More than one {name} is running', 'high')
        if name in SHELLS and parent and (parent.get('name') or '').lower() in DOCUMENT_APPS:
            _flag(p, 'DOCUMENT_STARTED_SHELL', f'{p["name"]} started by {parent.get("name")}', 'high')
        decoded = decode_powershell(p.get('cmdline'))
        if decoded is not None:
            p['decoded_command'] = decoded
            _flag(p, 'ENCODED_POWERSHELL', 'PowerShell with an encoded command', 'high')
        if folder and USER_FOLDERS.search(folder):
            _flag(p, 'USER_FOLDER', 'Runs from a temporary, download or shared folder', 'medium')
    for r in injected:
        p = by_pid.get(r.get('pid'))
        if r.get('mz'):
            _flag(r, 'MZ_HEADER', 'Starts with a program header (MZ): a program loaded without a file', 'high')
        if 'EXECUTE_READWRITE' in (r.get('protection') or '').upper():
            _flag(r, 'WRITABLE_AND_EXECUTABLE', 'Writable and executable', 'medium')
        if p:
            n = sum(1 for x in injected if x.get('pid') == r.get('pid'))
            _flag(p, 'INJECTED_CODE', f'Executable memory no file backs (malfind): {n} region{"s" if n != 1 else ""}',
                  'high' if any(x.get('mz') for x in injected if x.get('pid') == r.get('pid')) else 'medium')
    for c in conns:
        p = by_pid.get(c.get('pid'))
        owner = (c.get('owner') or (p or {}).get('name') or '').lower()
        if c.get('external') and owner in QUIET_PROGRAMS:
            _flag(c, 'UNUSUAL_PROGRAM', f'{c.get("owner") or owner} connected to the internet', 'medium')
            if p:
                _flag(p, 'UNUSUAL_CONNECTION', f'Connected to {c["foreign_addr"]}:{c.get("foreign_port")}', 'medium')
        elif c.get('external') and p:
            _flag(p, 'INTERNET_CONNECTION', 'Has internet connections', 'low')
        if p and any(f['severity'] == 'high' for f in p.get('flags', [])) and c.get('external'):
            _flag(c, 'PROCESS_STANDS_OUT', f'The process that owns it stands out ({p["name"]}, PID {p["pid"]})', 'high')
    for s in svcs:
        binary = s.get('binary_registry') or s.get('binary')
        folder = _folder(re.sub(r'^"?([^"]+?)"?(\s+-.*|\s+/.*)?$', r'\1', binary or ''))
        if folder and USER_FOLDERS.search(folder):
            _flag(s, 'USER_FOLDER', 'Its program is in a temporary, download or shared folder', 'high')
        if binary and re.search(r'(^|\\|\s)(cmd|powershell|pwsh|mshta|rundll32|regsvr32)(\.exe)?\s', binary, re.I):
            _flag(s, 'RUNS_A_SHELL', 'Runs a command interpreter or script host', 'high')
        s['process'] = (by_pid.get(s.get('pid')) or {}).get('name')
    for rec in procs + conns + injected + svcs:
        _finish(rec)


def assess_dlls(modules: list[dict], procs: list[dict]) -> None:
    """Flags DLLs loaded from temporary, download or shared folders, and the processes that loaded them."""
    by_pid = {p['pid']: p for p in procs if p.get('pid') is not None}
    for d in modules:
        folder = _folder(d.get('path'))
        if folder and USER_FOLDERS.search(folder):
            _flag(d, 'USER_FOLDER', 'Loaded from a temporary, download or shared folder', 'medium')
            if d.get('pid') in by_pid:
                _flag(by_pid[d['pid']], 'DLL_FROM_USER_FOLDER', f'Loaded {d.get("name")} from a temporary, download or shared folder', 'medium')
                _finish(by_pid[d['pid']])
        _finish(d)


def notable_pids(procs: list[dict], limit: int = MAX_DLL_PIDS) -> list[int]:
    """The processes worth listing the DLLs of: those that stand out, most first."""
    ranked = sorted((p for p in procs if p.get('notable') and p.get('pid') is not None), key=lambda p: (-p['score'], p['pid']))
    return [p['pid'] for p in ranked[:limit]]


def failure(stdout: str, stderr: str) -> str:
    """Why Volatility could not read the image, from its own messages."""
    text = f'{stdout}\n{stderr}'
    if 'kernel.layer_name' in text:
        return 'no Windows kernel was found in it'
    if 'symbol_table_name' in text:
        return 'the Windows kernel was found, but not its symbols'
    last = [ln for ln in text.splitlines() if ln.strip()][-1:] or ['no output']
    return last[0][:300]
