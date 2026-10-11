"""What Windows events mean: a catalog of the events an investigation looks for, each with a category, a plain-English
description built from the event's own data, whether it is notable (shown on the Notable tab and the timeline), and the
timeline event type it becomes.

Events are identified by channel and event ID, and by provider where two providers in one channel use the same ID
(System 7001 is a user logon from Winlogon but a service dependency failure from the Service Control Manager).
Events that are not in the catalog are still stored and searchable; they are just not described or put on the timeline.
"""
from __future__ import annotations
import base64
import binascii
import re
from dataclasses import dataclass
from typing import Callable

LOGON_TYPES = {
    '0': 'System', '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service', '7': 'Unlock', '8': 'Network cleartext',
    '9': 'New credentials (RunAs /netonly)', '10': 'Remote interactive (Remote Desktop)', '11': 'Cached interactive',
    '12': 'Cached remote interactive', '13': 'Cached unlock',
}
# NTSTATUS codes of failed logons (Status / SubStatus of 4625, and 4771/4776).
FAILURE_REASONS = {
    '0xc0000064': 'user name does not exist', '0xc000006a': 'wrong password', '0xc000006d': 'bad user name or password',
    '0xc000006e': 'account restriction', '0xc000006f': 'outside allowed logon hours', '0xc0000070': 'workstation not allowed',
    '0xc0000071': 'password expired', '0xc0000072': 'account disabled', '0xc000009a': 'insufficient system resources',
    '0xc0000133': 'clocks out of sync with the domain controller', '0xc000015b': 'logon type not granted',
    '0xc0000192': 'Netlogon service not started', '0xc0000193': 'account expired', '0xc0000224': 'password must be changed',
    '0xc0000234': 'account locked out', '0xc0000413': 'authentication firewall', '0xc0000371': 'local account store is not accessible',
}
# Accounts that log on constantly on every Windows computer: their logons are kept but are not notable.
SERVICE_SIDS = {'S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-0-0', 'S-1-5-7'}
SERVICE_NAMES = {'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', '-', ''}
LEVELS = {0: 'Information', 1: 'Critical', 2: 'Error', 3: 'Warning', 4: 'Information', 5: 'Verbose'}
SECURITY_LEVEL_NAMES = {0x8010000000000000: 'Audit Failure', 0x8020000000000000: 'Audit Success'}

CATEGORY_LABELS = {
    'LOGON': 'Logon and logoff', 'LOGON_FAILED': 'Failed logon', 'ACCOUNT': 'Accounts and groups', 'LOG_CLEARED': 'Log cleared',
    'SERVICE': 'Services', 'TASK': 'Scheduled tasks', 'REMOTE': 'Remote access', 'POWERSHELL': 'PowerShell',
    'DEVICE': 'Devices (USB)', 'DEFENDER': 'Microsoft Defender', 'POWER': 'Startup and shutdown', 'POLICY': 'Policy and time',
    'PROCESS': 'Processes', 'SHARE': 'Network shares', 'PROGRAM': 'Programs installed', 'PRIVILEGE': 'Privilege use',
}


def value(rec: dict, name: str, default: str = '') -> str:
    v = (rec.get('data') or {}).get(name)
    if v is None:
        v = (rec.get('details') or {}).get(name)
    return default if v is None else str(v)


def unnamed(rec: dict, i: int) -> str:
    vals = rec.get('data_values') or []
    return str(vals[i]) if i < len(vals) and vals[i] is not None else ''


def account(domain: str, name: str) -> str:
    name = (name or '').strip()
    if not name or name == '-':
        return ''
    return f'{domain}\\{name}' if domain and domain not in ('-', '') else name


def is_service_account(sid: str, name: str) -> bool:
    name = (name or '').strip()
    return (sid or '') in SERVICE_SIDS or name.upper() in SERVICE_NAMES or name.endswith('$') \
        or name.upper().startswith(('DWM-', 'UMFD-', 'FONT DRIVER HOST', 'WINDOW MANAGER'))


def logon_type(rec: dict) -> str:
    t = value(rec, 'LogonType')
    return f'{LOGON_TYPES.get(t, "type " + t)}, type {t}' if t else 'unknown type'


def failure_reason(rec: dict) -> str:
    for field in ('SubStatus', 'Status', 'FailureCode'):
        code = value(rec, field).lower()
        if code and code not in ('0x0', '0x00000000'):
            return FAILURE_REASONS.get(code, f'status {code}')
    return 'reason not recorded'


def remote_address(rec: dict) -> str:
    ip = value(rec, 'IpAddress') or value(rec, 'ClientAddress')
    return '' if ip in ('', '-', '127.0.0.1', '::1', 'LOCAL') else ip


# ---------------------------------------------------------------------------------- PowerShell
_ENC_TOKEN = re.compile(r'''(?:^|\s)[-/–—]([A-Za-z]+)\s+['"]?([A-Za-z0-9+/]{4,}={0,2})['"]?''')


def decode_encoded_command(command: str) -> str | None:
    """The script hidden in a PowerShell command line's -EncodedCommand argument (Base64 of UTF-16LE), or None.

    PowerShell accepts any unambiguous prefix of a parameter name, so -e, -en, -enc, ... -EncodedCommand and the alias
    -ec all mean EncodedCommand (-ex and -ep are ExecutionPolicy, not matched here)."""
    for m in _ENC_TOKEN.finditer(command or ''):
        name = m.group(1).lower()
        if name != 'ec' and not ('encodedcommand'.startswith(name) and name.startswith('e')):
            continue
        try:
            raw = base64.b64decode(m.group(2) + '=' * (-len(m.group(2)) % 4), validate=True)
            text = raw.decode('utf-16-le')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # A script is (almost all) plain text; random Base64 decodes to arbitrary UTF-16 characters.
        if text and sum(1 for c in text if ' ' <= c <= '~' or c in '\r\n\t') >= 0.8 * len(text):
            return text
    return None


def classic_powershell_details(text: str) -> dict:
    """The key=value lines of a classic "Windows PowerShell" event (400, 403, 600, 800): HostApplication, HostName,
    EngineVersion, CommandLine, ScriptName, ..."""
    out = {}
    for line in (text or '').splitlines():
        k, sep, v = line.strip().partition('=')
        if sep and re.fullmatch(r'[A-Za-z]{2,40}', k) and k not in out:
            out[k] = v.strip()
    return out


# ---------------------------------------------------------------------------------- the catalog
@dataclass(frozen=True)
class Entry:
    category: str
    title: str
    describe: Callable[[dict, Callable[[str], str]], str]
    timeline: str | None = None                     # timeline event type; None = not put on the timeline itself
    notable: bool | Callable[[dict], bool] = True
    provider: str | None = None                     # must match when set (case-insensitive)
    user: Callable[[dict, Callable[[str], str]], str] | None = None   # who the event is about (default: see event_user)


def _logon_notable(rec):
    return not is_service_account(value(rec, 'TargetUserSid'), value(rec, 'TargetUserName')) and value(rec, 'LogonType') != '5'


def _target(rec, name):
    return account(value(rec, 'TargetDomainName'), value(rec, 'TargetUserName'))


def _subject(rec, name):
    return account(value(rec, 'SubjectDomainName'), value(rec, 'SubjectUserName'))


def _member(rec, name):
    m = value(rec, 'MemberName')
    if m and m != '-':
        cn = re.match(r'(?i)CN=([^,]+)', m)
        return cn.group(1) if cn else m
    return name(value(rec, 'MemberSid')) or value(rec, 'MemberSid')


def _by(rec, name):
    s = _subject(rec, name)
    return f' by {s}' if s else ''


def _from(rec):
    ip, ws = remote_address(rec), value(rec, 'WorkstationName')
    parts = []
    if ip:
        parts.append(f'from {ip}')
    if ws and ws != '-':
        parts.append(f'(workstation {ws})')
    return (' ' + ' '.join(parts)) if parts else ''


def _logon(rec, name):
    return f'{_target(rec, name)} logged on ({logon_type(rec)}){_from(rec)}'


def _failed(rec, name):
    return f'Failed logon for {_target(rec, name) or "an unknown account"} ({logon_type(rec)}){_from(rec)}: {failure_reason(rec)}'


def _session_user(rec, name):
    u = value(rec, 'User') or value(rec, 'AccountName')
    return u or name(value(rec, 'UserSid'))


def _ps_command(rec):
    return value(rec, 'HostApplication') or value(rec, 'CommandLine')


def _ps_started(rec, name):
    cmd = _ps_command(rec)
    decoded = decode_encoded_command(cmd)
    if decoded:  # the decoded script says what the Base64 says; the full command line stays in the event's data
        cmd = re.sub(r'([A-Za-z0-9+/]{24})[A-Za-z0-9+/]{8,}={0,2}', r'\1…', cmd)
    text = f'PowerShell started: {cmd}' if cmd else 'PowerShell engine started'
    return text + (f' (decoded command: {decoded})' if decoded else '')


def _ps_suspicious_start(rec):
    cmd = _ps_command(rec).lower()
    return bool(decode_encoded_command(cmd)) or any(w in cmd for w in ('hidden', 'bypass', 'downloadstring', 'iex', 'invoke-expression',
                                                                        'frombase64string', '-nop'))


def _script_block(rec, name):
    text = ' '.join(value(rec, 'ScriptBlockText').split())
    flagged = ' (Windows logged it as suspicious)' if rec.get('level') == 3 else ''
    part = f' part {value(rec, "MessageNumber")} of {value(rec, "MessageTotal")}' if value(rec, 'MessageTotal') not in ('', '1') else ''
    return f'PowerShell script block{part}{flagged}: {text[:400]}' + ('…' if len(text) > 400 else '')


def _disk(rec, name):
    what = ' '.join(x for x in (value(rec, 'Manufacturer'), value(rec, 'Model')) if x).strip() or 'disk'
    serial = value(rec, 'SerialNumber')
    cap = value(rec, 'Capacity')
    if cap == '0':
        return f'Disk removed: {what}' + (f' (serial {serial})' if serial else '')
    size = f', {int(cap) / 1e9:.1f} GB' if cap.isdigit() else ''
    return f'Disk connected: {what}{size}' + (f' (serial {serial})' if serial else '')


def _device(verb):
    def describe(rec, name):
        dev = (value(rec, 'DeviceInstanceId') or value(rec, 'DeviceInstanceID') or value(rec, 'instance') or value(rec, 'DriverName')
               or unnamed(rec, 0))
        return f'Device {verb}: {dev}' if dev else f'Device {verb}'
    return describe


def _usb_device(rec):
    text = ' '.join(str(v) for v in (rec.get('data') or {}).values()).upper()
    return 'USBSTOR' in text or 'WPDBUSENUM' in text or '\\USB\\' in text or text.startswith('USB\\')


def _msi(verb):
    def describe(rec, name):
        product = value(rec, 'ProductName') or unnamed(rec, 0)
        product = re.sub(r'^Product:\s*', '', product).split(' -- ')[0].strip()
        version = unnamed(rec, 1) if rec.get('event_id') in (1033, 1034) else ''
        return f'Program {verb}: {product}' + (f' {version}' if version and version[0].isdigit() else '')
    return describe


def _plain(text):
    return lambda rec, name: text


E = Entry
SECURITY = {
    4624: E('LOGON', 'Logon', _logon, 'LOGON', _logon_notable, user=lambda r, n: value(r, 'TargetUserName')),
    4625: E('LOGON_FAILED', 'Failed logon', _failed, 'LOGON_FAILED', user=lambda r, n: value(r, 'TargetUserName')),
    4634: E('LOGON', 'Logoff', lambda r, n: f'{_target(r, n)} logged off ({logon_type(r)})', 'LOGOFF', _logon_notable,
            user=lambda r, n: value(r, 'TargetUserName')),
    4647: E('LOGON', 'User-initiated logoff', lambda r, n: f'{_target(r, n)} logged off (user initiated)', 'LOGOFF',
            user=lambda r, n: value(r, 'TargetUserName')),
    4648: E('LOGON', 'Logon with explicit credentials',
            lambda r, n: f'{_subject(r, n)} used the credentials of {_target(r, n)}'
                         + (f' for {value(r, "TargetServerName")}' if value(r, 'TargetServerName') not in ('', '-', 'localhost') else '')
                         + (f' ({value(r, "ProcessName")})' if value(r, 'ProcessName') not in ('', '-') else ''),
            'LOGON', lambda r: not is_service_account(value(r, 'SubjectUserSid'), value(r, 'SubjectUserName'))),
    4672: E('PRIVILEGE', 'Special privileges assigned to a new logon', lambda r, n: f'Administrator privileges assigned to {_subject(r, n)}',
            None, False),
    4688: E('PROCESS', 'Process created',
            lambda r, n: f'Process created: {value(r, "NewProcessName")}'
                         + (f' ({value(r, "CommandLine")})' if value(r, 'CommandLine') else '') + _by(r, n), None, False),
    4697: E('SERVICE', 'Service installed', lambda r, n: f'Service installed: {value(r, "ServiceName")} ({value(r, "ServiceFileName")}){_by(r, n)}',
            'SERVICE_INSTALLED'),
    4698: E('TASK', 'Scheduled task created', lambda r, n: f'Scheduled task created: {value(r, "TaskName")}{_by(r, n)}', 'SCHEDULED_TASK'),
    4699: E('TASK', 'Scheduled task deleted', lambda r, n: f'Scheduled task deleted: {value(r, "TaskName")}{_by(r, n)}', 'SCHEDULED_TASK'),
    4700: E('TASK', 'Scheduled task enabled', lambda r, n: f'Scheduled task enabled: {value(r, "TaskName")}{_by(r, n)}', 'SCHEDULED_TASK'),
    4701: E('TASK', 'Scheduled task disabled', lambda r, n: f'Scheduled task disabled: {value(r, "TaskName")}{_by(r, n)}', 'SCHEDULED_TASK'),
    4702: E('TASK', 'Scheduled task updated', lambda r, n: f'Scheduled task updated: {value(r, "TaskName")}{_by(r, n)}', 'SCHEDULED_TASK'),
    4616: E('POLICY', 'System time changed',
            lambda r, n: f'System time changed from {value(r, "PreviousTime")} to {value(r, "NewTime")}{_by(r, n)}'
                         + (f' ({value(r, "ProcessName")})' if value(r, 'ProcessName') not in ('', '-') else ''),
            'TIME_CHANGED', lambda r: value(r, 'SubjectUserSid') not in ('S-1-5-19',)),
    4719: E('POLICY', 'Audit policy changed', lambda r, n: f'Audit policy changed{_by(r, n)}: {value(r, "SubcategoryGuid")} {value(r, "AuditPolicyChanges")}'.rstrip(),
            'AUDIT_POLICY_CHANGED'),
    4720: E('ACCOUNT', 'User account created', lambda r, n: f'User account created: {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4722: E('ACCOUNT', 'User account enabled', lambda r, n: f'User account enabled: {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4723: E('ACCOUNT', 'Password change attempted', lambda r, n: f'Password change attempted for {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4724: E('ACCOUNT', 'Password reset', lambda r, n: f'Password reset for {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4725: E('ACCOUNT', 'User account disabled', lambda r, n: f'User account disabled: {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4726: E('ACCOUNT', 'User account deleted', lambda r, n: f'User account deleted: {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4738: E('ACCOUNT', 'User account changed', lambda r, n: f'User account changed: {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4740: E('ACCOUNT', 'User account locked out',
            lambda r, n: f'User account locked out: {value(r, "TargetUserName")} (from {value(r, "TargetDomainName") or "unknown computer"})',
            'ACCOUNT_CHANGED'),
    4767: E('ACCOUNT', 'User account unlocked', lambda r, n: f'User account unlocked: {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED'),
    4781: E('ACCOUNT', 'Account renamed', lambda r, n: f'Account renamed from {value(r, "OldTargetUserName")} to {value(r, "NewTargetUserName")}{_by(r, n)}',
            'ACCOUNT_CHANGED'),
    4778: E('REMOTE', 'Session reconnected',
            lambda r, n: f'Session reconnected: {account(value(r, "AccountDomain"), value(r, "AccountName"))} from {value(r, "ClientName")} ({value(r, "ClientAddress")})',
            'LOGON', user=lambda r, n: value(r, 'AccountName')),
    4779: E('REMOTE', 'Session disconnected',
            lambda r, n: f'Session disconnected: {account(value(r, "AccountDomain"), value(r, "AccountName"))} from {value(r, "ClientName")} ({value(r, "ClientAddress")})',
            'LOGOFF', user=lambda r, n: value(r, 'AccountName')),
    4800: E('LOGON', 'Workstation locked', lambda r, n: f'Workstation locked by {_target(r, n)}', 'LOGOFF', user=lambda r, n: value(r, 'TargetUserName')),
    4801: E('LOGON', 'Workstation unlocked', lambda r, n: f'Workstation unlocked by {_target(r, n)}', 'LOGON', user=lambda r, n: value(r, 'TargetUserName')),
    5140: E('SHARE', 'Network share accessed',
            lambda r, n: f'Network share {value(r, "ShareName")} accessed{_by(r, n)}' + (f' from {remote_address(r)}' if remote_address(r) else ''),
            'SHARE_ACCESS', lambda r: not is_service_account(value(r, 'SubjectUserSid'), value(r, 'SubjectUserName'))),
}
for _eid, _verb in ((4728, 'added to'), (4732, 'added to'), (4756, 'added to'), (4729, 'removed from'), (4733, 'removed from'),
                    (4757, 'removed from')):
    SECURITY[_eid] = E('ACCOUNT', f'Member {_verb} a group',
                       lambda r, n, v=_verb: f'{_member(r, n)} {v} group {_target(r, n)}{_by(r, n)}', 'ACCOUNT_CHANGED', user=_member)

_LOG_CLEARED = E('LOG_CLEARED', 'Security log cleared',
                 lambda r, n: f'Security log cleared{_by(r, n)}', 'LOG_CLEARED', provider='Microsoft-Windows-Eventlog',
                 user=lambda r, n: value(r, 'SubjectUserName'))

CATALOG: dict[tuple[str, int], list[Entry]] = {('security', k): [v] for k, v in SECURITY.items()}
CATALOG[('security', 1102)] = [_LOG_CLEARED]


def _add(channel: str, eid: int, entry: Entry):
    CATALOG.setdefault((channel.lower(), eid), []).append(entry)


_add('System', 104, E('LOG_CLEARED', 'Event log cleared',
                      lambda r, n: f'{value(r, "Channel") or "An event"} log cleared{_by(r, n)}', 'LOG_CLEARED',
                      provider='Microsoft-Windows-Eventlog', user=lambda r, n: value(r, 'SubjectUserName')))
_add('System', 7045, E('SERVICE', 'Service installed',
                       lambda r, n: f'Service installed: {value(r, "ServiceName")}: {value(r, "ImagePath")}'
                                    + (f' ({value(r, "StartType")}, runs as {value(r, "AccountName")})' if value(r, 'StartType') else ''),
                       'SERVICE_INSTALLED', provider='Service Control Manager'))
_add('System', 7040, E('SERVICE', 'Service start type changed',
                       lambda r, n: f'Service {unnamed(r, 0) or value(r, "param1")} start type changed from {unnamed(r, 1) or value(r, "param2")} to {unnamed(r, 2) or value(r, "param3")}',
                       'SERVICE_CHANGED', provider='Service Control Manager'))
_add('System', 7034, E('SERVICE', 'Service stopped unexpectedly',
                       lambda r, n: f'Service stopped unexpectedly: {unnamed(r, 0) or value(r, "param1")}', None, False,
                       provider='Service Control Manager'))
_add('System', 6005, E('POWER', 'Event log service started', _plain('Event log service started (Windows started)'), 'SYSTEM_STARTUP',
                       provider='EventLog'))
_add('System', 6006, E('POWER', 'Event log service stopped', _plain('Event log service stopped (clean shutdown)'), 'SYSTEM_SHUTDOWN',
                       provider='EventLog'))
_add('System', 6008, E('POWER', 'Unexpected shutdown',
                       lambda r, n: f'The previous shutdown was unexpected (at {unnamed(r, 1)} {unnamed(r, 0)} local time)'.replace(' ( local time)', ''),
                       'SYSTEM_SHUTDOWN', provider='EventLog'))
_add('System', 6009, E('POWER', 'Windows version at startup',
                       lambda r, n: f'Windows {unnamed(r, 0)} build {unnamed(r, 1)} {unnamed(r, 2)} started'.strip(), None, False, provider='EventLog'))
_add('System', 1074, E('POWER', 'Shutdown or restart requested',
                       lambda r, n: f'{value(r, "param7") or unnamed(r, 6)} requested {value(r, "param5") or unnamed(r, 4)} through '
                                    f'{value(r, "param1") or unnamed(r, 0)}: {value(r, "param3") or unnamed(r, 2)}',
                       'SYSTEM_SHUTDOWN', provider='User32', user=lambda r, n: (value(r, 'param7') or unnamed(r, 6)).split('\\')[-1]))
_add('System', 12, E('POWER', 'Operating system started', _plain('Operating system started'), 'SYSTEM_STARTUP',
                     provider='Microsoft-Windows-Kernel-General'))
_add('System', 13, E('POWER', 'Operating system shutdown', _plain('Operating system shut down'), 'SYSTEM_SHUTDOWN',
                     provider='Microsoft-Windows-Kernel-General'))
_add('System', 1, E('POLICY', 'System time changed',
                    lambda r, n: f'System time changed from {value(r, "OldTime")} to {value(r, "NewTime")}', 'TIME_CHANGED',
                    lambda r: value(r, 'Reason') not in ('2',), provider='Microsoft-Windows-Kernel-General'))
_add('System', 1, E('POWER', 'Resumed from sleep',
                    lambda r, n: f'Resumed from sleep (sleep started {value(r, "SleepTime")})', 'SYSTEM_STARTUP',
                    provider='Microsoft-Windows-Power-Troubleshooter'))
_add('System', 41, E('POWER', 'Unexpected restart', _plain('Windows restarted without shutting down cleanly (crash or power loss)'),
                     'SYSTEM_SHUTDOWN', provider='Microsoft-Windows-Kernel-Power'))
_add('System', 42, E('POWER', 'Sleep', _plain('The computer went to sleep'), 'SYSTEM_SHUTDOWN', provider='Microsoft-Windows-Kernel-Power'))
_add('System', 7001, E('LOGON', 'User logon notification', lambda r, n: f'{_session_user(r, n) or "A user"} logged on (Winlogon)', 'LOGON',
                       provider='Microsoft-Windows-Winlogon', user=_session_user))
_add('System', 7002, E('LOGON', 'User logoff notification', lambda r, n: f'{_session_user(r, n) or "A user"} logged off (Winlogon)', 'LOGOFF',
                       provider='Microsoft-Windows-Winlogon', user=_session_user))
_add('System', 20001, E('DEVICE', 'Device driver installed', _device('driver installed'), None, _usb_device,
                        provider='Microsoft-Windows-UserPnp'))
_add('System', 20003, E('DEVICE', 'Device service added', _device('service added'), None, _usb_device, provider='Microsoft-Windows-UserPnp'))

_add('Microsoft-Windows-Partition/Diagnostic', 1006, E('DEVICE', 'Disk connected or removed', _disk))
_add('Microsoft-Windows-Kernel-PnP/Configuration', 400, E('DEVICE', 'Device configured', _device('configured'), None, _usb_device))
_add('Microsoft-Windows-Kernel-PnP/Configuration', 410, E('DEVICE', 'Device started', _device('started'), None, _usb_device))
_add('Microsoft-Windows-Kernel-PnP/Configuration', 420, E('DEVICE', 'Device deleted', _device('deleted'), None, _usb_device))
_add('Microsoft-Windows-Kernel-PnP/Configuration', 430, E('DEVICE', 'Device installation incomplete', _device('not fully installed'), None,
                                                          _usb_device))
for _eid, _verb in ((2003, 'connected (driver framework loaded)'), (2100, 'being removed'), (2101, 'removal request completed'),
                    (2102, 'disconnected (driver framework unloaded)')):
    _add('Microsoft-Windows-DriverFrameworks-UserMode/Operational', _eid, E('DEVICE', f'Device {_verb}', _device(_verb), None, _usb_device))

_PS_OP = 'Microsoft-Windows-PowerShell/Operational'
_add(_PS_OP, 4104, E('POWERSHELL', 'PowerShell script block', _script_block, 'POWERSHELL',
                     lambda r: r.get('level') == 3))
_add(_PS_OP, 4103, E('POWERSHELL', 'PowerShell command (module logging)',
                     lambda r, n: f'PowerShell command: {" ".join(value(r, "Payload").split())[:300]}', None, False))
_add(_PS_OP, 40961, E('POWERSHELL', 'PowerShell console starting', _plain('PowerShell console is starting up'), None, False))
_add('Windows PowerShell', 400, E('POWERSHELL', 'PowerShell engine started', _ps_started, 'POWERSHELL'))
_add('Windows PowerShell', 403, E('POWERSHELL', 'PowerShell engine stopped',
                                  lambda r, n: f'PowerShell stopped: {_ps_command(r)}' if _ps_command(r) else 'PowerShell engine stopped',
                                  None, False))
_add('Windows PowerShell', 600, E('POWERSHELL', 'PowerShell provider started',
                                  lambda r, n: f'PowerShell provider {value(r, "ProviderName")} started: {_ps_command(r)}', None, False))
_add('Windows PowerShell', 800, E('POWERSHELL', 'PowerShell pipeline executed',
                                  lambda r, n: f'PowerShell pipeline executed: {value(r, "CommandLine") or unnamed(r, 0)[:300]}', 'POWERSHELL',
                                  _ps_suspicious_start))

_TASKS = 'Microsoft-Windows-TaskScheduler/Operational'
_add(_TASKS, 106, E('TASK', 'Scheduled task registered',
                    lambda r, n: f'Scheduled task registered: {value(r, "TaskName")}' + (f' by {value(r, "UserContext")}' if value(r, 'UserContext') else ''),
                    'SCHEDULED_TASK', user=lambda r, n: value(r, 'UserContext').split('\\')[-1]))
_add(_TASKS, 140, E('TASK', 'Scheduled task updated', lambda r, n: f'Scheduled task updated: {value(r, "TaskName")}' + (f' by {value(r, "UserName")}' if value(r, 'UserName') else ''),
                    'SCHEDULED_TASK', user=lambda r, n: value(r, 'UserName').split('\\')[-1]))
_add(_TASKS, 141, E('TASK', 'Scheduled task deleted', lambda r, n: f'Scheduled task deleted: {value(r, "TaskName")}' + (f' by {value(r, "UserName")}' if value(r, 'UserName') else ''),
                    'SCHEDULED_TASK', user=lambda r, n: value(r, 'UserName').split('\\')[-1]))
_add(_TASKS, 200, E('TASK', 'Scheduled task action started', lambda r, n: f'Scheduled task {value(r, "TaskName")} started {value(r, "ActionName")}',
                    None, False))
_add(_TASKS, 201, E('TASK', 'Scheduled task action completed', lambda r, n: f'Scheduled task {value(r, "TaskName")} finished {value(r, "ActionName")}',
                    None, False))

_LSM = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
for _eid, _what, _type in ((21, 'logon', 'LOGON'), (22, 'shell started', None), (23, 'logoff', 'LOGOFF'), (24, 'disconnected', 'LOGOFF'),
                           (25, 'reconnected', 'LOGON')):
    _add(_LSM, _eid, E('REMOTE', f'Remote Desktop session {_what}',
                       lambda r, n, w=_what: f'Remote Desktop session {w}: {value(r, "User")}'
                                             + (f' from {value(r, "Address")}' if value(r, 'Address') not in ('', 'LOCAL') else ' (local console)')
                                             + (f', session {value(r, "SessionID")}' if value(r, 'SessionID') else ''),
                       _type, _type is not None, user=lambda r, n: value(r, 'User').split('\\')[-1]))
_add('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', 1149,
     E('REMOTE', 'Remote Desktop authentication succeeded',
       lambda r, n: f'Remote Desktop authentication succeeded for {account(value(r, "Param2"), value(r, "Param1"))} from {value(r, "Param3")}',
       'LOGON', user=lambda r, n: value(r, 'Param1')))

_DEFENDER = 'Microsoft-Windows-Windows Defender/Operational'
_add(_DEFENDER, 1116, E('DEFENDER', 'Malware detected',
                        lambda r, n: f'Microsoft Defender detected {value(r, "Threat Name")} in {value(r, "Path")}'
                                     + (f' (user {value(r, "Detection User")})' if value(r, 'Detection User') else ''),
                        'DEFENDER_ALERT', user=lambda r, n: value(r, 'Detection User').split('\\')[-1]))
_add(_DEFENDER, 1117, E('DEFENDER', 'Malware action taken',
                        lambda r, n: f'Microsoft Defender acted on {value(r, "Threat Name")}: {value(r, "Action Name")} ({value(r, "Path")})',
                        'DEFENDER_ALERT', user=lambda r, n: value(r, 'Detection User').split('\\')[-1]))
_add(_DEFENDER, 1118, E('DEFENDER', 'Malware action failed', lambda r, n: f'Microsoft Defender could not act on {value(r, "Threat Name")}: {value(r, "Error Description")}',
                        'DEFENDER_ALERT'))
_add(_DEFENDER, 1119, E('DEFENDER', 'Malware action failed (critical)', lambda r, n: f'Microsoft Defender could not act on {value(r, "Threat Name")}: {value(r, "Error Description")}',
                        'DEFENDER_ALERT'))
_add(_DEFENDER, 5001, E('DEFENDER', 'Real-time protection disabled', _plain('Microsoft Defender real-time protection was turned off'), 'DEFENDER_ALERT'))
_add(_DEFENDER, 5010, E('DEFENDER', 'Spyware scanning disabled', _plain('Microsoft Defender scanning for spyware was turned off'), 'DEFENDER_ALERT'))
_add(_DEFENDER, 5012, E('DEFENDER', 'Virus scanning disabled', _plain('Microsoft Defender scanning for viruses was turned off'), 'DEFENDER_ALERT'))
_add(_DEFENDER, 5007, E('DEFENDER', 'Defender configuration changed',
                        lambda r, n: f'Microsoft Defender setting changed: {value(r, "New Value") or value(r, "Old Value")}', 'DEFENDER_ALERT',
                        lambda r: 'exclusions' in value(r, 'New Value').lower() or 'disable' in value(r, 'New Value').lower()))

_add('Application', 11707, E('PROGRAM', 'Program installed', _msi('installed'), 'PROGRAM_INSTALLED', provider='MsiInstaller'))
_add('Application', 11724, E('PROGRAM', 'Program removed', _msi('removed'), 'PROGRAM_INSTALLED', provider='MsiInstaller'))
_add('Application', 1033, E('PROGRAM', 'Program installed', _msi('installed'), 'PROGRAM_INSTALLED', provider='MsiInstaller'))
_add('Application', 1034, E('PROGRAM', 'Program removed', _msi('removed'), 'PROGRAM_INSTALLED', provider='MsiInstaller'))
_add('Application', 1000, E('PROCESS', 'Application crashed', lambda r, n: f'Application crashed: {unnamed(r, 0) or value(r, "AppName")}', None, False,
                            provider='Application Error'))


def lookup(rec: dict) -> Entry | None:
    for entry in CATALOG.get(((rec.get('channel') or '').lower(), rec.get('event_id')), ()):
        if entry.provider is None or entry.provider.lower() == (rec.get('provider') or '').lower():
            return entry
    return None


_NOT_A_USER = {'-', '', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON'}


def event_user(rec: dict, name_of: Callable[[str], str], entry: Entry | None = None) -> str | None:
    """The account an event is about: the account logging on, or whoever acted (who cleared the log, who created the
    account); computer and service accounts are left out. SIDs are named through the evidence's accounts."""
    if entry and entry.user:
        u = (entry.user(rec, name_of) or '').strip()
        return u if u and u.upper() not in _NOT_A_USER and not u.endswith('$') else None
    for field in ('TargetUserName', 'SubjectUserName'):
        u = value(rec, field)
        if u and u.upper() not in _NOT_A_USER and not u.endswith('$'):
            return u
    for sid in (value(rec, 'UserSid'), value(rec, 'TargetUserSid'), value(rec, 'SubjectUserSid'), rec.get('user_sid') or ''):
        if sid and sid not in SERVICE_SIDS:
            u = name_of(sid)
            if u:
                return u
    return None


def describe(rec: dict, name_of: Callable[[str], str]) -> dict:
    """Category, title, description, user, timeline type and whether the event is notable."""
    entry = lookup(rec)
    out = {'user': event_user(rec, name_of, entry)}
    if entry is None:
        return dict(out, category=None, title=None, description=None, timeline=None, notable=False)
    try:
        text = entry.describe(rec, name_of)
    except Exception:  # an event with unexpected data is still listed, with its title
        text = entry.title
    notable = entry.notable(rec) if callable(entry.notable) else entry.notable
    return dict(out, category=entry.category, title=entry.title, description=' '.join(str(text).split()), timeline=entry.timeline,
                notable=bool(notable))


def level_name(rec: dict) -> str:
    kw = rec.get('keywords_int')
    if rec.get('channel') == 'Security' and kw in SECURITY_LEVEL_NAMES:
        return SECURITY_LEVEL_NAMES[kw]
    return LEVELS.get(rec.get('level'), str(rec.get('level')))
