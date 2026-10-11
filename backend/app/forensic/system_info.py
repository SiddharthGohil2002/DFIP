"""The computer and its users, from the SYSTEM, SOFTWARE and SAM registry hives.

SYSTEM   computer name, last shutdown, network interfaces, time zone
SOFTWARE Windows edition, version and build, install date, registered owner, user profiles (SID -> profile
         folder, last load), the last user who signed in
SAM      local user accounts: name, full name, RID (so the SID), last logon, logon count, password last set,
         disabled flag

Values that are not in the hives are reported as absent, never estimated.
"""
from __future__ import annotations
import struct
from datetime import datetime, timezone

from .registry import as_bytes, control_sets, filetime_to_datetime, open_hive, subkey, values
from .timezone import read_time_zone

HIVE_PATHS = {'SYSTEM': '/Windows/System32/config/SYSTEM', 'SOFTWARE': '/Windows/System32/config/SOFTWARE',
              'SAM': '/Windows/System32/config/SAM'}
ACB_DISABLED = 0x0001
ACB_NORMAL = 0x0010
ACB_PWNOEXP = 0x0200
WELL_KNOWN_PROFILES = {'S-1-5-18': 'SYSTEM', 'S-1-5-19': 'LOCAL SERVICE', 'S-1-5-20': 'NETWORK SERVICE'}


def _iso(dt):
    return dt.isoformat() if dt else None


def _key(reg, path):
    try:
        return reg.get_key(path)
    except Exception:
        return None


def _first(value):
    return (value[0] if value else None) if isinstance(value, list) else value


def _epoch(value):
    """A REG_DWORD holding Unix seconds (InstallDate, DHCP lease times) as UTC."""
    if isinstance(value, int) and value > 0:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    return None


def find_hive(source, name: str):
    """(volume_id, inode) of a Windows hive on the first volume that has it, or (None, None)."""
    for vid in source.volumes():
        try:
            inode = source.find(vid, HIVE_PATHS[name])
        except Exception:
            inode = None
        if inode:
            return vid, inode
    return None, None


# ---------------------------------------------------------------------------------------------- SYSTEM
def parse_system(path) -> dict:
    out = {'status': 'COMPLETED', 'errors': [], 'computer_name': None, 'hostname': None, 'domain': None,
           'last_shutdown': None, 'interfaces': [], 'time_zone': None, 'control_set': None}
    try:
        reg = open_hive(path)
        sets = control_sets(reg)
    except Exception as exc:
        return dict(out, status='FAILED', errors=[f'Not a readable SYSTEM hive: {exc}'])
    if not sets:
        return dict(out, status='FAILED', errors=['No control set in the SYSTEM hive'])
    cs = sets[0]
    out['control_set'] = cs
    k = _key(reg, f'\\{cs}\\Control\\ComputerName\\ComputerName')
    if k:
        out['computer_name'] = values(k).get('ComputerName')
    k = _key(reg, f'\\{cs}\\Control\\Windows')
    if k:
        out['last_shutdown'] = _iso(filetime_to_datetime(values(k).get('ShutdownTime')))
    tcpip = _key(reg, f'\\{cs}\\Services\\Tcpip\\Parameters')
    if tcpip:
        v = values(tcpip)
        out['hostname'], out['domain'] = v.get('Hostname'), v.get('Domain') or None
        interfaces = subkey(tcpip, 'Interfaces')
        for iface in (interfaces.iter_subkeys() if interfaces else []):
            iv = values(iface)
            dhcp = bool(iv.get('EnableDHCP'))
            pick = lambda name: _first(iv.get(('Dhcp' + name) if dhcp else name))  # static values are REG_MULTI_SZ
            ip = pick('IPAddress')
            if not ip or ip == '0.0.0.0':
                continue
            out['interfaces'].append({
                'guid': iface.name, 'dhcp': dhcp, 'ip': ip, 'subnet_mask': pick('SubnetMask'), 'gateway': pick('DefaultGateway'),
                'dhcp_server': iv.get('DhcpServer') if dhcp else None, 'domain': iv.get('DhcpDomain') or iv.get('Domain') or None,
                'lease_obtained': _iso(_epoch(iv.get('LeaseObtainedTime')))})
    tz = read_time_zone(reg, cs)
    out['time_zone'] = tz.to_dict() if tz else None
    return out


# -------------------------------------------------------------------------------------------- SOFTWARE
def parse_software(path) -> dict:
    out = {'status': 'COMPLETED', 'errors': [], 'os': {}, 'profiles': [], 'last_logged_on_user': None}
    try:
        reg = open_hive(path)
    except Exception as exc:
        return dict(out, status='FAILED', errors=[f'Not a readable SOFTWARE hive: {exc}'])
    cv = _key(reg, '\\Microsoft\\Windows NT\\CurrentVersion')
    if cv:
        v = values(cv)
        build = v.get('CurrentBuild') or v.get('CurrentBuildNumber')
        name = v.get('ProductName')
        # Windows 11 kept "Windows 10" in ProductName; the build number tells them apart (22000 and later).
        if name and 'Windows 10' in name and str(build or '').isdigit() and int(build) >= 22000:
            name = name.replace('Windows 10', 'Windows 11')
        install = _epoch(v.get('InstallDate'))
        if isinstance(v.get('InstallTime'), int):
            install = filetime_to_datetime(struct.pack('<Q', v['InstallTime'])) or install
        out['os'] = {'product_name': name, 'edition': v.get('EditionID'), 'display_version': v.get('DisplayVersion') or v.get('ReleaseId'),
                     'build': build, 'ubr': v.get('UBR'), 'version': v.get('CurrentVersion'), 'install_date': _iso(install),
                     'registered_owner': v.get('RegisteredOwner'), 'registered_organization': v.get('RegisteredOrganization') or None,
                     'system_root': v.get('SystemRoot')}
    pl = _key(reg, '\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList')
    for p in (pl.iter_subkeys() if pl else []):
        pv = values(p)
        loaded = None
        if isinstance(pv.get('LocalProfileLoadTimeHigh'), int) and isinstance(pv.get('LocalProfileLoadTimeLow'), int):
            loaded = filetime_to_datetime(struct.pack('<Q', (pv['LocalProfileLoadTimeHigh'] << 32) | pv['LocalProfileLoadTimeLow']))
        out['profiles'].append({'sid': p.name, 'profile_path': pv.get('ProfileImagePath'), 'last_loaded': _iso(loaded),
                                'well_known': WELL_KNOWN_PROFILES.get(p.name)})
    lu = _key(reg, '\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI')
    if lu:
        v = values(lu)
        out['last_logged_on_user'] = v.get('LastLoggedOnUser') or v.get('LastLoggedOnSAMUser')
        out['last_logged_on_sid'] = v.get('LastLoggedOnUserSID')
    return out


# ------------------------------------------------------------------------------------------------- SAM
def parse_sam_f(raw) -> dict:
    """The fixed-length F record of a SAM user: logon statistics and account flags."""
    b = as_bytes(raw) or b''
    if len(b) < 0x44:
        return {}
    ft = lambda off: _iso(filetime_to_datetime(b[off:off + 8]))
    acb = struct.unpack_from('<H', b, 0x38)[0]
    return {'last_logon': ft(0x08), 'password_last_set': ft(0x18), 'account_expires': ft(0x20), 'last_failed_logon': ft(0x28),
            'rid': struct.unpack_from('<I', b, 0x30)[0], 'flags': acb, 'disabled': bool(acb & ACB_DISABLED),
            'password_never_expires': bool(acb & ACB_PWNOEXP),
            'failed_logon_count': struct.unpack_from('<H', b, 0x40)[0], 'logon_count': struct.unpack_from('<H', b, 0x42)[0]}


def _v_string(b: bytes, entry: int) -> str | None:
    base = entry * 0x0C
    if len(b) < 0xCC or len(b) < base + 8:
        return None
    off, length = struct.unpack_from('<II', b, base)
    start = 0xCC + off
    if not length or start + length > len(b):
        return None
    return b[start:start + length].decode('utf-16-le', errors='replace')


def parse_sam_v(raw) -> dict:
    """The variable-length V record of a SAM user: user name, full name and comment."""
    b = as_bytes(raw) or b''
    return {'username': _v_string(b, 1), 'full_name': _v_string(b, 2) or None, 'comment': _v_string(b, 3) or None}


def machine_sid(raw) -> str | None:
    """The computer's SID from the SAM domain V record: its last 12 bytes are the three sub-authorities."""
    b = as_bytes(raw) or b''
    if len(b) < 12:
        return None
    a, c, d = struct.unpack_from('<III', b, len(b) - 12)
    return f'S-1-5-21-{a}-{c}-{d}'


def parse_sam(path) -> dict:
    out = {'status': 'COMPLETED', 'errors': [], 'machine_sid': None, 'users': []}
    try:
        reg = open_hive(path)
    except Exception as exc:
        return dict(out, status='FAILED', errors=[f'Not a readable SAM hive: {exc}'])
    account = _key(reg, '\\SAM\\Domains\\Account')
    if not account:
        return dict(out, status='FAILED', errors=['No SAM\\Domains\\Account key'])
    out['machine_sid'] = machine_sid(values(account).get('V'))
    users = subkey(account, 'Users')
    for k in (users.iter_subkeys() if users else []):
        if k.name.lower() == 'names':
            continue
        try:
            rid = int(k.name, 16)
        except ValueError:
            continue
        v = values(k)
        user = {'rid': rid, **parse_sam_v(v.get('V')), **parse_sam_f(v.get('F'))}
        user['rid'] = rid
        user['sid'] = f'{out["machine_sid"]}-{rid}' if out['machine_sid'] else None
        out['users'].append(user)
    out['users'].sort(key=lambda u: u['rid'])
    return out


def accounts(sam: dict, software: dict) -> list[dict]:
    """User accounts from SAM, joined with SOFTWARE profiles by SID; profiles without a local account (domain or
    Microsoft accounts) are listed too."""
    profiles = {p['sid']: p for p in software.get('profiles', [])}
    out = []
    for u in sam.get('users', []):
        p = profiles.pop(u.get('sid'), None) or {}
        out.append(dict(u, profile_path=p.get('profile_path'), profile_last_loaded=p.get('last_loaded'), source='SAM'))
    for sid, p in profiles.items():
        if p.get('well_known'):
            continue
        name = (p.get('profile_path') or '').replace('/', '\\').rstrip('\\').rsplit('\\', 1)[-1] or None
        out.append({'sid': sid, 'username': name, 'profile_path': p.get('profile_path'), 'profile_last_loaded': p.get('last_loaded'),
                    'source': 'PROFILE_LIST'})
    return out
