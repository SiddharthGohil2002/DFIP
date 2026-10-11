"""Writes the test disk's registry hives (SYSTEM, SOFTWARE, SAM) for the scenario computer, with hivex.

The computer is LAPTOP-07, a Windows 10 Pro laptop in the US Eastern time zone, used by "alice" (RID 1001;
her SID matches the Recycle Bin folder). The HP v100w USB stick and its drive letter are copied key for key from
the real Windows 7 SYSTEM hive in backend/tests/fixtures/SYSTEM.xz (regipy test data, MIT), so USB parsing is still
tested on data Windows wrote; the SanDisk drive stays known only from setupapi.dev.log, as before.

Written by hivex (libguestfs), read by DFIP with regipy and checked by the tests with libregf: three independent
implementations of the format. Runs with Debian's python3 and python3-hivex:

    /usr/bin/python3 make_hives.py <tree> backend/tests/fixtures/SYSTEM.xz
"""
import lzma
import struct
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import hivex

from regf_base import empty_hive

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 0, 1, 2, 3, 4, 7, 11
MACHINE = (3623811015, 3361044348, 30300820)          # S-1-5-21-3623811015-3361044348-30300820
ALICE_SID = 'S-1-5-21-{}-{}-{}-1001'.format(*MACHINE)
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


def sz(s):
    return (s + '\0').encode('utf-16-le')


def multi(*items):
    return b''.join(sz(i) for i in items) + b'\0\0'


def dword(n):
    return struct.pack('<I', n & 0xFFFFFFFF)


def filetime_int(dt):
    return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


def filetime(dt):
    return struct.pack('<Q', filetime_int(dt))


def systemtime_rule(month, week, weekday, hour):
    """A recurring TimeZoneInformation transition: wYear 0, wMonth, wDayOfWeek, wDay = week (5 = last), wHour."""
    return struct.pack('<8H', 0, month, weekday, week, hour, 0, 0, 0)


def binary_sid(*subs, authority=5):
    return struct.pack('<BB', 1, len(subs)) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


class Hive:
    def __init__(self, path: Path):
        path.write_bytes(empty_hive())
        self.path = path
        self.h = hivex.Hivex(str(path), write=True)

    def node(self, key: str):
        n = self.h.root()
        for part in [p for p in key.split('\\') if p]:
            child = self.h.node_get_child(n, part)
            n = child if child else self.h.node_add_child(n, part)
        return n

    def set(self, key: str, **vals):
        """Sets values (name=(type, bytes)); '_default' is the key's default value."""
        n = self.node(key)
        for name, (t, data) in vals.items():
            self.h.node_set_value(n, {'key': '' if name == '_default' else name, 't': t, 'value': data})
        return n

    def copy_from(self, src, src_key: str, dst_key: str):
        """Copies a subtree, keys and values byte for byte, from another (hivex) hive."""
        s = src.root()
        for part in [p for p in src_key.split('\\') if p]:
            s = src.node_get_child(s, part)
            if not s:
                raise KeyError(src_key)
        self._copy(src, s, self.node(dst_key))

    def _copy(self, src, s, d):
        vals = [{'key': src.value_key(v), 't': src.value_type(v)[0], 'value': src.value_value(v)[1]} for v in src.node_values(s)]
        if vals:
            self.h.node_set_values(d, vals)
        for c in src.node_children(s):
            self._copy(src, c, self.h.node_add_child(d, src.node_name(c)))

    def commit(self):
        self.h.commit(str(self.path))


def system_hive(path: Path, real_system: Path):
    hv = Hive(path)
    with tempfile.NamedTemporaryFile(suffix='.hive') as t:
        t.write(lzma.decompress(real_system.read_bytes()))
        t.flush()
        real = hivex.Hivex(t.name)
        hv.copy_from(real, 'ControlSet001\\Enum\\USBSTOR', 'ControlSet001\\Enum\\USBSTOR')
        hv.copy_from(real, 'ControlSet001\\Enum\\USB', 'ControlSet001\\Enum\\USB')
        hv.copy_from(real, 'MountedDevices', 'MountedDevices')
    hv.set('Select', Current=(REG_DWORD, dword(1)), Default=(REG_DWORD, dword(1)), LastKnownGood=(REG_DWORD, dword(1)),
           Failed=(REG_DWORD, dword(0)))
    cs = 'ControlSet001'
    hv.set(f'{cs}\\Control\\ComputerName\\ComputerName', ComputerName=(REG_SZ, sz('LAPTOP-07')))
    hv.set(f'{cs}\\Control\\ComputerName\\ActiveComputerName', ComputerName=(REG_SZ, sz('LAPTOP-07')))
    # US Eastern: UTC = local + 300 min (standard) / + 240 min (daylight, 2nd Sunday of March to 1st Sunday of November).
    hv.set(f'{cs}\\Control\\TimeZoneInformation',
           Bias=(REG_DWORD, dword(300)), StandardName=(REG_SZ, sz('@tzres.dll,-112')), StandardBias=(REG_DWORD, dword(0)),
           StandardStart=(REG_BINARY, systemtime_rule(11, 1, 0, 2)), DaylightName=(REG_SZ, sz('@tzres.dll,-111')),
           DaylightBias=(REG_DWORD, dword(-60)), DaylightStart=(REG_BINARY, systemtime_rule(3, 2, 0, 2)),
           ActiveTimeBias=(REG_DWORD, dword(240)), TimeZoneKeyName=(REG_SZ, sz('Eastern Standard Time')),
           DynamicDaylightTimeDisabled=(REG_DWORD, dword(0)))
    hv.set(f'{cs}\\Control\\Windows', ShutdownTime=(REG_BINARY, filetime(utc(2026, 9, 1, 18, 42, 10))))
    hv.set(f'{cs}\\Services\\Tcpip\\Parameters', Hostname=(REG_SZ, sz('LAPTOP-07')), Domain=(REG_SZ, sz('')))
    hv.set(f'{cs}\\Services\\Tcpip\\Parameters\\Interfaces\\{{6BC5E8A2-1F3D-4C0B-9A7E-2D4F8B1C0E57}}',
           EnableDHCP=(REG_DWORD, dword(1)), DhcpIPAddress=(REG_SZ, sz('192.168.1.57')),
           DhcpSubnetMask=(REG_SZ, sz('255.255.255.0')), DhcpServer=(REG_SZ, sz('192.168.1.1')),
           DhcpDefaultGateway=(REG_MULTI_SZ, multi('192.168.1.1')), DhcpDomain=(REG_SZ, sz('corp.example')),
           LeaseObtainedTime=(REG_DWORD, dword(int(utc(2026, 9, 1, 13, 5).timestamp()))))
    hv.set(f'{cs}\\Services\\Tcpip\\Parameters\\Interfaces\\{{0D1C2B3A-4E5F-4A6B-8C7D-9E0F1A2B3C4D}}',
           EnableDHCP=(REG_DWORD, dword(0)), IPAddress=(REG_MULTI_SZ, multi('0.0.0.0')))  # an unused adapter
    hv.commit()


def software_hive(path: Path):
    hv = Hive(path)
    cv = 'Microsoft\\Windows NT\\CurrentVersion'
    installed = utc(2024, 3, 2, 9, 15)
    hv.set(cv, ProductName=(REG_SZ, sz('Windows 10 Pro')), EditionID=(REG_SZ, sz('Professional')),
           DisplayVersion=(REG_SZ, sz('22H2')), CurrentBuild=(REG_SZ, sz('19045')), CurrentBuildNumber=(REG_SZ, sz('19045')),
           UBR=(REG_DWORD, dword(4780)), CurrentVersion=(REG_SZ, sz('6.3')), SystemRoot=(REG_SZ, sz('C:\\Windows')),
           InstallDate=(REG_DWORD, dword(int(installed.timestamp()))), InstallTime=(REG_QWORD, struct.pack('<Q', filetime_int(installed))),
           RegisteredOwner=(REG_SZ, sz('alice')), RegisteredOrganization=(REG_SZ, sz('Corp Example')))
    for sid, path_ in (('S-1-5-18', '%systemroot%\\system32\\config\\systemprofile'),
                       ('S-1-5-19', '%systemroot%\\ServiceProfiles\\LocalService'),
                       ('S-1-5-20', '%systemroot%\\ServiceProfiles\\NetworkService')):
        hv.set(f'{cv}\\ProfileList\\{sid}', ProfileImagePath=(REG_EXPAND_SZ, sz(path_)))
    loaded = filetime_int(utc(2026, 9, 1, 13, 28, 45))
    hv.set(f'{cv}\\ProfileList\\{ALICE_SID}', ProfileImagePath=(REG_EXPAND_SZ, sz('C:\\Users\\alice')),
           Sid=(REG_BINARY, binary_sid(21, *MACHINE, 1001)), State=(REG_DWORD, dword(0)),
           LocalProfileLoadTimeHigh=(REG_DWORD, dword(loaded >> 32)), LocalProfileLoadTimeLow=(REG_DWORD, dword(loaded & 0xFFFFFFFF)))
    hv.set('Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI',
           LastLoggedOnUser=(REG_SZ, sz('.\\alice')), LastLoggedOnSAMUser=(REG_SZ, sz('.\\alice')),
           LastLoggedOnUserSID=(REG_SZ, sz(ALICE_SID)))
    hv.commit()


def sam_v(username, full_name='', comment=''):
    """A SAM user V record: 17 (offset, length, unknown) entries (0xCC bytes), then the UTF-16 strings."""
    blobs = [b'', username.encode('utf-16-le'), full_name.encode('utf-16-le'), comment.encode('utf-16-le')] + [b''] * 13
    header, data = bytearray(0xCC), bytearray()
    for i, blob in enumerate(blobs):
        struct.pack_into('<III', header, i * 12, len(data), len(blob), 0)
        data += blob + b'\0' * (-len(blob) % 4)
    return bytes(header + data)


NEVER = 0x7FFFFFFFFFFFFFFF


def sam_f(rid, acb, logons=0, last_logon=None, password_set=None, failed=0, last_failed=None):
    """A SAM user F record (0x50 bytes): logon times, RID, account flags and counters."""
    b = bytearray(0x50)
    struct.pack_into('<HH', b, 0, 2, 1)
    struct.pack_into('<Q', b, 0x08, filetime_int(last_logon) if last_logon else 0)
    struct.pack_into('<Q', b, 0x18, filetime_int(password_set) if password_set else 0)
    struct.pack_into('<Q', b, 0x20, NEVER)
    struct.pack_into('<Q', b, 0x28, filetime_int(last_failed) if last_failed else 0)
    struct.pack_into('<IH', b, 0x30, rid, 0)
    struct.pack_into('<H', b, 0x38, acb)
    struct.pack_into('<HH', b, 0x40, failed, logons)
    return bytes(b)


USERS = [  # (rid, name, full name, comment, ACB flags, logons, last logon, password last set)
    (500, 'Administrator', '', 'Built-in account for administering the computer/domain', 0x0211, 3,
     utc(2024, 3, 2, 9, 40), utc(2024, 3, 2, 9, 20)),
    (501, 'Guest', '', 'Built-in account for guest access to the computer/domain', 0x0215, 0, None, None),
    (503, 'DefaultAccount', '', 'A user account managed by the system.', 0x0211, 0, None, None),
    (504, 'WDAGUtilityAccount', '', 'A user account managed and used by the system for Windows Defender Application Guard scenarios.',
     0x0211, 0, None, utc(2024, 3, 2, 9, 16)),
    (1001, 'alice', 'Alice Example', '', 0x0210, 214, utc(2026, 9, 1, 13, 28, 40), utc(2026, 3, 2, 10, 0)),
]


def sam_hive(path: Path):
    hv = Hive(path)
    hv.set('SAM\\Domains\\Account', F=(REG_BINARY, bytes(0x50)),
           V=(REG_BINARY, bytes(0x40) + binary_sid(21, *MACHINE)))  # the machine SID ends the domain V record
    for rid, name, full, comment, acb, logons, last, pwd in USERS:
        hv.set(f'SAM\\Domains\\Account\\Users\\{rid:08X}', F=(REG_BINARY, sam_f(rid, acb, logons, last, pwd)),
               V=(REG_BINARY, sam_v(name, full, comment)))
        hv.set(f'SAM\\Domains\\Account\\Users\\Names\\{name}', _default=(rid, b''))  # the value type is the RID
    hv.commit()


def main():
    tree, real_system = Path(sys.argv[1]), Path(sys.argv[2])
    config = tree / 'Windows' / 'System32' / 'config'
    config.mkdir(parents=True, exist_ok=True)
    system_hive(config / 'SYSTEM', real_system)
    software_hive(config / 'SOFTWARE')
    sam_hive(config / 'SAM')
    print('Hives:', ', '.join(f'{p.name} ({p.stat().st_size:,} bytes)' for p in sorted(config.iterdir())))


if __name__ == '__main__':
    main()
