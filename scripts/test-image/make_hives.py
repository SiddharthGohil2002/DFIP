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

import codecs
import hashlib

import hivex

from regf_base import empty_hive, set_key_times

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'backend' / 'tests' / 'fixtures'))
import winfmt  # noqa: E402  (shell items, shared with the backend unit tests)

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
    d = dt - EPOCH_1601  # integer arithmetic: a float would land a fraction short of the second
    return (d.days * 86_400 + d.seconds) * 10_000_000 + d.microseconds * 10


def filetime(dt):
    return struct.pack('<Q', filetime_int(dt))


def systemtime_rule(month, week, weekday, hour):
    """A recurring TimeZoneInformation transition: wYear 0, wMonth, wDayOfWeek, wDay = week (5 = last), wHour."""
    return struct.pack('<8H', 0, month, weekday, week, hour, 0, 0, 0)


def binary_sid(*subs, authority=5):
    return struct.pack('<BB', 1, len(subs)) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


class Hive:
    def __init__(self, path: Path, file_name: str = ''):
        path.write_bytes(empty_hive(file_name=file_name))
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
    hv = Hive(path, '\\SystemRoot\\System32\\Config\\SYSTEM')
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
    hv = Hive(path, '\\SystemRoot\\System32\\Config\\SOFTWARE')
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
    hv = Hive(path, '\\SystemRoot\\System32\\Config\\SAM')
    hv.set('SAM\\Domains\\Account', F=(REG_BINARY, bytes(0x50)),
           V=(REG_BINARY, bytes(0x40) + binary_sid(21, *MACHINE)))  # the machine SID ends the domain V record
    for rid, name, full, comment, acb, logons, last, pwd in USERS:
        hv.set(f'SAM\\Domains\\Account\\Users\\{rid:08X}', F=(REG_BINARY, sam_f(rid, acb, logons, last, pwd)),
               V=(REG_BINARY, sam_v(name, full, comment)))
        hv.set(f'SAM\\Domains\\Account\\Users\\Names\\{name}', _default=(rid, b''))  # the value type is the RID
    hv.commit()


# ---------------------------------------------------------------- Phase 5: user activity, programs and persistence
# Everything below tells the same story as the rest of the test disk (2026-09-01, all times UTC): alice downloads and
# runs SecureDelete.exe, browses the SanDisk drive (E:\Exports), searches Explorer for "payroll", opens the export, and
# sets up persistence for an "updater".
SECUREDELETE_SHA1 = hashlib.sha1(b'SecureDelete.exe 1.4.0 test binary').hexdigest()
CS = 'ControlSet001'
EXPLORER = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer'
UA_EXE = f'{EXPLORER}\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count'
DOWNLOADS = '{374DE290-123F-4565-9164-39C4925E467B}'   # KnownFolderID of the user's Downloads folder
SYSTEM32 = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}'    # KnownFolderID of System32
USERASSIST = [  # (name as stored before ROT13, run count, focus count, focus time ms, last run)
    (f'{DOWNLOADS}\\SecureDelete.exe', 2, 3, 41_000, utc(2026, 9, 1, 14, 18, 30)),
    (f'{SYSTEM32}\\notepad.exe', 5, 7, 312_000, utc(2026, 9, 1, 14, 13, 40)),
]
TYPED_PATHS = ['E:\\Exports', 'C:\\Users\\alice\\Documents']           # url1 is the most recent
WORDWHEEL = {0: 'usb wipe', 1: 'payroll'}                               # value name -> search term
WORDWHEEL_ORDER = [1, 0]                                                # most recent first
RECENT_DOCS = {0: 'payroll-export.csv', 1: 'q3-payroll.docx'}
RECENT_ORDER = [0, 1]
RUN_MRU = {'a': 'cmd', 'b': 'powershell -ExecutionPolicy Bypass -File C:\\Users\\alice\\Downloads\\cleanup.ps1'}
RUN_MRU_ORDER = 'ba'
NTUSER_RUN = {'Updater': 'C:\\Users\\alice\\AppData\\Roaming\\updater.exe -silent'}
RDP_SERVER, RDP_USER = 'fileserver.corp.example', 'CORP\\alice'
NETWORK_DRIVE = ('Z', '\\\\fileserver.corp.example\\finance')
BAM = [('\\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\SecureDelete.exe', utc(2026, 9, 1, 14, 18, 31)),
       ('\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe', utc(2026, 9, 1, 14, 13, 41))]
SHIMCACHE = [('C:\\Users\\alice\\Downloads\\SecureDelete.exe', utc(2026, 8, 14, 9, 12, 33)),
             ('C:\\Windows\\System32\\notepad.exe', utc(2024, 3, 2, 9, 30, 10))]
SERVICES = {  # name -> (ImagePath, Start, DisplayName)
    'SecureDeleteSvc': ('C:\\Users\\alice\\AppData\\Roaming\\sdsvc.exe', 2, 'Secure Delete Helper'),
    'Spooler': ('%SystemRoot%\\System32\\spoolsv.exe', 2, 'Print Spooler'),
}
SOFTWARE_RUN = {'SecurityHealth': '%windir%\\system32\\SecurityHealthSystray.exe'}
SOFTWARE_RUNONCE = {'Cleanup': 'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA='}
UNINSTALL = {  # key -> values
    'SecureDelete': {'DisplayName': 'SecureDelete 1.4', 'DisplayVersion': '1.4.0', 'Publisher': 'Example Tools',
                     'InstallDate': '20260901', 'InstallLocation': 'C:\\Program Files\\SecureDelete',
                     'UninstallString': '"C:\\Program Files\\SecureDelete\\uninstall.exe"'},
    '7-Zip': {'DisplayName': '7-Zip 23.01 (x64)', 'DisplayVersion': '23.01', 'Publisher': 'Igor Pavlov', 'InstallDate': '20240305',
              'InstallLocation': 'C:\\Program Files\\7-Zip\\', 'UninstallString': '"C:\\Program Files\\7-Zip\\Uninstall.exe"'},
}
IFEO = {'sethc.exe': 'C:\\Windows\\System32\\cmd.exe'}  # the "sticky keys" backdoor
SHELLBAG_E = utc(2026, 9, 1, 14, 13, 2)                  # E:\ and E:\Exports last browsed


def mru_list_ex(order):
    return b''.join(struct.pack('<I', i) for i in order) + b'\xff\xff\xff\xff'


def userassist_value(run_count, focus_count, focus_ms, last_run):
    """Windows 7+ UserAssist data (72 bytes): session, run count, focus count, focus time, ..., last run FILETIME at 60."""
    b = bytearray(72)
    struct.pack_into('<IIII', b, 0, 0, run_count, focus_count, focus_ms)
    struct.pack_into('<Q', b, 60, filetime_int(last_run))
    return bytes(b)


def appcompatcache_win10(entries):
    """Windows 10 (Creators Update and later) AppCompatCache: a 0x34-byte header, then '10ts' entries."""
    header = bytearray(0x34)
    struct.pack_into('<I', header, 0, 0x34)
    out = bytes(header)
    for path, modified in entries:
        p = path.encode('utf-16-le')
        data = struct.pack('<H', len(p)) + p + struct.pack('<QI', filetime_int(modified), 0)
        out += b'10ts' + struct.pack('<II', 0, len(data)) + data
    return out


def add_system_activity(path: Path):
    """BAM, ShimCache and services on the SYSTEM hive written by system_hive()."""
    h = hivex.Hivex(str(path), write=True)
    hv = Hive.__new__(Hive)
    hv.path, hv.h = path, h
    for exe, when in BAM:
        hv.set(f'{CS}\\Services\\bam\\State\\UserSettings\\{ALICE_SID}', **{exe: (REG_BINARY, filetime(when) + bytes(16))})
    hv.set(f'{CS}\\Services\\bam\\State\\UserSettings\\{ALICE_SID}', Version=(REG_DWORD, dword(1)), SequenceNumber=(REG_DWORD, dword(9)))
    hv.set(f'{CS}\\Control\\Session Manager\\AppCompatCache', AppCompatCache=(REG_BINARY, appcompatcache_win10(SHIMCACHE)))
    for name, (image, start, display) in SERVICES.items():
        hv.set(f'{CS}\\Services\\{name}', ImagePath=(REG_EXPAND_SZ, sz(image)), Start=(REG_DWORD, dword(start)),
               Type=(REG_DWORD, dword(0x10)), DisplayName=(REG_SZ, sz(display)), ObjectName=(REG_SZ, sz('LocalSystem')))
    hv.commit()
    set_key_times(path, {f'{CS}\\Services\\bam\\State\\UserSettings\\{ALICE_SID}': utc(2026, 9, 1, 14, 18, 31),
                         f'{CS}\\Control\\Session Manager\\AppCompatCache': utc(2026, 9, 1, 18, 42, 9),
                         f'{CS}\\Services\\SecureDeleteSvc': utc(2026, 9, 1, 10, 7, 30),
                         f'{CS}\\Services\\Spooler': utc(2024, 3, 2, 9, 20)})


def add_software_activity(path: Path):
    """Run keys, installed programs and an Image File Execution Options debugger on the SOFTWARE hive."""
    h = hivex.Hivex(str(path), write=True)
    hv = Hive.__new__(Hive)
    hv.path, hv.h = path, h
    hv.set('Microsoft\\Windows\\CurrentVersion\\Run', **{k: (REG_SZ, sz(v)) for k, v in SOFTWARE_RUN.items()})
    hv.set('Microsoft\\Windows\\CurrentVersion\\RunOnce', **{k: (REG_SZ, sz(v)) for k, v in SOFTWARE_RUNONCE.items()})
    for key, vals in UNINSTALL.items():
        hv.set(f'Microsoft\\Windows\\CurrentVersion\\Uninstall\\{key}', **{k: (REG_SZ, sz(v)) for k, v in vals.items()})
    for exe, debugger in IFEO.items():
        hv.set(f'Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{exe}', Debugger=(REG_SZ, sz(debugger)))
    hv.commit()
    set_key_times(path, {'Microsoft\\Windows\\CurrentVersion\\Run': utc(2024, 3, 2, 9, 25),
                         'Microsoft\\Windows\\CurrentVersion\\RunOnce': utc(2026, 9, 1, 10, 7, 10),
                         'Microsoft\\Windows\\CurrentVersion\\Uninstall\\SecureDelete': utc(2026, 9, 1, 10, 5, 40),
                         'Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip': utc(2024, 3, 5, 11, 0),
                         'Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe': utc(2026, 9, 1, 10, 8, 15)})


def utf16z(s):
    return s.encode('utf-16-le') + b'\0\0'


def ntuser_hive(path: Path):
    hv = Hive(path, '\\??\\C:\\Users\\alice\\ntuser.dat')
    hv.set(UA_EXE, **{codecs.encode(name, 'rot13'): (REG_BINARY, userassist_value(rc, fc, fms, last))
                      for name, rc, fc, fms, last in USERASSIST})
    hv.set(f'{EXPLORER}\\TypedPaths', **{f'url{i}': (REG_SZ, sz(p)) for i, p in enumerate(TYPED_PATHS, 1)})
    hv.set(f'{EXPLORER}\\WordWheelQuery', MRUListEx=(REG_BINARY, mru_list_ex(WORDWHEEL_ORDER)),
           **{str(i): (REG_BINARY, utf16z(t)) for i, t in WORDWHEEL.items()})
    # RecentDocs values: the file name (UTF-16), then the shell item of its shortcut, which DFIP does not need.
    recent = {str(i): (REG_BINARY, utf16z(n) + b'\x14\x00\x32\x00' + bytes(16)) for i, n in RECENT_DOCS.items()}
    hv.set(f'{EXPLORER}\\RecentDocs', MRUListEx=(REG_BINARY, mru_list_ex(RECENT_ORDER)), **recent)
    hv.set(f'{EXPLORER}\\RecentDocs\\.csv', MRUListEx=(REG_BINARY, mru_list_ex([0])), **{'0': recent['0']})
    hv.set(f'{EXPLORER}\\RecentDocs\\.docx', MRUListEx=(REG_BINARY, mru_list_ex([0])), **{'0': recent['1']})
    hv.set(f'{EXPLORER}\\RunMRU', MRUList=(REG_SZ, sz(RUN_MRU_ORDER)), **{k: (REG_SZ, sz(v + '\\1')) for k, v in RUN_MRU.items()})
    hv.set('Software\\Microsoft\\Windows\\CurrentVersion\\Run', **{k: (REG_SZ, sz(v)) for k, v in NTUSER_RUN.items()})
    hv.set('Software\\Microsoft\\Terminal Server Client\\Default', MRU0=(REG_SZ, sz(RDP_SERVER)))
    hv.set(f'Software\\Microsoft\\Terminal Server Client\\Servers\\{RDP_SERVER}', UsernameHint=(REG_SZ, sz(RDP_USER)))
    letter, remote = NETWORK_DRIVE
    hv.set(f'Network\\{letter}', RemotePath=(REG_SZ, sz(remote)), UserName=(REG_SZ, sz(RDP_USER)),
           ProviderName=(REG_SZ, sz('Microsoft Windows Network')), ConnectionType=(REG_DWORD, dword(1)))
    hv.commit()
    set_key_times(path, {UA_EXE: utc(2026, 9, 1, 14, 18, 30), f'{EXPLORER}\\TypedPaths': utc(2026, 9, 1, 14, 12, 50),
                         f'{EXPLORER}\\WordWheelQuery': utc(2026, 9, 1, 14, 12, 55), f'{EXPLORER}\\RecentDocs': utc(2026, 9, 1, 14, 14, 6),
                         f'{EXPLORER}\\RecentDocs\\.csv': utc(2026, 9, 1, 14, 14, 6), f'{EXPLORER}\\RecentDocs\\.docx': utc(2026, 8, 31, 16, 50),
                         f'{EXPLORER}\\RunMRU': utc(2026, 9, 1, 10, 6, 10), 'Software\\Microsoft\\Windows\\CurrentVersion\\Run': utc(2026, 9, 1, 10, 7),
                         f'Software\\Microsoft\\Terminal Server Client\\Servers\\{RDP_SERVER}': utc(2026, 9, 1, 13, 40),
                         f'Network\\{letter}': utc(2026, 9, 1, 13, 35)},
                  default=utc(2026, 9, 1, 13, 28, 45))  # other keys: the logon


def usrclass_hive(path: Path):
    """ShellBags: This PC > E:\\ > Exports."""
    hv = Hive(path, '\\??\\C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat')
    bags = 'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU'
    hv.set(bags, MRUListEx=(REG_BINARY, mru_list_ex([0])), **{'0': (REG_BINARY, winfmt.id_list(winfmt.shell_item_root()))},
           NodeSlots=(REG_BINARY, b'\x02'))
    hv.set(f'{bags}\\0', MRUListEx=(REG_BINARY, mru_list_ex([0])), **{'0': (REG_BINARY, winfmt.id_list(winfmt.shell_item_volume('E:\\')))},
           NodeSlot=(REG_DWORD, dword(1)))
    hv.set(f'{bags}\\0\\0', MRUListEx=(REG_BINARY, mru_list_ex([0])), NodeSlot=(REG_DWORD, dword(2)),
           **{'0': (REG_BINARY, winfmt.id_list(winfmt.shell_item_directory('Exports', 'EXPORTS', utc(2026, 9, 1, 9, 41, 2),
                                                                         utc(2026, 8, 30, 9, 0), SHELLBAG_E, 41, 2)))})
    hv.set(f'{bags}\\0\\0\\0', NodeSlot=(REG_DWORD, dword(3)))
    hv.commit()
    set_key_times(path, {bags: SHELLBAG_E, f'{bags}\\0': SHELLBAG_E, f'{bags}\\0\\0': SHELLBAG_E, f'{bags}\\0\\0\\0': SHELLBAG_E},
                  default=utc(2026, 9, 1, 13, 28, 45))


def amcache_hive(path: Path):
    """Windows 10 Amcache: Root\\InventoryApplicationFile entries with SHA-1 (FileId), path, size and link date."""
    hv = Hive(path, '\\??\\C:\\Windows\\AppCompat\\Programs\\Amcache.hve')
    files = 'Root\\InventoryApplicationFile'
    hv.set(f'{files}\\securedelete.exe|5b3c8f2a9d1e4c70', ProgramId=(REG_SZ, sz('0006f1a2b3c4d5e6f708192a3b4c5d6e7f800000ffff')),
           FileId=(REG_SZ, sz('0000' + SECUREDELETE_SHA1)), LowerCaseLongPath=(REG_SZ, sz('c:\\users\\alice\\downloads\\securedelete.exe')),
           LongPathHash=(REG_SZ, sz('securedelete.exe|5b3c8f2a9d1e4c70')), Name=(REG_SZ, sz('SecureDelete.exe')),
           OriginalFileName=(REG_SZ, sz('securedelete.exe')), Publisher=(REG_SZ, sz('example tools')), Version=(REG_SZ, sz('1.4.0')),
           BinFileVersion=(REG_SZ, sz('1.4.0.0')), BinaryType=(REG_SZ, sz('pe32_i386')), ProductName=(REG_SZ, sz('securedelete')),
           ProductVersion=(REG_SZ, sz('1.4.0')), LinkDate=(REG_SZ, sz('08/14/2026 09:12:33')), BinProductVersion=(REG_SZ, sz('1.4.0.0')),
           Size=(REG_QWORD, struct.pack('<Q', 482_304)), Language=(REG_DWORD, dword(0)), IsPeFile=(REG_DWORD, dword(1)),
           IsOsComponent=(REG_DWORD, dword(0)))
    hv.commit()
    set_key_times(path, {f'{files}\\securedelete.exe|5b3c8f2a9d1e4c70': utc(2026, 9, 1, 10, 6, 2)}, default=utc(2026, 9, 1, 10, 6, 2))


def main():
    tree, real_system = Path(sys.argv[1]), Path(sys.argv[2])
    config = tree / 'Windows' / 'System32' / 'config'
    config.mkdir(parents=True, exist_ok=True)
    system_hive(config / 'SYSTEM', real_system)
    add_system_activity(config / 'SYSTEM')
    software_hive(config / 'SOFTWARE')
    add_software_activity(config / 'SOFTWARE')
    sam_hive(config / 'SAM')
    alice = tree / 'Users' / 'alice'
    ntuser_hive(alice / 'NTUSER.DAT')
    (alice / 'AppData' / 'Local' / 'Microsoft' / 'Windows').mkdir(parents=True, exist_ok=True)
    usrclass_hive(alice / 'AppData' / 'Local' / 'Microsoft' / 'Windows' / 'UsrClass.dat')
    (tree / 'Windows' / 'AppCompat' / 'Programs').mkdir(parents=True, exist_ok=True)
    amcache_hive(tree / 'Windows' / 'AppCompat' / 'Programs' / 'Amcache.hve')
    print('Hives:', ', '.join(f'{p.name} ({p.stat().st_size:,} bytes)' for p in sorted(config.iterdir())))


if __name__ == '__main__':
    main()
