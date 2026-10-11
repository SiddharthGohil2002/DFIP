"""Registry activity: known folders, device paths, persistence flags, MRU decoding and the execution evidence merge."""
import struct

import pytest

from app.forensic import user_registry as ur
from app.forensic.execution import merge


def test_known_folders_are_resolved_with_the_users_profile():
    assert ur.resolve_known_folder('{374DE290-123F-4565-9164-39C4925E467B}\\SecureDelete.exe', 'C:\\Users\\alice') == \
        'C:\\Users\\alice\\Downloads\\SecureDelete.exe'
    assert ur.resolve_known_folder('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe', None) == 'C:\\Windows\\System32\\notepad.exe'
    assert ur.resolve_known_folder('%SYSTEM32%\\cmd.exe', None) == 'C:\\Windows\\System32\\cmd.exe'
    # A user-relative folder without a known profile stays as recorded.
    assert ur.resolve_known_folder('{374DE290-123F-4565-9164-39C4925E467B}\\x.exe', None) == '{374DE290-123F-4565-9164-39C4925E467B}\\x.exe'
    assert ur.resolve_known_folder('Microsoft.Windows.Explorer', 'C:\\Users\\a') == 'Microsoft.Windows.Explorer'


def test_device_paths():
    assert ur.device_to_path('\\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\SecureDelete.exe') == '\\Users\\alice\\Downloads\\SecureDelete.exe'


@pytest.mark.parametrize('command,flagged', [
    ('C:\\Users\\alice\\AppData\\Roaming\\updater.exe -silent', True),
    ('powershell.exe -NoProfile -EncodedCommand SQBFAFgA', True),
    ('powershell -w hidden -c iex', True),
    ('rundll32.exe C:\\ProgramData\\x.dll,Start', True),
    ('mshta http://example.org/a.hta', True),
    ('%windir%\\system32\\SecurityHealthSystray.exe', False),
    ('"C:\\Program Files\\7-Zip\\7zFM.exe"', False),
])
def test_command_flags(command, flagged):
    assert bool(ur.flag_command(command)) is flagged


def test_persistence_flags_for_debuggers_and_winlogon():
    assert ur.persistence_flags({'kind': 'IFEO debugger', 'command': 'C:\\Windows\\System32\\cmd.exe'})[0].startswith('a debugger')
    assert ur.persistence_flags({'kind': 'Winlogon', 'command': 'explorer.exe, evil.exe', 'not_default': True})[0] == 'differs from the Windows default'
    assert ur.persistence_flags({'kind': 'Run', 'command': 'C:\\Windows\\System32\\ctfmon.exe'}) == []


def test_mru_list_and_names():
    raw = struct.pack('<III', 1, 0, 0xFFFFFFFF)
    assert ur._mru_order(raw) == [1, 0] and ur._mru_order(raw.hex()) == [1, 0] and ur._mru_order(b'') == []
    data = 'payroll-export.csv'.encode('utf-16-le') + b'\0\0' + b'\x14\x00\x32\x00' + bytes(16)
    assert ur._utf16_name(data) == 'payroll-export.csv' and ur._utf16_name(None) is None


PREFETCH = [{'executable': 'SECUREDELETE.EXE', 'executable_path': '\\VOLUME{x}\\USERS\\ALICE\\DOWNLOADS\\SECUREDELETE.EXE', 'run_count': 2,
             'last_run_times': ['2026-09-01T14:18:30+00:00', '2026-09-01T10:06:02+00:00'], 'evidence_id': 'E1'}]
USERASSIST = [{'program': 'C:\\Users\\alice\\Downloads\\SecureDelete.exe', 'run_count': 2, 'last_run': '2026-09-01T14:18:30+00:00',
               'user': 'alice', 'evidence_id': 'E1'},
              {'program': 'C:\\Windows\\System32\\notepad.exe', 'run_count': 5, 'last_run': '2026-09-01T14:13:40+00:00', 'user': 'alice',
               'evidence_id': 'E1'}]
BAM = [{'path': '\\Users\\alice\\Downloads\\SecureDelete.exe', 'last_run': '2026-09-01T14:18:31+00:00', 'user': 'alice', 'evidence_id': 'E1'}]
AMCACHE = [{'path': 'c:\\users\\alice\\downloads\\securedelete.exe', 'name': 'SecureDelete.exe', 'sha1': 'ab' * 20,
            'key_last_write': '2026-09-01T10:06:02+00:00', 'evidence_id': 'E1'}]
SHIM = [{'path': 'C:\\Users\\alice\\Downloads\\SecureDelete.exe', 'last_modified': '2026-08-14T09:12:33+00:00', 'position': 0, 'evidence_id': 'E1'},
        {'path': 'C:\\Tools\\never-ran.exe', 'last_modified': '2025-01-01T00:00:00+00:00', 'position': 1, 'evidence_id': 'E1'}]


def test_execution_evidence_merges_every_trace_of_a_program():
    rows = {r['program'].lower(): r for r in merge(PREFETCH, USERASSIST, BAM, AMCACHE, SHIM)}
    sd = rows['securedelete.exe']
    assert sd['program'] == 'SecureDelete.exe'  # the mixed-case name wins over Prefetch's upper case
    assert sd['sources'] == ['prefetch', 'userassist', 'bam', 'amcache', 'shimcache'] and sd['ran'] is True
    assert sd['last_run'] == '2026-09-01T14:18:31+00:00' and sd['first_seen'] == '2026-09-01T10:06:02+00:00' and sd['sha1'] == 'ab' * 20
    assert len(sd['paths']) == 4  # the same program at differently written paths stays one row
    assert rows['notepad.exe']['sources'] == ['userassist']
    never = rows['never-ran.exe']
    assert never['ran'] is False and never['last_run'] is None and never['sources'] == ['shimcache']


def test_execution_rows_are_newest_first():
    rows = merge(PREFETCH, USERASSIST, BAM, AMCACHE, SHIM)
    assert [r['program'] for r in rows][:2] == ['SecureDelete.exe', 'notepad.exe'] and rows[-1]['program'] == 'never-ran.exe'
