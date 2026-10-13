"""Phone extractions for the scenario: alice's Android phone (a full file system extraction ZIP, `Dump/data/...`) and her
iPhone (a full file system ZIP, `filesystem1/private/var/...`). The databases use the apps' own table layouts (only the
columns the analysis reads, plus a few it must ignore).

Android (Pixel 8, Android 14): SMS with dmitri (+44 20 7946 0958) after the upload, a WhatsApp chat (current msgstore.db
layout) where she sends him the download link, an outgoing call to him and a missed call from Bob, contacts, installed
apps (Signal, Proton Mail, WhatsApp, Chrome), saved Wi-Fi networks (the competitor's guest network), Chrome history.
iPhone (iOS 17.6.1): iMessage with dmitri's email address, an SMS from Mom, a FaceTime audio call with dmitri, contacts,
a WhatsApp chat (ChatStorage.sqlite), Safari history, installed apps.

Usage: make_phones.py OUT_DIR. Writes dfip-test-android.zip, dfip-test-iphone.zip and phones-expected.json.
"""
import hashlib
import json
import plistlib
import sqlite3
import struct
import sys
import tempfile
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
DMITRI, BOB, MOM = '+442079460958', '+12025550143', '+12125550147'
DMITRI_MAIL = 'dmitri.k.rival@protonmail.example'
LINK = 'https://filetransfer.example.net/d/7Hq2xK'


def t(*a):
    return datetime(*a, tzinfo=UTC)


def ms(d):
    return int(d.timestamp() * 1000)


def mac(d):
    return (d - MAC_EPOCH).total_seconds()


def db_bytes(script: str, rows: list[tuple[str, tuple]]) -> bytes:
    """A SQLite database built from a schema and rows, returned as bytes."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'x.db'
        con = sqlite3.connect(p)
        con.executescript(script)
        for sql, args in rows:
            con.execute(sql, args)
        con.commit()
        con.close()
        return p.read_bytes()


# ------------------------------------------------------------------------------------------------ Android
SMS = [(t(2026, 8, 30, 13, 0, 0), MOM, 1, 'Dinner Sunday?'), (t(2026, 9, 1, 18, 28, 10), DMITRI, 1, 'Did it go through?'),
       (t(2026, 9, 1, 18, 29, 2), DMITRI, 2, 'Uploaded. Link in WhatsApp.')]
CALLS_A = [(t(2026, 9, 1, 18, 31, 0), DMITRI, 2, 127), (t(2026, 9, 1, 19, 5, 11), BOB, 3, 0)]
WA_A = [(t(2026, 9, 1, 18, 30, 15), True, LINK), (t(2026, 9, 1, 18, 30, 40), False, 'Perfect. Delete everything.')]
APPS_A = [('com.whatsapp', 'WhatsApp', t(2025, 2, 10, 9, 0)), ('org.thoughtcrime.securesms', 'Signal', t(2026, 8, 31, 21, 14, 3)),
          ('ch.protonmail.android', 'Proton Mail', t(2026, 8, 31, 21, 16, 40)), ('com.android.chrome', 'Chrome', t(2024, 11, 1, 8, 0))]
WIFI_A = [('CorpNet', 'WPA_EAP'), ('Rival-Guest', 'WPA_PSK')]
MMS = (t(2026, 9, 1, 18, 26, 30), DMITRI, 'This one?', 'columns.png')  # incoming, with a picture
DEVICE_NAME, ZONE = 'Alice’s Pixel', 'America/New_York'


class Abx:
    """Android Binary XML, as Android 12 and later write packages.xml and the settings files (BinaryXmlSerializer)."""
    START_DOCUMENT, END_DOCUMENT, START_TAG, END_TAG, ATTRIBUTE = 0, 1, 2, 3, 15
    NULL, STRING, INTERNED, INT, LONG_HEX = 0x10, 0x20, 0x30, 0x60, 0x90

    def __init__(self):
        self.out, self.interned = bytearray(b'ABX\x00'), []
        self.out.append(self.START_DOCUMENT | self.NULL)

    def _utf(self, s):
        b = s.encode()
        self.out += struct.pack('>H', len(b)) + b

    def _interned(self, s):
        if s in self.interned:
            self.out += struct.pack('>H', self.interned.index(s))
        else:
            self.out += b'\xff\xff'
            self._utf(s)
            self.interned.append(s)

    def start(self, tag, **attrs):
        self.out.append(self.START_TAG | self.INTERNED)
        self._interned(tag)
        for k, v in attrs.items():
            if isinstance(v, Hex):
                self.out.append(self.ATTRIBUTE | self.LONG_HEX)
                self._interned(k)
                self.out += struct.pack('>q', int(v))
            elif isinstance(v, int):
                self.out.append(self.ATTRIBUTE | self.INT)
                self._interned(k)
                self.out += struct.pack('>i', v)
            else:
                self.out.append(self.ATTRIBUTE | self.STRING)
                self._interned(k)
                self._utf(v)
        return self

    def end(self, tag):
        self.out.append(self.END_TAG | self.INTERNED)
        self._interned(tag)
        return self

    def done(self) -> bytes:
        self.out.append(self.END_DOCUMENT | self.NULL)
        return bytes(self.out)


class Hex(int):
    """A long written as hex (attributeLongHex), as packages.xml stores its times."""


def proto_props(props: dict) -> bytes:
    """/data/property/persistent_properties: PersistentProperties { repeated PropEntry properties = 1; } with
    PropEntry { string name = 1; string value = 2; }."""
    def field(num, data):
        return bytes([num << 3 | 2, len(data)]) + data
    return b''.join(field(1, field(1, k.encode()) + field(2, v.encode())) for k, v in props.items())


def png(w=4, h=4) -> bytes:
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rows = b''.join(b'\x00' + bytes([40, 90, 160]) * w for _ in range(h))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')


HEIC = b'\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic' + bytes(1000)  # the start of a HEIF picture


def android() -> dict:
    files = {}
    files['system/build.prop'] = ('ro.product.manufacturer=Google\nro.product.model=Pixel 8\nro.product.brand=google\n'
                                  'ro.build.version.release=14\nro.build.fingerprint=google/shiba/shiba:14/AP2A.240905.003/12231197:user/release-keys\n')
    settings = Abx().start('settings', version=213)
    for i, (k, v) in enumerate((('airplane_mode_on', '0'), ('device_name', DEVICE_NAME))):
        settings.start('setting', id=str(i + 1), name=k, value=v, package='android', defaultSysSet='true').end('setting')
    files['data/system/users/0/settings_global.xml'] = settings.end('settings').done()
    files['data/property/persistent_properties'] = proto_props({'persist.sys.locale': 'en-US', 'persist.sys.timezone': ZONE})
    d, a, txt, pic = MMS
    files['data/data/com.android.providers.telephony/databases/mmssms.db'] = db_bytes(
        'CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER, date INTEGER, date_sent INTEGER, '
        'protocol INTEGER, read INTEGER, status INTEGER, type INTEGER, body TEXT, seen INTEGER);'
        'CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_sent INTEGER, msg_box INTEGER, read INTEGER, '
        'm_type INTEGER, sub TEXT, ct_t TEXT);'
        'CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, seq INTEGER, ct TEXT, name TEXT, chset INTEGER, cl TEXT, _data TEXT, text TEXT);'
        'CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, contact_id INTEGER, address TEXT, type INTEGER, charset INTEGER);',
        [('INSERT INTO sms (thread_id, address, date, date_sent, read, type, body, seen) VALUES (?,?,?,?,1,?,?,1)',
          (1 if a == DMITRI else 2, a, ms(d), ms(d), ty, b)) for d, a, ty, b in SMS]
        + [('INSERT INTO pdu VALUES (1, 1, ?, ?, 1, 1, 132, NULL, ?)', (int(d.timestamp()), int(d.timestamp()), 'application/vnd.wap.multipart.related')),
           ("INSERT INTO part VALUES (1, 1, -1, 'application/smil', 'smil.xml', 106, 'smil.xml', NULL, '<smil/>')", ()),
           ('INSERT INTO part VALUES (2, 1, 0, ?, ?, NULL, ?, ?, NULL)', ('image/png', pic, pic, f'/data/user/0/com.android.providers.telephony/app_parts/PART_{ms(d)}')),
           ("INSERT INTO part VALUES (3, 1, 1, 'text/plain', NULL, 106, 'text_0.txt', NULL, ?)", (txt,)),
           ('INSERT INTO addr VALUES (1, 1, NULL, ?, 137, 106)', (a,)),
           ("INSERT INTO addr VALUES (2, 1, NULL, 'insert-address-token', 151, 106)", ())])
    files['data/data/com.android.providers.contacts/databases/calllog.db'] = db_bytes(
        'CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT, countryiso TEXT);',
        [('INSERT INTO calls (number, date, duration, type, countryiso) VALUES (?,?,?,?,?)', (n, ms(d), dur, ty, 'US')) for d, n, ty, dur in CALLS_A])
    files['data/data/com.android.providers.contacts/databases/contacts2.db'] = db_bytes(
        'CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT, deleted INTEGER DEFAULT 0);'
        'CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);'
        'CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT, data2 TEXT);',
        [("INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2')", ()),
         ("INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/email_v2')", ()),
         ("INSERT INTO mimetypes VALUES (3, 'vnd.android.cursor.item/name')", ())]
        + [('INSERT INTO raw_contacts (_id, display_name) VALUES (?,?)', (i, n)) for i, n in ((1, 'Dmitri K'), (2, 'Bob Builder'), (3, 'Mom'))]
        + [('INSERT INTO data (raw_contact_id, mimetype_id, data1) VALUES (?,?,?)', r) for r in
           ((1, 1, '+44 20 7946 0958'), (1, 2, DMITRI_MAIL), (2, 1, '+1 202-555-0143'), (3, 1, '+1 212-555-0147'))])
    files['data/data/com.whatsapp/databases/msgstore.db'] = db_bytes(
        'CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);'
        'CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);'
        'CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER, '
        'timestamp INTEGER, message_type INTEGER, text_data TEXT, status INTEGER);',
        [("INSERT INTO jid VALUES (1, '442079460958', 's.whatsapp.net', '442079460958@s.whatsapp.net')", ()),
         ('INSERT INTO chat VALUES (1, 1, NULL)', ())]
        + [('INSERT INTO message (chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data) VALUES (1,?,?,0,?,0,?)',
            (int(me), f'3EB0{i:04d}', ms(d), txt)) for i, (d, me, txt) in enumerate(WA_A)])
    files['data/data/com.whatsapp/databases/wa.db'] = db_bytes(
        'CREATE TABLE wa_contacts (_id INTEGER PRIMARY KEY, jid TEXT, is_whatsapp_user INTEGER, display_name TEXT, number TEXT);',
        [("INSERT INTO wa_contacts (jid, is_whatsapp_user, display_name, number) VALUES ('442079460958@s.whatsapp.net', 1, 'Dmitri K', '+44 20 7946 0958')", ())])
    files[f'data/data/com.android.providers.telephony/app_parts/PART_{ms(d)}'] = png()
    pk = Abx().start('packages')
    pk.start('package', name='com.android.settings', codePath='/system_ext/priv-app/Settings', ft=Hex(ms(t(2024, 10, 1))), it=Hex(ms(t(2024, 10, 1))),
             ut=Hex(ms(t(2024, 10, 1))), version=34, userId=1000).end('package')
    for i, (p, _, d) in enumerate(APPS_A):
        pk.start('package', name=p, codePath=f'/data/app/~~{i}Xq==/{p}-1', ft=Hex(ms(d)), it=Hex(ms(d)), ut=Hex(ms(d)), version=1, userId=10100 + i,
                 installer='com.android.vending').end('package')
    files['data/system/packages.xml'] = pk.end('packages').done()
    files['data/misc/apexdata/com.android.wifi/WifiConfigStore.xml'] = (
        '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n<WifiConfigStoreData>\n<int name="Version" value="3" />\n<NetworkList>\n'
        + ''.join(f'<Network>\n<WifiConfiguration>\n<string name="ConfigKey">&quot;{s}&quot;{k}</string>\n<string name="SSID">&quot;{s}&quot;</string>\n'
                  f'<string name="PreSharedKey">&quot;not-a-real-key-{s}&quot;</string>\n<string name="CreationTime">time=09-02 15:47:30.000</string>\n'
                  f'</WifiConfiguration>\n<NetworkStatus>\n<string name="SelectionStatus">NETWORK_SELECTION_ENABLED</string>\n</NetworkStatus>\n</Network>\n'
                  for s, k in WIFI_A)
        + '</NetworkList>\n</WifiConfigStoreData>\n')
    chrome_epoch = datetime(1601, 1, 1, tzinfo=UTC)
    files['data/data/com.android.chrome/app_chrome/Default/History'] = db_bytes(
        'CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0, '
        'last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0);'
        'CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path LONGVARCHAR, tab_url LONGVARCHAR, total_bytes INTEGER, start_time INTEGER, '
        'end_time INTEGER, state INTEGER);',
        [('INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?,?,1,?)',
          (LINK, 'Your file is ready - Anonymous File Upload', int((t(2026, 9, 1, 18, 30, 5) - chrome_epoch).total_seconds() * 1_000_000)))])
    return files


# ------------------------------------------------------------------------------------------------ iPhone
IMSG = [(t(2026, 8, 31, 14, 0, 0), MOM, 'SMS', False, 'Call me when you land'),
        (t(2026, 9, 2, 13, 35, 0), DMITRI_MAIL, 'iMessage', False, 'Got the file. The Mac one too?'),
        (t(2026, 9, 2, 13, 36, 10), DMITRI_MAIL, 'iMessage', True, 'Yes, uploaded from the laptop and the Mac.')]
CALL_I = (t(2026, 9, 2, 13, 40, 0), DMITRI_MAIL, 16, True, 300)  # FaceTime audio, outgoing, 5 minutes
WA_I = [(t(2026, 9, 2, 13, 50, 1), False, 'Delete the chats.'), (t(2026, 9, 2, 13, 50, 30), True, 'Doing it now.')]
APPS_I = [('net.whatsapp.WhatsApp', 'WhatsApp', '24.17.79'), ('ch.protonmail.protonmail', 'Proton Mail', '4.20.0'),
          ('org.whispersystems.signal', 'Signal', '7.27')]
WIFI_I = ('Rival-Guest', t(2026, 9, 2, 15, 47, 30), t(2026, 9, 2, 15, 48, 2))  # added, joined by the user


def iphone() -> dict:
    files = {}
    files['System/Library/CoreServices/SystemVersion.plist'] = plistlib.dumps({'ProductName': 'iPhone OS', 'ProductVersion': '17.6.1',
                                                                              'ProductBuildVersion': '21G93'})
    files['private/var/root/Library/Lockdown/data_ark.plist'] = plistlib.dumps({'-DeviceName': 'Alice’s iPhone', '-TimeZone': 'America/New_York',
                                                                               'com.apple.mobile.data_sync-DeviceClass': 'iPhone'},
                                                                              fmt=plistlib.FMT_BINARY)
    handles = {MOM: 1, DMITRI_MAIL: 2}
    rows = [('INSERT INTO handle (ROWID, id, service) VALUES (?,?,?)', (i, h, 'SMS' if h == MOM else 'iMessage')) for h, i in handles.items()]
    for n, (d, h, svc, me, txt) in enumerate(IMSG, 1):
        rows.append(('INSERT INTO message (ROWID, guid, text, handle_id, service, date, is_from_me, cache_has_attachments) VALUES (?,?,?,?,?,?,?,?)',
                     (n, f'G-{n}', txt, handles[h], svc, int(mac(d) * 1e9), int(me), 1 if n == 2 else 0)))
    rows += [('INSERT INTO attachment (ROWID, filename, mime_type, transfer_name, total_bytes) VALUES (1, ?, ?, ?, ?)',
              ('~/Library/SMS/Attachments/ab/12/IMG_0042.HEIC', 'image/heic', 'IMG_0042.HEIC', len(HEIC))),
             ('INSERT INTO message_attachment_join (message_id, attachment_id) VALUES (2, 1)', ())]
    files['private/var/mobile/Library/SMS/Attachments/ab/12/IMG_0042.HEIC'] = HEIC
    files['private/var/mobile/Library/SMS/sms.db'] = db_bytes(
        'CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, service TEXT);'
        'CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER, service TEXT, date INTEGER, is_from_me INTEGER, '
        'cache_has_attachments INTEGER);'
        'CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT, mime_type TEXT, transfer_name TEXT, total_bytes INTEGER);'
        'CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);', rows)
    d, addr, kind, out, dur = CALL_I
    files['private/var/mobile/Library/CallHistoryDB/CallHistory.storedata'] = db_bytes(
        'CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS VARCHAR, ZDATE TIMESTAMP, ZDURATION FLOAT, ZORIGINATED INTEGER, ZANSWERED INTEGER, '
        'ZCALLTYPE INTEGER, ZNAME VARCHAR, ZSERVICE_PROVIDER VARCHAR);',
        [('INSERT INTO ZCALLRECORD (ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED, ZCALLTYPE, ZSERVICE_PROVIDER) VALUES (?,?,?,?,1,?,?)',
          (addr, mac(d), float(dur), int(out), kind, 'com.apple.FaceTime'))])
    files['private/var/mobile/Library/AddressBook/AddressBook.sqlitedb'] = db_bytes(
        'CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Organization TEXT);'
        'CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, record_id INTEGER, property INTEGER, label INTEGER, value TEXT);',
        [("INSERT INTO ABPerson VALUES (1, 'Dmitri', 'K', 'Rival Corp')", ()), ("INSERT INTO ABPerson VALUES (2, 'Mom', NULL, NULL)", ())]
        + [('INSERT INTO ABMultiValue (record_id, property, value) VALUES (?,?,?)', r) for r in
           ((1, 3, '+44 20 7946 0958'), (1, 4, DMITRI_MAIL), (2, 3, '(212) 555-0147'))])
    files['private/var/mobile/Containers/Shared/AppGroup/2D1A7E88-4F0B-4C55-9E1D-6B9A0C1E7F31/ChatStorage.sqlite'] = db_bytes(
        'CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, ZCONTACTJID VARCHAR, ZPARTNERNAME VARCHAR);'
        'CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZCHATSESSION INTEGER, ZISFROMME INTEGER, ZFROMJID VARCHAR, ZTOJID VARCHAR, '
        'ZMESSAGEDATE TIMESTAMP, ZTEXT VARCHAR, ZMESSAGETYPE INTEGER);',
        [("INSERT INTO ZWACHATSESSION VALUES (1, '442079460958@s.whatsapp.net', 'Dmitri K')", ())]
        + [('INSERT INTO ZWAMESSAGE (ZCHATSESSION, ZISFROMME, ZFROMJID, ZTOJID, ZMESSAGEDATE, ZTEXT, ZMESSAGETYPE) VALUES (1,?,?,?,?,?,0)',
            (int(me), None if me else '442079460958@s.whatsapp.net', '442079460958@s.whatsapp.net' if me else None, mac(d), txt)) for d, me, txt in WA_I])
    files['private/var/mobile/Library/Safari/History.db'] = db_bytes(
        'CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, domain_expansion TEXT, visit_count INTEGER);'
        'CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);',
        [("INSERT INTO history_items VALUES (1, 'https://tools.example.org/securedelete/', NULL, 1)", ()),
         ('INSERT INTO history_visits (history_item, visit_time, title) VALUES (1, ?, ?)', (mac(t(2026, 9, 2, 13, 45, 0)), 'SecureDelete'))])
    for i, (bundle, name, ver) in enumerate(APPS_I):
        guid = f'7A0C{i:04d}-1111-4222-8333-000000000000'
        files[f'private/var/containers/Bundle/Application/{guid}/{name.replace(" ", "")}.app/Info.plist'] = plistlib.dumps(
            {'CFBundleIdentifier': bundle, 'CFBundleDisplayName': name, 'CFBundleShortVersionString': ver}, fmt=plistlib.FMT_BINARY)
    ssid, added, joined = WIFI_I
    files['private/var/preferences/com.apple.wifi.known-networks.plist'] = plistlib.dumps(
        {f'wifi.network.ssid.{ssid}': {'SSID': ssid.encode(), 'AddedAt': added.replace(tzinfo=None), 'JoinedByUserAt': joined.replace(tzinfo=None),
                                        'SupportedSecurityTypes': 'WPA2 Personal', '__OSSpecific__': {'WiFiNetworkPasswordModificationDate': added.replace(tzinfo=None)}}},
        fmt=plistlib.FMT_BINARY)
    return files


EXPECTED = {
    'android': {
        'device': {'model': 'Pixel 8', 'manufacturer': 'Google', 'os_version': '14', 'name': DEVICE_NAME, 'zone': ZONE},
        'sms': [{'time': d.isoformat(), 'party': a, 'direction': 'incoming' if ty == 1 else 'outgoing', 'text': b} for d, a, ty, b in SMS],
        'mms': {'time': MMS[0].isoformat(), 'party': MMS[1], 'direction': 'incoming', 'text': MMS[2], 'attachment': MMS[3],
                'attachment_path': f'/data/data/com.android.providers.telephony/app_parts/PART_{ms(MMS[0])}', 'attachment_sha256': hashlib.sha256(png()).hexdigest()},
        'calls': [{'time': d.isoformat(), 'party': n, 'direction': {2: 'outgoing', 3: 'missed'}[ty], 'duration': dur} for d, n, ty, dur in CALLS_A],
        'whatsapp': [{'time': d.isoformat(), 'direction': 'outgoing' if me else 'incoming', 'text': txt, 'party': '442079460958@s.whatsapp.net'}
                     for d, me, txt in WA_A],
        'contacts': {'Dmitri K': ['+44 20 7946 0958', DMITRI_MAIL], 'Bob Builder': ['+1 202-555-0143'], 'Mom': ['+1 212-555-0147']},
        'apps': {p: d.isoformat() for p, _, d in APPS_A},
        'wifi': [s for s, _ in WIFI_A],
        'chrome': LINK,
    },
    'iphone': {
        'device': {'name': 'Alice’s iPhone', 'os_version': '17.6.1', 'zone': 'America/New_York'},
        'messages': [{'time': d.isoformat(), 'party': h, 'app': svc, 'direction': 'outgoing' if me else 'incoming', 'text': txt} for d, h, svc, me, txt in IMSG],
        'attachment': 'IMG_0042.HEIC',
        'attachment_path': '/private/var/mobile/Library/SMS/Attachments/ab/12/IMG_0042.HEIC',
        'call': {'time': CALL_I[0].isoformat(), 'party': DMITRI_MAIL, 'kind': 'FaceTime audio', 'direction': 'outgoing', 'duration': 300},
        'whatsapp': [{'time': d.isoformat(), 'direction': 'outgoing' if me else 'incoming', 'text': txt} for d, me, txt in WA_I],
        'contacts': {'Dmitri K': ['+44 20 7946 0958', DMITRI_MAIL], 'Mom': ['(212) 555-0147']},
        'apps': {b: v for b, _, v in APPS_I},
        'safari': 'https://tools.example.org/securedelete/',
        'wifi': {'ssid': WIFI_I[0], 'last_joined': WIFI_I[2].isoformat()},
    },
}


def write_zip(path: Path, prefix: str, files: dict):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel, data in sorted(files.items()):
            info = zipfile.ZipInfo(f'{prefix}/{rel}', date_time=(2026, 9, 3, 10, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data.encode() if isinstance(data, str) else data)


if __name__ == '__main__':
    out = Path(sys.argv[1])
    write_zip(out / 'dfip-test-android.zip', 'Dump', android())
    write_zip(out / 'dfip-test-iphone.zip', 'filesystem1', iphone())
    (out / 'phones-expected.json').write_text(json.dumps(EXPECTED, indent=1, ensure_ascii=False), encoding='utf-8')
    print('Built the Android and iPhone extractions')
