"""Network captures (tshark output parsing, capture detection, which modules apply) and phone extractions (Android
and iOS databases, Android binary XML, root detection)."""
import json
import plistlib
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.forensic import disk_formats, network as net, packages, phones
from app.forensic.modules import REGISTRY, plan
from app.forensic.source import evidence_kind

UTC = timezone.utc
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)


def _db(path: Path, script: str, rows=()):
    con = sqlite3.connect(path)
    con.executescript(script)
    for sql, args in rows:
        con.execute(sql, args)
    con.commit()
    con.close()
    return path


def _tsv(path: Path, fields, rows):
    path.write_text(''.join('\t'.join(r.get(f, '') for f in fields) + '\n' for r in rows), encoding='utf-8')
    return path


# ------------------------------------------------------------------------------------------------ captures
def test_capture_detection_and_kinds(tmp_path):
    for magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\x0a\x0d\x0d\x0a'):
        p = tmp_path / 'x.pcap'
        p.write_bytes(magic + bytes(60))
        assert disk_formats.detect(p) == 'PCAP'
    assert disk_formats.extension_ok('traffic.pcapng') and disk_formats.extension_ok('a.cap')
    assert evidence_kind({'format': 'PCAP'}) == 'capture' and evidence_kind({'format': 'LOGICAL'}) == 'logical' and evidence_kind({'format': 'E01'}) == 'disk'
    # A capture has no file system: of the standard profile only these apply to it.
    applies = [n for n in plan(['network', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara', 'fs_index'], {})
               if 'capture' in REGISTRY[n].kinds]
    assert applies == ['network', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara']
    assert REGISTRY['network'].kinds == ('capture',) and 'capture' not in REGISTRY['fs_index'].kinds and 'capture' not in REGISTRY['phone'].kinds


def test_conversations_use_the_outer_header(tmp_path):
    f = net.FRAME_FIELDS
    rows = [
        {'frame.time_epoch': '1788272401.0', 'frame.len': '100', 'ip.src': '10.0.0.5', 'ip.dst': '10.0.0.1', 'ip.proto': '17', 'udp.srcport': '5353',
         'udp.dstport': '53', '_ws.col.Protocol': 'DNS'},
        {'frame.time_epoch': '1788272401.5', 'frame.len': '120', 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.5', 'ip.proto': '17', 'udp.srcport': '53',
         'udp.dstport': '5353', '_ws.col.Protocol': 'DNS'},
        # An ICMP error quoting a UDP packet: the outer header is ICMP (1); the quoted ports are not a conversation's.
        {'frame.time_epoch': '1788272402.0', 'frame.len': '70', 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.5', 'ip.proto': '1', 'udp.srcport': '5353',
         'udp.dstport': '53', '_ws.col.Protocol': 'ICMP'},
        {'frame.time_epoch': '1788272403.0', 'frame.len': '60', 'ipv6.src': 'fe80::1', 'ipv6.dst': 'fe80::2', 'ipv6.nxt': '6', 'tcp.srcport': '50000',
         'tcp.dstport': '443', '_ws.col.Protocol': 'TCP'},
        {'frame.time_epoch': '1788272404.0', 'frame.len': '42', '_ws.col.Protocol': 'ARP'},
    ]
    convs, totals = net.conversations(_tsv(tmp_path / 'f.tsv', f, rows))
    assert totals['packets'] == 5 and totals['bytes'] == 392 and totals['first'] == datetime.fromtimestamp(1788272401, UTC)
    by = {(c['protocol'], c['client'], c['server']): c for c in convs}
    dns = by[('UDP', '10.0.0.5', '10.0.0.1')]
    assert (dns['packets'], dns['bytes_from_client'], dns['bytes_from_server'], dns['client_port'], dns['server_port']) == (2, 100, 120, 5353, 53)
    assert by[('IP', '10.0.0.1', '10.0.0.5')]['client_port'] is None and ('TCP', 'fe80::1', 'fe80::2') in by and len(convs) == 3


def test_dns_pairs_answers_with_questions(tmp_path):
    rows = [
        {'frame.time_epoch': '1788272401.0', 'ip.src': '10.0.0.5', 'ip.dst': '10.0.0.1', 'dns.id': '0x1a2b', 'dns.flags.response': '0',
         'dns.qry.name': 'example.org', 'dns.qry.type': '1'},
        {'frame.time_epoch': '1788272401.1', 'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.5', 'dns.id': '0x1a2b', 'dns.flags.response': '1',
         'dns.flags.rcode': '0', 'dns.qry.name': 'example.org', 'dns.qry.type': '1', 'dns.a': '192.0.2.1,192.0.2.2', 'dns.cname': ''},
        {'frame.time_epoch': '1788272402.0', 'ip.src': '10.0.0.5', 'ip.dst': '10.0.0.1', 'dns.id': '0x0001', 'dns.flags.response': '0',
         'dns.qry.name': 'nothing.invalid', 'dns.qry.type': '28'},
    ]
    q = net.dns(_tsv(tmp_path / 'd.tsv', net.DNS_FIELDS, rows))
    assert [(x['name'], x['query_type'], x['answers'], x['answered'], x['client'], x['server']) for x in q] == [
        ('example.org', 'A', ['192.0.2.1', '192.0.2.2'], True, '10.0.0.5', '10.0.0.1'), ('nothing.invalid', 'AAAA', [], False, '10.0.0.5', '10.0.0.1')]
    assert 'type' not in q[0]  # the record's own type field is the document's


def test_http_bodies_and_uploads(tmp_path):
    form = (b'------b\r\nContent-Disposition: form-data; name="file"; filename="../../payroll.csv"\r\nContent-Type: text/csv\r\n\r\n'
            b'id,name\r\n1,alice\r\n------b\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n------b--\r\n')
    ek = [{'index': {}}, {'timestamp': '1', 'layers': {'frame_number': ['7'], 'frame_time_epoch': ['1788272402.02'], 'http_request_method': ['POST'],
                                                        'http_request_uri': ['/upload'], 'http_content_type': ['multipart/form-data; boundary=----b'],
                                                        'http_file_data': [form.hex()]}},
          {'timestamp': '2', 'layers': {'frame_number': ['9'], 'frame_time_epoch': ['1788272402.5'], 'http_response_code': ['200'],
                                        'http_request_in': ['7'], 'http_content_type': ['application/json'], 'http_file_data': [b'{"ok":true}'.hex()]}}]
    p = tmp_path / 'b.json'
    p.write_text('\n'.join(json.dumps(x) for x in ek) + '\n', encoding='utf-8')
    bodies = list(net.http_bodies(p))
    assert [(b['direction'], b['request_frame'], b['code']) for b in bodies] == [('request', 7, None), ('response', 7, 200)]
    parts = net.multipart_parts(bodies[0]['data'], bodies[0]['content_type'])
    assert [(x['name'], x['field'], x['content_type'], x['data']) for x in parts] == [('.._.._payroll.csv', 'file', 'text/csv', b'id,name\r\n1,alice')]
    assert net.body_name('/upload?x=1', 'multipart/form-data', 'request') == 'upload (request body)'
    assert net.body_name('/', 'text/html', 'response') == 'index' and net.body_name('/a/b%20c.png', None, 'response') == 'b_20c.png'
    assert net.multipart_parts(b'plain', 'text/plain') == []


# ------------------------------------------------------------------------------------------------ Android binary XML
def _abx(tree) -> bytes:
    """A small Android binary XML writer: (tag, {attr: value}, [children]); ints as INT, ('hex', n) as LONG_HEX."""
    out, interned = bytearray(b'ABX\x00\x10'), []

    def utf(s):
        b = s.encode()
        out.extend(struct.pack('>H', len(b)) + b)

    def name(s):
        if s in interned:
            out.extend(struct.pack('>H', interned.index(s)))
        else:
            out.extend(b'\xff\xff')
            utf(s)
            interned.append(s)

    def element(tag, attrs, kids):
        out.append(0x32)
        name(tag)
        for k, v in attrs.items():
            if isinstance(v, tuple):
                out.append(0x9F)
                name(k)
                out.extend(struct.pack('>q', v[1]))
            elif isinstance(v, bool):
                out.append(0xCF if v else 0xDF)
                name(k)
            elif isinstance(v, int):
                out.append(0x6F)
                name(k)
                out.extend(struct.pack('>i', v))
            else:
                out.append(0x2F)
                name(k)
                utf(v)
        for kid in kids:
            element(*kid)
        out.append(0x33)
        name(tag)
    element(*tree)
    out.append(0x11)
    return bytes(out)


def test_android_binary_xml_packages_and_settings():
    t = int(datetime(2026, 8, 31, 21, 14, 3, tzinfo=UTC).timestamp() * 1000)
    data = _abx(('packages', {}, [
        ('package', {'name': 'org.thoughtcrime.securesms', 'codePath': '/data/app/~~x==/org.thoughtcrime.securesms-1', 'it': ('hex', t), 'ut': ('hex', t),
                     'version': 1500, 'userId': 10123, 'installer': 'com.android.vending'}, []),
        ('package', {'name': 'com.android.settings', 'codePath': '/system_ext/priv-app/Settings', 'it': ('hex', t)}, []),
        ('package', {'name': 'com.example.flagged', 'codePath': '/data/app/x', 'flags': 1}, []),  # FLAG_SYSTEM
    ]))
    apps, system = phones.android_packages(data)
    assert system == 2 and [(a['app_id'], a['installed'], a['version'], a['installer'], a['known_name'], a['notable']) for a in apps] == [
        ('org.thoughtcrime.securesms', datetime(2026, 8, 31, 21, 14, 3, tzinfo=UTC), '1500', 'com.android.vending', 'Signal', True)]
    # The same packages written as text XML (Android 11 and earlier) read the same.
    text = (f'<packages><package name="org.thoughtcrime.securesms" codePath="/data/app/x" it="{t:x}" ut="{t:x}" version="1500" '
            f'installer="com.android.vending" /></packages>').encode()
    assert phones.android_packages(text)[0][0]['installed'] == apps[0]['installed']
    settings = _abx(('settings', {'version': 213}, [('setting', {'id': '1', 'name': 'device_name', 'value': 'Pixel', 'defaultSysSet': True}, []),
                                                    ('setting', {'id': '2', 'name': 'device_name_x', 'value': 'y'}, [])]))
    assert phones.android_settings(settings) == {'device_name': 'Pixel', 'device_name_x': 'y'}


def test_android_device_time_zone_and_wifi():
    field = lambda n, b: bytes([n << 3 | 2, len(b)]) + b
    props = field(1, field(1, b'persist.sys.timezone') + field(2, b'Europe/London')) + field(1, field(1, b'persist.sys.locale') + field(2, b'en-GB'))
    assert phones.persistent_properties(props) == {'persist.sys.timezone': 'Europe/London', 'persist.sys.locale': 'en-GB'}
    assert phones.persistent_properties(b'\x0a\xff') == {}  # truncated: nothing, no error
    d = phones.android_device(phones.build_prop(b'# c\nro.product.system.model=Pixel 7\nro.product.manufacturer=Google\nro.build.version.release=13\n'),
                              {'bluetooth_name': 'Pix'}, phones.persistent_properties(props))
    assert (d['model'], d['manufacturer'], d['os_version'], d['name'], d['time_zone']) == ('Pixel 7', 'Google', '13', 'Pix', 'Europe/London')
    xml = (b'<WifiConfigStoreData><NetworkList><Network><WifiConfiguration><string name="ConfigKey">&quot;Cafe&quot;WPA_PSK</string>'
           b'<string name="SSID">&quot;Cafe&quot;</string><string name="PreSharedKey">&quot;secret-psk&quot;</string>'
           b'<boolean name="HiddenSSID" value="true" /><string name="DefaultGwMacAddress">02:00:00:aa:bb:cc</string></WifiConfiguration></Network>'
           b'</NetworkList></WifiConfigStoreData>')
    w = phones.android_wifi(xml)
    assert [(x['ssid'], x['security'], x['hidden'], x['router_mac']) for x in w] == [('Cafe', 'WPA_PSK', True, '02:00:00:aa:bb:cc')]
    assert 'secret-psk' not in json.dumps(w, default=str)
    old = phones.wpa_supplicant(b'network={\n\tssid="Home"\n\tpsk="hunter22"\n\tkey_mgmt=WPA-PSK\n}\n')
    assert [(x['ssid'], x['security']) for x in old] == [('Home', 'WPA-PSK')] and 'hunter22' not in json.dumps(old)


# ------------------------------------------------------------------------------------------------ Android databases
def test_android_sms_mms_calls_contacts(tmp_path):
    ms = lambda *a: int(datetime(*a, tzinfo=UTC).timestamp() * 1000)
    db = _db(tmp_path / 'mmssms.db',
             'CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER, date_sent INTEGER, read INTEGER, type INTEGER, body TEXT);'
             'CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, msg_box INTEGER, read INTEGER, sub TEXT);'
             'CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, ct TEXT, name TEXT, cl TEXT, _data TEXT, text TEXT);'
             'CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER);',
             [('INSERT INTO sms VALUES (1, 1, ?, ?, ?, 1, 5, ?)', ('+15550001', ms(2026, 9, 1, 10), ms(2026, 9, 1, 10), 'not sent')),
              ('INSERT INTO pdu VALUES (1, 2, ?, 2, 1, ?)', (int(datetime(2026, 9, 1, 11, tzinfo=UTC).timestamp()), 'Subject')),
              ("INSERT INTO part VALUES (1, 1, 'application/smil', 'smil.xml', NULL, NULL, '<smil/>')", ()),
              ("INSERT INTO part VALUES (2, 1, 'text/plain', NULL, 'text_0.txt', NULL, 'see this')", ()),
              ("INSERT INTO part VALUES (3, 1, 'image/jpeg', NULL, 'IMG_1.jpg', '/data/user/0/com.android.providers.telephony/app_parts/PART_1', NULL)", ()),
              ("INSERT INTO addr VALUES (1, 1, 'insert-address-token', 137)", ()), ("INSERT INTO addr VALUES (2, 1, '+15550002', 151)", ()),
              ("INSERT INTO addr VALUES (3, 1, '+15550003', 151)", ())])
    sms, mms = phones.android_sms(db)
    assert (sms['direction'], sms['status'], sms['text'], sms['time']) == ('outgoing', 'failed', 'not sent', datetime(2026, 9, 1, 10, tzinfo=UTC))
    assert (mms['app'], mms['direction'], mms['party'], mms['text']) == ('MMS', 'outgoing', '+15550002, +15550003', 'Subject\nsee this')
    assert [(a['name'], a['mime_type']) for a in mms['attachments']] == [('IMG_1.jpg', 'image/jpeg')]
    # Calls in contacts2.db (Android 6 and earlier), with a video call and a blocked one.
    c2 = _db(tmp_path / 'contacts2.db',
             'CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT, features INTEGER);'
             'CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT, deleted INTEGER);'
             'CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);'
             'CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT);',
             [('INSERT INTO calls VALUES (1, ?, ?, 61, 2, NULL, 1)', ('+15550001', ms(2026, 9, 1, 12))), ('INSERT INTO calls VALUES (2, ?, ?, 0, 6, NULL, 0)', ('+15550009', ms(2026, 9, 1, 13))),
              ("INSERT INTO raw_contacts VALUES (1, NULL, 0)", ()), ("INSERT INTO raw_contacts VALUES (2, 'Gone', 1)", ()),
              ("INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2')", ()), ("INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/name')", ()),
              ("INSERT INTO data VALUES (1, 1, 2, 'Ann Example')", ()), ("INSERT INTO data VALUES (2, 1, 1, '555-0001')", ()), ("INSERT INTO data VALUES (3, 2, 1, '555-0099')", ())])
    calls = phones.android_calls(c2)
    assert [(c['direction'], c['kind'], c['duration']) for c in calls] == [('outgoing', 'Video', 61), ('blocked', 'Phone', 0)]
    assert [(c['name'], c['numbers']) for c in phones.android_contacts(c2)] == [('Ann Example', ['555-0001'])]  # the deleted contact left out


def test_whatsapp_android_both_layouts(tmp_path):
    ms = lambda *a: int(datetime(*a, tzinfo=UTC).timestamp() * 1000)
    old = _db(tmp_path / 'old.db',
              'CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER, key_id TEXT, data TEXT, timestamp INTEGER, '
              'media_mime_type TEXT, media_name TEXT, media_size INTEGER, remote_resource TEXT, media_wa_type TEXT, media_caption TEXT);'
              'CREATE TABLE chat_list (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, subject TEXT);',
              [("INSERT INTO messages (key_remote_jid, key_from_me, key_id, data, timestamp) VALUES ('-1', 0, '-1', NULL, 0)", ()),
               ('INSERT INTO messages (key_remote_jid, key_from_me, key_id, data, timestamp, remote_resource) VALUES (?,?,?,?,?,?)',
                ('12036302@g.us', 0, 'A1', 'hello group', ms(2026, 9, 1, 9), '15550001@s.whatsapp.net')),
               ('INSERT INTO messages (key_remote_jid, key_from_me, key_id, timestamp, media_mime_type, media_name, media_size, media_wa_type, media_caption) '
                'VALUES (?,?,?,?,?,?,?,?,?)', ('15550001@s.whatsapp.net', 1, 'A2', ms(2026, 9, 1, 9, 5), 'image/jpeg', 'IMG-1.jpg', 2048, '1', 'the photo')),
               ("INSERT INTO chat_list VALUES (1, '12036302@g.us', 'Team')", ())])
    m = phones.whatsapp_android(old)
    assert [(x['party'], x['group'], x['chat_name'], x['sender'], x['direction'], x['text'], x['message_type']) for x in m] == [
        ('12036302@g.us', True, 'Team', '15550001@s.whatsapp.net', 'incoming', 'hello group', 'text'),
        ('15550001@s.whatsapp.net', False, None, None, 'outgoing', 'the photo', 'image')]
    assert m[1]['attachments'][0]['name'] == 'IMG-1.jpg'
    new = _db(tmp_path / 'new.db',
              'CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT);'  # no raw_string column (older current layouts)
              'CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);'
              'CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER, timestamp INTEGER, '
              'message_type INTEGER, text_data TEXT);'
              'CREATE TABLE message_media (message_row_id INTEGER, file_path TEXT, mime_type TEXT, file_size INTEGER);',
              [("INSERT INTO jid VALUES (1, '15550001', 's.whatsapp.net')", ()), ('INSERT INTO chat VALUES (1, 1, NULL)', ()),
               ('INSERT INTO message VALUES (1, 1, 0, ?, 0, ?, 9, NULL)', ('K1', ms(2026, 9, 1, 9))),
               ("INSERT INTO message_media VALUES (1, 'Media/WhatsApp Documents/plan.pdf', 'application/pdf', 4096)", ())])
    m = phones.whatsapp_android(new)
    assert [(x['party'], x['message_type'], x['attachments'][0]['name'], x['attachments'][0]['device_path']) for x in m] == [
        ('15550001@s.whatsapp.net', 'document', 'plan.pdf', 'Media/WhatsApp Documents/plan.pdf')]


# ------------------------------------------------------------------------------------------------ iOS
def test_ios_messages_calls_and_text_in_attributed_body(tmp_path):
    mac = lambda *a: (datetime(*a, tzinfo=UTC) - MAC_EPOCH).total_seconds()
    body = b'\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+\x0bHello there\x86'
    assert phones.attributed_text(body) == 'Hello there' and phones.attributed_text(None) is None
    db = _db(tmp_path / 'sms.db',
             'CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);'
             'CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT, display_name TEXT);'
             'CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);'
             'CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, attributedBody BLOB, handle_id INTEGER, service TEXT, date INTEGER, '
             'is_from_me INTEGER, date_read INTEGER);',
             [("INSERT INTO handle VALUES (1, '+15550001')", ()), ("INSERT INTO chat VALUES (1, 'chat123456', 'Family')", ()),
              ('INSERT INTO chat_message_join VALUES (1, 2)', ()),
              ('INSERT INTO message VALUES (1, ?, NULL, ?, 1, ?, ?, 0, 0)', ('G1', body, 'iMessage', int(mac(2026, 9, 2, 13) * 1e9))),
              ('INSERT INTO message VALUES (2, ?, ?, NULL, 0, ?, ?, 1, 0)', ('G2', 'to the group', 'iMessage', int(mac(2026, 9, 2, 14)))),  # seconds (iOS 10)
              ])
    m = sorted(phones.ios_messages(db), key=lambda x: x['time'])
    assert [(x['text'], x['party'], x['group'], x['chat_name'], x['time']) for x in m] == [
        ('Hello there', '+15550001', False, None, datetime(2026, 9, 2, 13, tzinfo=UTC)),
        ('to the group', 'chat123456', True, 'Family', datetime(2026, 9, 2, 14, tzinfo=UTC))]
    ch = _db(tmp_path / 'CallHistory.storedata',
             'CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS BLOB, ZDATE TIMESTAMP, ZDURATION FLOAT, ZORIGINATED INTEGER, ZANSWERED INTEGER, '
             'ZCALLTYPE INTEGER, ZSERVICE_PROVIDER VARCHAR);',
             [('INSERT INTO ZCALLRECORD VALUES (1, ?, ?, 0.0, 0, 0, 1, ?)', (b'+15550001', mac(2026, 9, 2, 15), 'com.apple.Telephony')),
              ('INSERT INTO ZCALLRECORD VALUES (2, ?, ?, 42.4, 0, 1, 1, ?)', ('15550002', mac(2026, 9, 2, 16), 'net.whatsapp.WhatsApp'))])
    c = phones.ios_calls(ch)
    assert [(x['party'], x['direction'], x['kind'], x['app'], x['duration']) for x in c] == [
        ('+15550001', 'missed', 'Phone', 'Phone', 0), ('15550002', 'incoming', 'WhatsApp', 'WhatsApp', 42)]


def test_ios_apps_and_party_keys():
    info = plistlib.dumps({'CFBundleIdentifier': 'org.whispersystems.signal', 'CFBundleName': 'Signal', 'CFBundleVersion': '7.1'})
    meta = plistlib.dumps({'com.apple.iTunesStore.downloadInfo': {'purchaseDate': '2026-08-31T21:00:00Z'}, 'artistName': 'Signal Messenger'})
    a = phones.ios_app(info, meta)
    assert (a['name'], a['version'], a['installed'], a['installer'], a['notable']) == ('Signal', '7.1', datetime(2026, 8, 31, 21, tzinfo=UTC), 'Signal Messenger', True)
    assert phones.ios_app(plistlib.dumps({'CFBundleName': 'x'})) is None
    k = phones.party_key
    assert k('+44 20 7946 0958') == k('442079460958@s.whatsapp.net') == k('+442079460958') and k('(212) 555-0147') == k('+12125550147')
    assert k('Dmitri@Example.org') == 'dmitri@example.org' and k(None) is None and k('#31#') == '#31#'
    when = datetime(2026, 9, 2, 13, 35, tzinfo=UTC)
    secs = (when - MAC_EPOCH).total_seconds()
    assert phones.apple_time(0) is None and phones.apple_time(secs) == phones.apple_time(int(secs) * 10**9) == when  # seconds, or nanoseconds (iOS 11+)
    assert phones.apple_time(secs + 0.5) == when + timedelta(milliseconds=500)


# ------------------------------------------------------------------------------------------------ package roots
def test_phone_roots_are_found(tmp_path):
    a = tmp_path / 'a' / 'Dump'
    for d in ('data/data/com.whatsapp', 'data/system', 'system'):
        (a / d).mkdir(parents=True)
    i = tmp_path / 'i' / 'filesystem1'
    for d in ('private/var/mobile/Library', 'System/Library/CoreServices'):
        (i / d).mkdir(parents=True)
    m = tmp_path / 'm' / 'Macintosh HD'
    for d in ('Users/alice', 'Library', 'private/var/db', 'System'):
        (m / d).mkdir(parents=True)
    assert [(r['path'], r['os']) for r in packages.find_roots(tmp_path / 'a')] == [('Dump', 'android')]
    assert [(r['path'], r['os']) for r in packages.find_roots(tmp_path / 'i')] == [('filesystem1', 'ios')]
    assert [(r['path'], r['os']) for r in packages.find_roots(tmp_path / 'm')] == [('Macintosh HD', 'macos')]
