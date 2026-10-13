"""Phone extractions (Android and iOS full file system dumps): the device, messages (SMS, MMS, iMessage, WhatsApp),
calls, contacts, installed apps and saved Wi-Fi networks.

The parsers read copies of the apps' SQLite databases (read-only) and the system's XML files, property lists and
properties; modules/phone.py finds the files. Android 12 and later write some system XML (packages.xml, settings) in
Android Binary XML (ABX), read here too. Wi-Fi passwords are never read into the results.
"""
from __future__ import annotations
import base64
import re
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as ET

from .unix import MAC_EPOCH, mac_time, plist

UTC = timezone.utc
SMS_TYPES = {1: ('incoming', None), 2: ('outgoing', None), 3: ('outgoing', 'draft'), 4: ('outgoing', 'outbox'), 5: ('outgoing', 'failed'),
             6: ('outgoing', 'queued')}
ANDROID_CALL_TYPES = {1: 'incoming', 2: 'outgoing', 3: 'missed', 4: 'voicemail', 5: 'rejected', 6: 'blocked', 7: 'answered elsewhere'}
IOS_CALL_TYPES = {1: 'Phone', 8: 'FaceTime video', 16: 'FaceTime audio'}
CALL_APPS = {'com.apple.Telephony': 'Phone', 'com.apple.FaceTime': 'FaceTime', 'net.whatsapp.WhatsApp': 'WhatsApp',
             'org.whispersystems.signal': 'Signal', 'ph.telegra.Telegraph': 'Telegram', 'com.skype.skype': 'Skype'}
MMS_ADDR_FROM, MMS_ADDR_TO = 137, 151
WHATSAPP_TYPES = {0: 'text', 1: 'image', 2: 'audio', 3: 'video', 4: 'contact', 5: 'location', 7: 'system', 9: 'document', 13: 'GIF',
                  15: 'deleted', 20: 'sticker', 42: 'view-once image', 43: 'view-once video'}
# Apps that matter to an investigation, by Android package or iOS bundle: (name, category).
KNOWN_APPS = {
    'com.whatsapp': ('WhatsApp', 'messaging'), 'net.whatsapp.WhatsApp': ('WhatsApp', 'messaging'),
    'com.whatsapp.w4b': ('WhatsApp Business', 'messaging'), 'net.whatsapp.WhatsAppSMB': ('WhatsApp Business', 'messaging'),
    'org.thoughtcrime.securesms': ('Signal', 'encrypted messaging'), 'org.whispersystems.signal': ('Signal', 'encrypted messaging'),
    'org.telegram.messenger': ('Telegram', 'messaging'), 'ph.telegra.Telegraph': ('Telegram', 'messaging'),
    'ch.threema.app': ('Threema', 'encrypted messaging'), 'ch.threema.iapp': ('Threema', 'encrypted messaging'),
    'com.wire': ('Wire', 'encrypted messaging'), 'com.wickr.pro': ('Wickr', 'encrypted messaging'),
    'com.snapchat.android': ('Snapchat', 'disappearing messages'), 'com.toyopagroup.picaboo': ('Snapchat', 'disappearing messages'),
    'ch.protonmail.android': ('Proton Mail', 'encrypted email'), 'ch.protonmail.protonmail': ('Proton Mail', 'encrypted email'),
    'com.tutanota': ('Tuta Mail', 'encrypted email'), 'de.tutao.tutanota': ('Tuta Mail', 'encrypted email'),
    'ch.protonvpn.android': ('Proton VPN', 'VPN'), 'ch.protonmail.vpn': ('Proton VPN', 'VPN'),
    'com.nordvpn.android': ('NordVPN', 'VPN'), 'com.nordvpn.NordVPN': ('NordVPN', 'VPN'),
    'com.expressvpn.vpn': ('ExpressVPN', 'VPN'), 'com.expressvpn.ExpressVPN': ('ExpressVPN', 'VPN'),
    'org.torproject.torbrowser': ('Tor Browser', 'anonymity'), 'com.theonionbrowser.onionbrowser': ('Onion Browser', 'anonymity'),
    'org.torproject.android': ('Orbot', 'anonymity'),
    'com.android.chrome': ('Chrome', 'browser'), 'com.google.chrome.ios': ('Chrome', 'browser'),
    'org.mozilla.firefox': ('Firefox', 'browser'), 'org.mozilla.ios.Firefox': ('Firefox', 'browser'),
    'com.dropbox.android': ('Dropbox', 'cloud storage'), 'com.getdropbox.Dropbox': ('Dropbox', 'cloud storage'),
    'com.google.android.apps.docs': ('Google Drive', 'cloud storage'), 'com.google.Drive': ('Google Drive', 'cloud storage'),
    'com.microsoft.skydrive': ('OneDrive', 'cloud storage'), 'me.proton.android.drive': ('Proton Drive', 'cloud storage'),
    'com.wetransfer.app.live': ('WeTransfer', 'file transfer'), 'com.wetransfer.transfer': ('WeTransfer', 'file transfer'),
    'com.piriform.ccleaner': ('CCleaner', 'cleaner'), 'com.protectstar.ishredder.android': ('iShredder', 'secure deletion'),
    'com.protectstar.ishredder': ('iShredder', 'secure deletion'),
}
NOTABLE_CATEGORIES = {'encrypted messaging', 'disappearing messages', 'encrypted email', 'VPN', 'anonymity', 'file transfer', 'cleaner',
                      'secure deletion', 'cloud storage'}


def app_info(app_id: str) -> dict:
    name, category = KNOWN_APPS.get(app_id, (None, None))
    return {'known_name': name, 'category': category, 'notable': category in NOTABLE_CATEGORIES}


# ------------------------------------------------------------------------------------------------ helpers
def epoch_ms(v) -> datetime | None:
    try:
        v = int(v)
        return datetime.fromtimestamp(v / 1000, UTC) if v > 0 else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def epoch_s(v) -> datetime | None:
    try:
        v = int(v)
        return datetime.fromtimestamp(v, UTC) if v > 0 else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def apple_time(v) -> datetime | None:
    """Seconds since 2001 (Core Data), or nanoseconds since 2001 (Messages since iOS 11)."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if not v:
        return None
    if abs(v) > 1e11:
        v /= 1e9
    try:
        return MAC_EPOCH + timedelta(seconds=v)
    except OverflowError:
        return None


def party_key(v) -> str | None:
    """A form of a phone number, email address or WhatsApp JID that matches the other forms of it: the last ten digits
    of a number, or the address in lower case."""
    if not v:
        return None
    v = str(v).strip()
    if v.endswith(('@s.whatsapp.net', '@c.us')):
        v = v.split('@', 1)[0]
    elif '@' in v:
        return v.lower()
    digits = re.sub(r'\D', '', v)
    return digits[-10:] if len(digits) >= 7 else v.lower()


def connect(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    return con


def tables(con) -> set[str]:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")}


def columns(con, table: str) -> set[str]:
    return {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}


def _col(cols: set[str], name: str, alias: str | None = None, prefix: str = '') -> str:
    """`prefix.name AS alias` when the column exists, else `NULL AS alias` (the apps' schemas differ by version)."""
    return f'{prefix}{name} AS {alias or name}' if name in cols else f'NULL AS {alias or name}'


# ------------------------------------------------------------------------------------------------ Android Binary XML
_ABX_MAGIC = b'ABX\x00'
_START_DOCUMENT, _END_DOCUMENT, _START_TAG, _END_TAG, _TEXT, _CDSECT = 0, 1, 2, 3, 4, 5
_ATTRIBUTE = 15


class _AbxReader:
    def __init__(self, data: bytes):
        self.data, self.pos, self.interned = data, len(_ABX_MAGIC), []

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError('ABX: truncated')
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u16(self) -> int:
        return struct.unpack('>H', self.take(2))[0]

    def utf(self) -> str:
        return self.take(self.u16()).decode('utf-8', errors='replace')

    def interned_utf(self) -> str:
        i = self.u16()
        if i == 0xFFFF:
            s = self.utf()
            self.interned.append(s)
            return s
        if i >= len(self.interned):
            raise ValueError('ABX: bad string reference')
        return self.interned[i]

    def value(self, typ: int) -> str | None:
        t = typ >> 4
        if t == 1:
            return None
        if t == 2:
            return self.utf()
        if t == 3:
            return self.interned_utf()
        if t in (4, 5):
            raw = self.take(self.u16())
            return raw.hex() if t == 4 else base64.b64encode(raw).decode()
        if t == 6:
            return str(struct.unpack('>i', self.take(4))[0])
        if t == 7:
            return format(struct.unpack('>i', self.take(4))[0] & 0xFFFFFFFF, 'x')
        if t == 8:
            return str(struct.unpack('>q', self.take(8))[0])
        if t == 9:
            return format(struct.unpack('>q', self.take(8))[0] & 0xFFFFFFFFFFFFFFFF, 'x')
        if t == 10:
            return repr(struct.unpack('>f', self.take(4))[0])
        if t == 11:
            return repr(struct.unpack('>d', self.take(8))[0])
        if t == 12:
            return 'true'
        if t == 13:
            return 'false'
        raise ValueError(f'ABX: unknown value type {t}')


def abx(data: bytes) -> Element:
    """Android Binary XML as an element tree, attribute values in their text forms (longs written as hex stay hex)."""
    r = _AbxReader(data)
    root, stack = None, []
    while r.pos < len(data):
        token = r.take(1)[0]
        cmd, typ = token & 0x0F, token & 0xF0
        if cmd == _ATTRIBUTE:
            name = r.interned_utf()
            v = r.value(typ)
            if stack and v is not None:
                stack[-1].set(name, v)
        elif cmd == _START_TAG:
            el = Element(r.interned_utf())
            if stack:
                stack[-1].append(el)
            elif root is None:
                root = el
            stack.append(el)
        elif cmd == _END_TAG:
            r.interned_utf()
            if stack:
                stack.pop()
        elif cmd in (_START_DOCUMENT, _END_DOCUMENT):
            r.value(typ)
        else:  # text, CDATA, comments, processing instructions, whitespace
            v = r.value(typ)
            if cmd in (_TEXT, _CDSECT) and stack and v:
                stack[-1].text = (stack[-1].text or '') + v
    if root is None:
        raise ValueError('ABX: no root element')
    return root


def android_xml(data: bytes) -> Element:
    return abx(data) if data[:4] == _ABX_MAGIC else ET.fromstring(data)


# ------------------------------------------------------------------------------------------------ Android
def build_prop(data: bytes) -> dict:
    props = {}
    for line in data.decode('utf-8', errors='replace').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            props[k.strip()] = v.strip()
    return props


def android_device(props: dict, settings: dict | None = None, persistent: dict | None = None) -> dict:
    def first(*keys):
        return next((props[k] for k in keys if props.get(k)), None)
    settings, persistent = settings or {}, persistent or {}
    return {'platform': 'Android', 'manufacturer': first('ro.product.manufacturer', 'ro.product.system.manufacturer', 'ro.product.vendor.manufacturer'),
            'model': first('ro.product.model', 'ro.product.system.model', 'ro.product.vendor.model'),
            'brand': first('ro.product.brand', 'ro.product.system.brand'),
            'device': first('ro.product.device', 'ro.product.system.device'),
            'os_version': first('ro.build.version.release', 'ro.system.build.version.release'),
            'build': first('ro.build.display.id', 'ro.build.id', 'ro.system.build.id'),
            'security_patch': first('ro.build.version.security_patch'),
            'fingerprint': first('ro.build.fingerprint', 'ro.system.build.fingerprint'),
            'name': settings.get('device_name') or settings.get('bluetooth_name'),
            'time_zone': persistent.get('persist.sys.timezone') or props.get('persist.sys.timezone')}


def android_settings(data: bytes) -> dict:
    """settings_global.xml / settings_secure.xml: {name: value}."""
    out = {}
    for s in android_xml(data).iter('setting'):
        if s.get('name'):
            out[s.get('name')] = s.get('value')
    return out


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    v = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, pos
        shift += 7
    raise ValueError('truncated varint')


def persistent_properties(data: bytes) -> dict:
    """/data/property/persistent_properties: a protobuf of (name, value) entries."""
    out, pos = {}, 0

    def fields(buf):
        p = 0
        while p < len(buf):
            key, p = _varint(buf, p)
            if key & 7 == 2:
                n, p = _varint(buf, p)
                yield key >> 3, buf[p:p + n]
                p += n
            elif key & 7 == 0:
                _, p = _varint(buf, p)
            else:
                return
    try:
        for num, entry in fields(data):
            if num == 1:
                kv = dict(fields(entry))
                if 1 in kv:
                    out[kv[1].decode(errors='replace')] = kv.get(2, b'').decode(errors='replace')
    except ValueError:
        pass
    return out


def android_sms(db: Path) -> list[dict]:
    """mmssms.db: SMS, and MMS with their text and attached files."""
    con = connect(db)
    out = []
    try:
        have = tables(con)
        if 'sms' in have:
            cols = columns(con, 'sms')
            for r in con.execute(f'SELECT _id, address, date, type, body, {_col(cols, "read")}, {_col(cols, "thread_id")}, '
                                 f'{_col(cols, "date_sent")} FROM sms ORDER BY date'):
                direction, status = SMS_TYPES.get(r['type'], ('incoming' if r['type'] == 1 else 'outgoing', None))
                out.append({'app': 'SMS', 'id': f'sms:{r["_id"]}', 'time': epoch_ms(r['date']), 'sent_time': epoch_ms(r['date_sent']),
                            'party': r['address'], 'direction': direction, 'status': status, 'text': r['body'], 'thread': r['thread_id'],
                            'read': bool(r['read']) if r['read'] is not None else None, 'attachments': []})
        if {'pdu', 'part', 'addr'} <= have:
            parts, addrs = {}, {}
            for p in con.execute('SELECT mid, ct, text, ' + _col(columns(con, 'part'), 'name') + ', ' + _col(columns(con, 'part'), 'cl') + ', '
                                 + _col(columns(con, 'part'), '_data', 'data') + ' FROM part ORDER BY _id'):
                parts.setdefault(p['mid'], []).append(p)
            for a in con.execute('SELECT msg_id, address, type FROM addr'):
                if a['address'] and a['address'] != 'insert-address-token':
                    addrs.setdefault(a['msg_id'], []).append((a['type'], a['address']))
            cols = columns(con, 'pdu')
            for r in con.execute(f'SELECT _id, date, msg_box, {_col(cols, "sub")}, {_col(cols, "thread_id")}, {_col(cols, "read")} FROM pdu ORDER BY date'):
                outgoing = r['msg_box'] in (2, 4)
                party = [a for t, a in addrs.get(r['_id'], []) if t == (MMS_ADDR_TO if outgoing else MMS_ADDR_FROM)]
                text = '\n'.join(p['text'] for p in parts.get(r['_id'], []) if p['ct'] == 'text/plain' and p['text'])
                atts = [{'name': p['name'] or p['cl'] or (p['data'] or '').rsplit('/', 1)[-1] or None, 'mime_type': p['ct'], 'device_path': p['data']}
                        for p in parts.get(r['_id'], []) if p['ct'] not in ('text/plain', 'application/smil')]
                out.append({'app': 'MMS', 'id': f'mms:{r["_id"]}', 'time': epoch_s(r['date']), 'party': ', '.join(party) or None,
                            'direction': 'outgoing' if outgoing else 'incoming', 'status': 'draft' if r['msg_box'] == 3 else None,
                            'text': '\n'.join(x for x in (r['sub'], text) if x) or None, 'thread': r['thread_id'],
                            'read': bool(r['read']) if r['read'] is not None else None, 'attachments': atts})
    finally:
        con.close()
    return out


def android_calls(db: Path) -> list[dict]:
    """calllog.db (Android 7 and later) or contacts2.db (earlier): the `calls` table."""
    con = connect(db)
    try:
        if 'calls' not in tables(con):
            return []
        cols = columns(con, 'calls')
        rows = con.execute(f'SELECT _id, number, date, duration, type, {_col(cols, "name")}, {_col(cols, "features")}, '
                           f'{_col(cols, "geocoded_location")}, {_col(cols, "countryiso")}, {_col(cols, "subscription_component_name", "via")} '
                           'FROM calls ORDER BY date').fetchall()
    finally:
        con.close()
    return [{'id': f'call:{r["_id"]}', 'time': epoch_ms(r['date']), 'party': r['number'], 'party_name': r['name'],
             'direction': ANDROID_CALL_TYPES.get(r['type'], str(r['type'])), 'duration': r['duration'],
             'kind': 'Video' if (r['features'] or 0) & 1 else 'Phone', 'app': 'Phone', 'location': r['geocoded_location'],
             'country': r['countryiso']} for r in rows]


def android_contacts(db: Path) -> list[dict]:
    """contacts2.db: each contact (not deleted) with its numbers and email addresses."""
    con = connect(db)
    try:
        if not {'raw_contacts', 'data', 'mimetypes'} <= tables(con):
            return []
        cols = columns(con, 'raw_contacts')
        deleted = 'WHERE COALESCE(r.deleted, 0) = 0' if 'deleted' in cols else ''
        rows = con.execute(f'SELECT r._id AS id, {_col(cols, "display_name", prefix="r.")}, m.mimetype, d.data1 FROM raw_contacts r '
                           f'LEFT JOIN data d ON d.raw_contact_id = r._id LEFT JOIN mimetypes m ON m._id = d.mimetype_id {deleted} '
                           'ORDER BY r._id, d._id').fetchall()
    finally:
        con.close()
    people = {}
    for r in rows:
        p = people.setdefault(r['id'], {'name': r['display_name'], 'numbers': [], 'emails': []})
        mt, v = r['mimetype'] or '', r['data1']
        if not v:
            continue
        if mt.endswith('/phone_v2'):
            p['numbers'].append(v)
        elif mt.endswith('/email_v2'):
            p['emails'].append(v)
        elif mt.endswith('/name') and not p['name']:
            p['name'] = v
    return [dict(p, id=f'contact:{k}', source='Contacts') for k, p in people.items() if p['name'] or p['numbers'] or p['emails']]


def whatsapp_android(db: Path) -> list[dict]:
    """msgstore.db, in its current layout (message, chat, jid) or the layout before 2022 (messages)."""
    con = connect(db)
    out = []
    try:
        have = tables(con)
        media = {}
        if 'message' in have and {'chat', 'jid'} <= have:
            jcols = columns(con, 'jid')
            jid = (lambda a: f'COALESCE({a}.raw_string, {a}.user || \'@\' || {a}.server)') if 'raw_string' in jcols else (lambda a: f"{a}.user || '@' || {a}.server")
            if 'message_media' in have:
                mc = columns(con, 'message_media')
                for m in con.execute(f'SELECT message_row_id, {_col(mc, "file_path")}, {_col(mc, "mime_type")}, {_col(mc, "file_size")}, '
                                     f'{_col(mc, "media_name")} FROM message_media'):
                    media[m['message_row_id']] = {'name': m['media_name'] or (m['file_path'] or '').rsplit('/', 1)[-1] or None,
                                                  'mime_type': m['mime_type'], 'size': m['file_size'], 'device_path': m['file_path']}
            cols, ccols = columns(con, 'message'), columns(con, 'chat')
            rows = con.execute(f'SELECT m._id, m.from_me, m.timestamp, {_col(cols, "text_data", prefix="m.")}, {_col(cols, "message_type", prefix="m.")}, '
                               f'{_col(cols, "key_id", prefix="m.")}, {_col(cols, "status", prefix="m.")}, {jid("cj")} AS chat_jid, '
                               f'{_col(ccols, "subject", prefix="c.")}, {jid("sj")} AS sender_jid '
                               'FROM message m LEFT JOIN chat c ON c._id = m.chat_row_id LEFT JOIN jid cj ON cj._id = c.jid_row_id '
                               'LEFT JOIN jid sj ON sj._id = m.sender_jid_row_id ORDER BY m.timestamp').fetchall()
            for r in rows:
                if r['chat_jid'] is None and r['text_data'] is None:
                    continue
                out.append(_wa(r['_id'], r['chat_jid'], r['subject'], bool(r['from_me']), r['sender_jid'], epoch_ms(r['timestamp']), r['text_data'],
                               r['message_type'], r['key_id'], media.get(r['_id'])))
        elif 'messages' in have:
            cols = columns(con, 'messages')
            sel = ', '.join(_col(cols, c) for c in ('key_remote_jid', 'key_from_me', 'key_id', 'data', 'timestamp', 'media_mime_type', 'media_name',
                                                     'media_size', 'remote_resource', 'media_wa_type', 'media_caption'))
            subjects = {}
            if 'chat_list' in have and 'subject' in columns(con, 'chat_list'):
                subjects = {r[0]: r[1] for r in con.execute('SELECT key_remote_jid, subject FROM chat_list')}
            for r in con.execute(f'SELECT _id, {sel} FROM messages ORDER BY timestamp'):
                if r['key_remote_jid'] in (None, '-1'):
                    continue
                att = {'name': r['media_name'], 'mime_type': r['media_mime_type'], 'size': r['media_size'], 'device_path': None} \
                    if r['media_mime_type'] or r['media_name'] else None
                mtype = int(r['media_wa_type']) if str(r['media_wa_type'] or '').isdigit() else 0
                out.append(_wa(r['_id'], r['key_remote_jid'], subjects.get(r['key_remote_jid']), bool(r['key_from_me']), r['remote_resource'] or None,
                               epoch_ms(r['timestamp']), r['data'] or r['media_caption'], mtype, r['key_id'], att))
    finally:
        con.close()
    return out


def _wa(row_id, chat_jid, subject, from_me, sender, when, text, mtype, key_id, attachment) -> dict:
    group = bool(chat_jid and chat_jid.endswith('@g.us'))
    return {'app': 'WhatsApp', 'id': f'wa:{row_id}', 'time': when, 'party': chat_jid, 'chat_name': subject, 'group': group,
            'sender': None if from_me else (sender if group else chat_jid), 'direction': 'outgoing' if from_me else 'incoming',
            'text': text, 'message_type': WHATSAPP_TYPES.get(mtype or 0, str(mtype)), 'key_id': key_id,
            'attachments': [attachment] if attachment else []}


def whatsapp_contacts(db: Path) -> list[dict]:
    """wa.db: the people WhatsApp knows, with their numbers."""
    con = connect(db)
    try:
        if 'wa_contacts' not in tables(con):
            return []
        cols = columns(con, 'wa_contacts')
        rows = con.execute(f'SELECT jid, {_col(cols, "display_name")}, {_col(cols, "wa_name")}, {_col(cols, "number")}, '
                           f'{_col(cols, "is_whatsapp_user")} FROM wa_contacts').fetchall()
    finally:
        con.close()
    return [{'id': f'wa:{r["jid"]}', 'name': r['display_name'] or r['wa_name'], 'numbers': [r['number'] or r['jid'].split('@', 1)[0]],
             'emails': [], 'whatsapp_id': r['jid'], 'source': 'WhatsApp'}
            for r in rows if r['jid'] and r['jid'].endswith('@s.whatsapp.net') and (r['display_name'] or r['wa_name'])]


def android_packages(data: bytes) -> tuple[list[dict], int]:
    """packages.xml (text or ABX): apps installed by the user, and how many system apps there are."""
    root = android_xml(data)
    apps, system = [], 0
    for p in root.iter('package'):
        name, code = p.get('name'), p.get('codePath') or ''
        if not name:
            continue
        flags = int(p.get('flags') or p.get('pkgFlags') or 0) if (p.get('flags') or p.get('pkgFlags') or '0').lstrip('-').isdigit() else 0
        if flags & 1 or code.startswith(('/system/', '/product/', '/vendor/', '/apex/', '/system_ext/')):
            system += 1
            continue

        def hexms(k):
            v = p.get(k)
            try:
                return epoch_ms(int(v, 16)) if v else None
            except ValueError:
                return None
        installer = p.get('installer') or p.get('installInitiator')
        src = p.find('install-source') if p.find('install-source') is not None else None
        if src is not None and not installer:
            installer = src.get('installerPackageName') or src.get('installInitiator')
        apps.append({'app_id': name, 'version': p.get('version'), 'installed': hexms('it'), 'updated': hexms('ut'), 'installer': installer,
                     'path': code, 'uid': p.get('userId') or p.get('sharedUserId'), **app_info(name)})
    return apps, system


def android_packages_list(data: bytes) -> list[dict]:
    """packages.list: one line per app (name, uid, debuggable, data folder ...), no install times."""
    out = []
    for line in data.decode('utf-8', errors='replace').splitlines():
        f = line.split()
        if len(f) >= 4 and f[3].startswith('/data/'):
            out.append({'app_id': f[0], 'uid': f[1], 'path': f[3], 'version': None, 'installed': None, 'updated': None, 'installer': None,
                        **app_info(f[0])})
    return out


def android_wifi(data: bytes) -> list[dict]:
    """WifiConfigStore.xml: saved networks (name, security, hidden, the router's MAC address). Passwords are skipped."""
    out = []
    for net in android_xml(data).iter('Network'):
        conf = net.find('WifiConfiguration')
        if conf is None:
            continue
        vals = {}
        for el in conf:
            if el.get('name'):
                vals[el.get('name')] = el.get('value') if el.get('value') is not None else (el.text or '')
        ssid = (vals.get('SSID') or '').strip()
        if ssid.startswith('"') and ssid.endswith('"'):
            ssid = ssid[1:-1]
        key = vals.get('ConfigKey') or ''
        out.append({'ssid': ssid or None, 'security': key.rsplit('"', 1)[-1] or None if '"' in key else None,
                    'hidden': vals.get('HiddenSSID') == 'true', 'router_mac': vals.get('DefaultGwMacAddress') or None,
                    'created_by': vals.get('CreatorName') or None, 'added': None, 'last_joined': None})
    return out


def wpa_supplicant(data: bytes) -> list[dict]:
    """wpa_supplicant.conf (Android 7 and earlier): network blocks (the psk line is skipped)."""
    out = []
    for block in re.findall(r'network=\{(.*?)\}', data.decode('utf-8', errors='replace'), re.S):
        vals = dict(re.findall(r'^\s*(\w+)=(.*)$', block, re.M))
        ssid = vals.get('ssid', '').strip()
        out.append({'ssid': ssid[1:-1] if ssid.startswith('"') else ssid or None, 'security': vals.get('key_mgmt'),
                    'hidden': vals.get('scan_ssid') == '1', 'router_mac': None, 'created_by': None, 'added': None, 'last_joined': None})
    return out


# ------------------------------------------------------------------------------------------------ iOS
def ios_device(version: bytes, ark: bytes) -> dict:
    v, a = plist(version), plist(ark)
    return {'platform': 'iOS', 'manufacturer': 'Apple', 'model': a.get('-ProductType') or None, 'brand': 'Apple', 'device': None,
            'os_version': v.get('ProductVersion'), 'build': v.get('ProductBuildVersion'), 'security_patch': None, 'fingerprint': None,
            'name': a.get('-DeviceName'), 'time_zone': a.get('-TimeZone'), 'product': v.get('ProductName')}


def attributed_text(blob) -> str | None:
    """The text of a message stored only as an NSAttributedString (Messages since iOS 16): the string after `NSString`."""
    if not blob:
        return None
    blob = bytes(blob)
    i = blob.find(b'NSString')
    if i < 0:
        return None
    rest = blob[i + 8:]
    j = rest.find(b'+')
    if j < 0 or j > 8 or j + 2 > len(rest):
        return None
    rest = rest[j + 1:]
    n, rest = rest[0], rest[1:]
    if n == 0x81:
        n, rest = int.from_bytes(rest[:2], 'little'), rest[2:]
    elif n == 0x82:
        n, rest = int.from_bytes(rest[:4], 'little'), rest[4:]
    return rest[:n].decode('utf-8', errors='replace') or None


def ios_messages(db: Path) -> list[dict]:
    """sms.db: iMessage, SMS and RCS messages with their attachments."""
    con = connect(db)
    try:
        have = tables(con)
        cols = columns(con, 'message')
        chat = ("(SELECT c.chat_identifier FROM chat_message_join j JOIN chat c ON c.ROWID = j.chat_id WHERE j.message_id = m.ROWID LIMIT 1)"
                if {'chat', 'chat_message_join'} <= have else 'NULL')
        chat_name = ("(SELECT c.display_name FROM chat_message_join j JOIN chat c ON c.ROWID = j.chat_id WHERE j.message_id = m.ROWID LIMIT 1)"
                     if {'chat', 'chat_message_join'} <= have and 'display_name' in columns(con, 'chat') else 'NULL')
        rows = con.execute(f'SELECT m.ROWID AS id, {_col(cols, "guid", prefix="m.")}, {_col(cols, "text", prefix="m.")}, '
                           f'{_col(cols, "attributedBody", prefix="m.")}, {_col(cols, "service", prefix="m.")}, m.date, m.is_from_me, '
                           f'{_col(cols, "date_read", prefix="m.")}, {_col(cols, "is_read", prefix="m.")}, h.id AS handle, {chat} AS chat, '
                           f'{chat_name} AS chat_name FROM message m LEFT JOIN handle h ON h.ROWID = m.handle_id ORDER BY m.date').fetchall()
        atts = {}
        if {'attachment', 'message_attachment_join'} <= have:
            ac = columns(con, 'attachment')
            for a in con.execute(f'SELECT j.message_id, {_col(ac, "filename", prefix="a.")}, {_col(ac, "mime_type", prefix="a.")}, '
                                 f'{_col(ac, "transfer_name", prefix="a.")}, {_col(ac, "total_bytes", prefix="a.")} '
                                 'FROM message_attachment_join j JOIN attachment a ON a.ROWID = j.attachment_id'):
                atts.setdefault(a['message_id'], []).append({'name': a['transfer_name'] or (a['filename'] or '').rsplit('/', 1)[-1] or None,
                                                             'mime_type': a['mime_type'], 'size': a['total_bytes'], 'device_path': a['filename']})
    finally:
        con.close()
    out = []
    for r in rows:
        text = r['text'] if r['text'] not in (None, '￼') else attributed_text(r['attributedBody']) or r['text']
        party = r['handle'] or r['chat']
        out.append({'app': r['service'] or 'iMessage', 'id': f'msg:{r["id"]}', 'guid': r['guid'], 'time': apple_time(r['date']), 'party': party,
                    'chat_name': r['chat_name'] or None, 'group': bool(r['chat'] and r['chat'].startswith('chat')),
                    'direction': 'outgoing' if r['is_from_me'] else 'incoming', 'text': text, 'read_time': apple_time(r['date_read']),
                    'read': bool(r['is_read']) if r['is_read'] is not None else None, 'attachments': atts.get(r['id'], [])})
    return out


def ios_calls(db: Path) -> list[dict]:
    """CallHistory.storedata: phone, FaceTime and app (WhatsApp, Signal ...) calls."""
    con = connect(db)
    try:
        if 'ZCALLRECORD' not in tables(con):
            return []
        cols = columns(con, 'ZCALLRECORD')
        sel = ', '.join(_col(cols, c) for c in ('ZADDRESS', 'ZDATE', 'ZDURATION', 'ZORIGINATED', 'ZANSWERED', 'ZCALLTYPE', 'ZNAME',
                                                 'ZSERVICE_PROVIDER', 'ZLOCATION', 'ZISO_COUNTRY_CODE'))
        rows = con.execute(f'SELECT Z_PK, {sel} FROM ZCALLRECORD ORDER BY ZDATE').fetchall()
    finally:
        con.close()
    out = []
    for r in rows:
        addr = r['ZADDRESS']
        if isinstance(addr, bytes):
            addr = addr.decode('utf-8', errors='replace')
        provider = r['ZSERVICE_PROVIDER'] or 'com.apple.Telephony'
        app = CALL_APPS.get(provider, provider)
        kind = IOS_CALL_TYPES.get(r['ZCALLTYPE'], 'Phone') if provider in ('com.apple.FaceTime', 'com.apple.Telephony') else app
        direction = 'outgoing' if r['ZORIGINATED'] else 'incoming' if r['ZANSWERED'] else 'missed'
        out.append({'id': f'call:{r["Z_PK"]}', 'time': apple_time(r['ZDATE']), 'party': addr, 'party_name': r['ZNAME'], 'direction': direction,
                    'duration': round(r['ZDURATION']) if r['ZDURATION'] is not None else None, 'kind': kind, 'app': app,
                    'location': r['ZLOCATION'], 'country': r['ZISO_COUNTRY_CODE']})
    return out


def ios_contacts(db: Path) -> list[dict]:
    """AddressBook.sqlitedb: people with their numbers (property 3) and email addresses (property 4)."""
    con = connect(db)
    try:
        if not {'ABPerson', 'ABMultiValue'} <= tables(con):
            return []
        cols = columns(con, 'ABPerson')
        rows = con.execute(f'SELECT p.ROWID AS id, {_col(cols, "First", prefix="p.")}, {_col(cols, "Last", prefix="p.")}, '
                           f'{_col(cols, "Organization", prefix="p.")}, v.property, v.value FROM ABPerson p '
                           'LEFT JOIN ABMultiValue v ON v.record_id = p.ROWID ORDER BY p.ROWID, v.UID').fetchall()
    finally:
        con.close()
    people = {}
    for r in rows:
        name = ' '.join(x for x in (r['First'], r['Last']) if x) or r['Organization']
        p = people.setdefault(r['id'], {'name': name, 'organization': r['Organization'], 'numbers': [], 'emails': []})
        if r['value']:
            if r['property'] == 3:
                p['numbers'].append(r['value'])
            elif r['property'] == 4:
                p['emails'].append(r['value'])
    return [dict(p, id=f'contact:{k}', source='Contacts') for k, p in people.items() if p['name'] or p['numbers'] or p['emails']]


def whatsapp_ios(db: Path) -> list[dict]:
    """ChatStorage.sqlite: WhatsApp messages on an iPhone."""
    con = connect(db)
    out = []
    try:
        have = tables(con)
        if not {'ZWAMESSAGE', 'ZWACHATSESSION'} <= have:
            return []
        cols = columns(con, 'ZWAMESSAGE')
        media = {}
        if 'ZWAMEDIAITEM' in have:
            mc = columns(con, 'ZWAMEDIAITEM')
            for m in con.execute(f'SELECT ZMESSAGE, {_col(mc, "ZMEDIALOCALPATH")}, {_col(mc, "ZFILESIZE")}, {_col(mc, "ZTITLE")} FROM ZWAMEDIAITEM'):
                media[m['ZMESSAGE']] = {'name': (m['ZMEDIALOCALPATH'] or '').rsplit('/', 1)[-1] or m['ZTITLE'], 'mime_type': None, 'size': m['ZFILESIZE'],
                                        'device_path': m['ZMEDIALOCALPATH']}
        member = ''
        if 'ZWAGROUPMEMBER' in have and 'ZGROUPMEMBER' in cols:
            member = ', (SELECT g.ZMEMBERJID FROM ZWAGROUPMEMBER g WHERE g.Z_PK = m.ZGROUPMEMBER) AS member'
        rows = con.execute(f'SELECT m.Z_PK, m.ZISFROMME, m.ZMESSAGEDATE, {_col(cols, "ZTEXT", prefix="m.")}, {_col(cols, "ZMESSAGETYPE", prefix="m.")}, '
                           f'{_col(cols, "ZSTANZAID", prefix="m.")}, s.ZCONTACTJID, s.ZPARTNERNAME{member} '
                           'FROM ZWAMESSAGE m LEFT JOIN ZWACHATSESSION s ON s.Z_PK = m.ZCHATSESSION ORDER BY m.ZMESSAGEDATE').fetchall()
        for r in rows:
            m = _wa(r['Z_PK'], r['ZCONTACTJID'], r['ZPARTNERNAME'], bool(r['ZISFROMME']), r['member'] if member else None,
                    apple_time(r['ZMESSAGEDATE']), r['ZTEXT'], r['ZMESSAGETYPE'], r['ZSTANZAID'], media.get(r['Z_PK']))
            if not m['group']:
                m['chat_name'] = None
                m['party_name'] = r['ZPARTNERNAME']
            out.append(m)
    finally:
        con.close()
    return out


def ios_app(info: bytes, metadata: bytes | None = None) -> dict | None:
    """An installed app's Info.plist (with iTunesMetadata.plist, when present, for the purchase date and seller)."""
    p = plist(info)
    bundle = p.get('CFBundleIdentifier')
    if not bundle:
        return None
    meta = plist(metadata or b'')
    bought = (meta.get('com.apple.iTunesStore.downloadInfo') or {}).get('purchaseDate') or meta.get('purchaseDate')
    when = mac_time(bought) if isinstance(bought, datetime) else _iso(bought)
    return {'app_id': bundle, 'name': p.get('CFBundleDisplayName') or p.get('CFBundleName'), 'version': p.get('CFBundleShortVersionString') or p.get('CFBundleVersion'),
            'installed': when, 'updated': None, 'installer': meta.get('artistName'), 'uid': None, **app_info(bundle)}


def _iso(v):
    try:
        return datetime.fromisoformat(str(v).replace('Z', '+00:00')).astimezone(UTC) if v else None
    except ValueError:
        return None


def ios_wifi_legacy(data: bytes) -> list[dict]:
    """com.apple.wifi.plist (iOS 13 and earlier): 'List of known networks'."""
    out = []
    for n in plist(data).get('List of known networks') or []:
        if isinstance(n, dict):
            joined = [t for t in (mac_time(n.get('lastJoined')), mac_time(n.get('lastAutoJoined'))) if t]
            out.append({'ssid': n.get('SSID_STR'), 'security': n.get('SecurityMode'), 'hidden': bool(n.get('HIDDEN_NETWORK')),
                        'router_mac': n.get('BSSID'), 'created_by': None, 'added': mac_time(n.get('addedAt')),
                        'last_joined': max(joined) if joined else None})
    return out
