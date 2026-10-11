"""Email stores: Outlook PST/OST (libpff), MBOX files and Thunderbird folders, single EML and Outlook MSG files.

Every parser yields messages as dictionaries with the same fields (folder, sender, recipients, dates, subject, the
plain-text and HTML bodies, the transport headers, flags) and calls `store(data, name)` for each attachment and
inline picture, which saves it (under its SHA-256, never under its own name) and returns what to record about it.
Bodies are kept as text: HTML is shown only after sanitising, in a sandbox that loads nothing remote.

Times are UTC: PST and MSG keep FILETIMEs; for MBOX and EML the Date header (sent) and the newest Received header
(when it arrived) are used.
"""
from __future__ import annotations
import email
import email.policy
import email.utils
import html
import mailbox
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator

MAX_MESSAGES = 200_000
MAX_TEXT = 256 * 1024
MAX_HTML = 1024 * 1024
MAX_HEADERS = 64 * 1024
MAX_ATTACHMENT = 64 << 20
MOZ_FLAGS = {0x0001: 'read', 0x0002: 'replied', 0x0004: 'flagged', 0x0008: 'deleted', 0x1000: 'forwarded'}
SENT_FOLDER = re.compile(r'(^|/)(sent|sent items|sent mail|sent messages|outbox|gesendete|envoy|enviados|inviata|verzonden)', re.I)

Store = Callable[[bytes, str, str | None], dict]


def _utc(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _date(value):
    try:
        return _utc(email.utils.parsedate_to_datetime(str(value))) if value else None
    except (TypeError, ValueError, IndexError):
        return None


def _received_time(msg):
    """The time on the newest Received header (the last hop: when the message reached this mailbox)."""
    for h in msg.get_all('Received') or []:
        part = str(h).rsplit(';', 1)
        if len(part) == 2:
            t = _date(part[1].strip())
            if t:
                return t
    return None


def _addresses(value) -> list[dict]:
    if not value:
        return []
    try:
        pairs = email.utils.getaddresses([str(value)])
    except (TypeError, ValueError, IndexError):
        return [{'name': None, 'address': str(value)[:300]}]
    return [{'name': n or None, 'address': a or None} for n, a in pairs if n or a][:500]


def html_to_text(markup: str) -> str:
    """A readable plain-text version of an HTML body (for search and the text view)."""
    s = re.sub(r'(?is)<(script|style|head)\b.*?</\1\s*>', ' ', markup)
    s = re.sub(r'(?i)<br\s*/?>|</(p|div|tr|li|h[1-6])\s*>', '\n', s)
    s = re.sub(r'(?s)<[^>]*>', '', s)
    s = html.unescape(s)
    s = re.sub(r'[ \t\r\f\v]+', ' ', s)
    return re.sub(r'\n\s*\n+', '\n\n', s).strip()


def _cap(text, limit):
    if text is None:
        return None, False
    return (text[:limit], True) if len(text) > limit else (text, False)


def _finish(m: dict) -> dict:
    """Fills the derived fields: text from HTML when there is no plain part, caps, the sent/received direction."""
    if not m.get('body_text') and m.get('body_html'):
        m['body_text'] = html_to_text(m['body_html'])
    m['body_text'], t1 = _cap(m.get('body_text'), MAX_TEXT)
    m['body_html'], t2 = _cap(m.get('body_html'), MAX_HTML)
    m['headers'], _ = _cap(m.get('headers'), MAX_HEADERS)
    m['truncated'] = t1 or t2
    m['has_html'] = bool(m.get('body_html'))
    m['direction'] = 'sent' if SENT_FOLDER.search(m.get('folder') or '') else 'received'
    m['attachment_count'] = sum(1 for a in m.get('attachments', []) if not a.get('inline'))
    m['snippet'] = re.sub(r'\s+', ' ', (m.get('body_text') or '')[:400]).strip()[:200]
    return m


# -- RFC 822 messages (MBOX, EML) ---------------------------------------------------------------------------------
def _text_of(part) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeError, AssertionError, KeyError, ValueError):
        raw = part.get_payload(decode=True) or b''
        return raw.decode('utf-8', 'replace')


def from_rfc822(raw: bytes, folder: str, store: Store, index: int) -> dict:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    h = lambda k: _safe_header(msg, k)
    plain = msg.get_body(preferencelist=('plain',)) if msg.is_multipart() or msg.get_content_type() == 'text/plain' else None
    rich = msg.get_body(preferencelist=('html',)) if msg.is_multipart() or msg.get_content_type() == 'text/html' else None
    sender = _addresses(h('From'))
    m = {'folder': folder, 'index': index, 'message_id': (h('Message-ID') or '').strip() or None, 'subject': h('Subject'),
         'from_name': sender[0]['name'] if sender else None, 'from_address': sender[0]['address'] if sender else None,
         'to': _addresses(h('To')), 'cc': _addresses(h('Cc')), 'bcc': _addresses(h('Bcc')), 'reply_to': _addresses(h('Reply-To')),
         'sent': _date(h('Date')), 'received': _received_time(msg), 'in_reply_to': h('In-Reply-To'),
         'originating_ip': h('X-Originating-IP'), 'user_agent': h('User-Agent') or h('X-Mailer'),
         'headers': _header_block(raw), 'body_text': _text_of(plain) if plain is not None else None,
         'body_html': _text_of(rich) if rich is not None else None, 'attachments': [], 'flags': []}
    status = h('X-Mozilla-Status')
    if status and re.fullmatch(r'[0-9a-fA-F]{1,8}', status.strip()):
        bits = int(status.strip(), 16)
        m['flags'] = [name for bit, name in MOZ_FLAGS.items() if bits & bit]
    m['deleted'] = 'deleted' in m['flags']
    for part in msg.walk():
        if part.is_multipart() or part is plain or part is rich:
            continue
        ctype = part.get_content_type()
        name = part.get_filename()
        cid = (part.get('Content-ID') or '').strip().strip('<>') or None
        if ctype == 'message/rfc822':
            inner = part.get_payload()
            data = (inner[0] if isinstance(inner, list) and inner else part).as_bytes()
            name = name or 'attached message.eml'
        else:
            data = part.get_payload(decode=True)
            if data is None:
                continue
            if not name and not cid and ctype.startswith('text/'):
                name = 'body.' + ('html' if ctype == 'text/html' else 'txt')
        inline = bool(cid) and (part.get_content_disposition() != 'attachment')
        m['attachments'].append(_attachment(store, data, name or f'part-{len(m["attachments"]) + 1}', ctype, cid, inline))
    return _finish(m)


def _safe_header(msg, key):
    try:
        v = msg.get(key)
        return str(v) if v is not None else None
    except (TypeError, ValueError, IndexError, AttributeError):
        return None


def _header_block(raw: bytes) -> str:
    end = raw.find(b'\r\n\r\n')
    end = raw.find(b'\n\n') if end < 0 else end
    return raw[:end if end >= 0 else MAX_HEADERS].decode('utf-8', 'replace')


def _attachment(store: Store, data: bytes, name: str, mime: str | None, cid: str | None, inline: bool) -> dict:
    size = len(data)
    if size > MAX_ATTACHMENT:
        return {'name': name, 'size': size, 'mime': mime, 'content_id': cid, 'inline': inline, 'stored': False,
                'note': f'over {MAX_ATTACHMENT >> 20} MiB: not extracted'}
    info = store(data, name, mime)
    return {'name': name, 'size': size, 'mime': mime, 'content_id': cid, 'inline': inline, 'stored': True, **info}


def parse_mbox(path: Path, folder: str, store: Store, limit: int = MAX_MESSAGES) -> Iterator[dict]:
    box = mailbox.mbox(str(path), create=False)
    try:
        for i, key in enumerate(box.iterkeys()):
            if i >= limit:
                break
            yield from_rfc822(box.get_bytes(key), folder, store, i)
    finally:
        box.close()


def parse_eml(path: Path, folder: str, store: Store) -> dict:
    return from_rfc822(path.read_bytes()[:256 << 20], folder, store, 0)


def looks_like_mbox(path: Path) -> bool:
    with path.open('rb') as f:
        head = f.read(5)
    return head == b'From '


# -- Outlook MSG (OLE compound file) -----------------------------------------------------------------------------
def _filetime(v: int):
    if not v:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)
    except OverflowError:
        return None


def parse_msg(path: Path, folder: str, store: Store) -> dict:
    import olefile
    ole = olefile.OleFileIO(str(path))
    try:
        def stream(prefix, prop, binary=False):
            for kind in (('0102',) if binary else ('001F', '001E', '0102')):
                name = f'{prefix}__substg1.0_{prop}{kind}'
                if ole.exists(name):
                    data = ole.openstream(name).read()
                    if binary or kind == '0102':
                        return data
                    return data.decode('utf-16-le' if kind == '001F' else 'cp1252', 'replace').rstrip('\x00')
            return None

        def props(prefix, header):
            out = {}
            name = f'{prefix}__properties_version1.0'
            if not ole.exists(name):
                return out
            data = ole.openstream(name).read()
            for off in range(header, len(data) - 15, 16):
                ptype, pid = struct.unpack('<HH', data[off:off + 4])
                out[pid] = (ptype, data[off + 8:off + 16])
            return out

        top = props('', 32)
        when = lambda pid: _filetime(struct.unpack('<Q', top[pid][1])[0]) if pid in top and top[pid][0] == 0x0040 else None
        headers = stream('', '007D')
        hmsg = email.message_from_string(headers or '', policy=email.policy.default) if headers else None
        body_html = stream('', '1013', binary=True)
        if isinstance(body_html, bytes):
            body_html = body_html.decode('utf-8', 'replace')
        sender_addr = stream('', '5D01') or stream('', '0C1F') or stream('', '0065')
        m = {'folder': folder, 'index': 0, 'message_id': stream('', '1035'), 'subject': stream('', '0037'),
             'from_name': stream('', '0C1A') or stream('', '0042'), 'from_address': sender_addr if sender_addr and '@' in sender_addr else None,
             'to': [], 'cc': [], 'bcc': [], 'reply_to': [], 'sent': when(0x0039), 'received': when(0x0E06),
             'in_reply_to': stream('', '1042'), 'headers': headers, 'body_text': stream('', '1000'), 'body_html': body_html,
             'attachments': [], 'flags': [], 'deleted': False,
             'originating_ip': _safe_header(hmsg, 'X-Originating-IP') if hmsg else None, 'user_agent': None}
        kinds = {1: 'to', 2: 'cc', 3: 'bcc'}
        for entry in ole.listdir(streams=False, storages=True):
            top_name = entry[0]
            if len(entry) != 1:
                continue
            if top_name.startswith('__recip_version1.0_'):
                p = f'{top_name}/'
                rp = props(p, 8)
                kind = struct.unpack('<I', rp[0x0C15][1][:4])[0] if 0x0C15 in rp else 1
                addr = stream(p, '39FE') or stream(p, '3003')
                m[kinds.get(kind, 'to')].append({'name': stream(p, '3001'), 'address': addr})
            elif top_name.startswith('__attach_version1.0_'):
                p = f'{top_name}/'
                ap = props(p, 8)
                method = struct.unpack('<I', ap[0x3705][1][:4])[0] if 0x3705 in ap else 1
                name = stream(p, '3707') or stream(p, '3704') or stream(p, '3001') or 'attachment'
                cid = stream(p, '3712')
                if method == 5 or not ole.exists(f'{p}__substg1.0_37010102'):
                    m['attachments'].append({'name': name, 'size': None, 'mime': stream(p, '370E'), 'content_id': cid, 'inline': False,
                                             'stored': False, 'note': 'embedded Outlook item: not extracted'})
                    continue
                data = ole.openstream(f'{p}__substg1.0_37010102').read()
                m['attachments'].append(_attachment(store, data, name, stream(p, '370E'), cid, bool(cid)))
        if not (m['to'] or m['cc'] or m['bcc']) and hmsg:  # no recipient records: the transport headers name them
            m['to'], m['cc'] = _addresses(hmsg.get('To')), _addresses(hmsg.get('Cc'))
        return _finish(m)
    finally:
        ole.close()


# -- Outlook PST / OST (libpff) -----------------------------------------------------------------------------------
_PFF_WANTED = (0x0C1F, 0x5D01, 0x0065, 0x1035, 0x0E07, 0x1042)
_PFF_RECIPIENT = (0x3001, 0x3003, 0x39FE, 0x0C15)


def _pff_entries(item, wanted) -> list[dict]:
    """The record sets of a libpff item as {entry type: value}, one dictionary per record set."""
    out = []
    for rs in range(item.number_of_record_sets):
        r, vals = item.get_record_set(rs), {}
        for e in range(r.number_of_entries):
            en = r.get_entry(e)
            if en.entry_type in wanted and en.entry_type not in vals:
                try:
                    if en.value_type in (0x1E, 0x1F):
                        vals[en.entry_type] = en.data_as_string
                    elif en.value_type in (0x02, 0x03):
                        vals[en.entry_type] = en.data_as_integer
                    else:
                        vals[en.entry_type] = en.data
                except (IOError, OSError, ValueError):
                    pass
        out.append(vals)
    return out


def _decode(body) -> str | None:
    if body is None:
        return None
    if isinstance(body, str):
        return body
    for enc in ('utf-8', 'cp1252'):
        try:
            return body.decode(enc).rstrip('\x00')
        except UnicodeDecodeError:
            continue
    return body.decode('utf-8', 'replace')


def parse_pst(path: Path, store: Store, limit: int = MAX_MESSAGES, warn=lambda m: None) -> Iterator[dict]:
    import pypff
    f = pypff.file()
    f.open(str(path))
    count = [0]
    try:
        def walk(folder, name, depth):
            if depth > 64:
                return
            for i in range(folder.number_of_sub_messages):
                if count[0] >= limit:
                    return
                try:
                    m = folder.get_sub_message(i)
                    if not hasattr(m, 'number_of_attachments'):  # a contact, appointment or other non-mail item
                        continue
                    count[0] += 1
                    yield _pff_message(m, name, i, store)
                except (IOError, OSError) as exc:
                    warn(f'{name or "/"} item {i}: {exc}')
            for i in range(folder.number_of_sub_folders):
                sub = folder.get_sub_folder(i)
                sub_name = sub.name or f'folder {i}'
                if depth == 0 and sub_name.lower().startswith('top of '):  # "Top of Outlook data file" / "Top of Personal Folders"
                    yield from walk(sub, '', depth + 1)
                else:
                    yield from walk(sub, f'{name}/{sub_name}' if name else sub_name, depth + 1)
        yield from walk(f.get_root_folder(), '', 0)
        for i in range(f.number_of_orphan_items):
            if count[0] >= limit:
                break
            try:
                m = f.get_orphan_item(i)
                if hasattr(m, 'number_of_attachments'):
                    count[0] += 1
                    msg = _pff_message(m, '(orphan items)', i, store)
                    msg['deleted'] = True
                    msg['flags'] = msg['flags'] + ['orphan']
                    yield msg
            except (IOError, OSError) as exc:
                warn(f'orphan item {i}: {exc}')
    finally:
        f.close()


def _pff_message(m, folder: str, index: int, store: Store) -> dict:
    headers = _decode(m.transport_headers)
    hmsg = email.message_from_string(headers, policy=email.policy.default) if headers else None
    props = {}
    for vals in _pff_entries(m, _PFF_WANTED):
        for k, v in vals.items():
            props.setdefault(k, v)
    sender = _addresses(_safe_header(hmsg, 'From')) if hmsg else []
    addr = next((props[k] for k in (0x5D01, 0x0C1F, 0x0065) if isinstance(props.get(k), str) and '@' in props[k]), None)
    msg = {'folder': folder, 'index': index, 'message_id': props.get(0x1035) or (_safe_header(hmsg, 'Message-ID') if hmsg else None),
           'subject': m.subject, 'from_name': m.sender_name or (sender[0]['name'] if sender else None),
           'from_address': addr or (sender[0]['address'] if sender else None), 'to': [], 'cc': [], 'bcc': [], 'reply_to': [],
           'sent': _utc(m.client_submit_time), 'received': _utc(m.delivery_time), 'in_reply_to': props.get(0x1042),
           'headers': headers, 'body_text': _decode(m.plain_text_body), 'body_html': _decode(m.html_body),
           'attachments': [], 'flags': [], 'deleted': False,
           'originating_ip': _safe_header(hmsg, 'X-Originating-IP') if hmsg else None, 'user_agent': None}
    flags = props.get(0x0E07)
    if isinstance(flags, int):
        msg['flags'] = [n for b, n in ((0x01, 'read'), (0x08, 'draft')) if flags & b]
    if m.recipients is not None:
        kinds = {1: 'to', 2: 'cc', 3: 'bcc'}
        for vals in _pff_entries(m.recipients, _PFF_RECIPIENT):
            if vals.get(0x3001) or vals.get(0x3003):
                addr = vals.get(0x39FE) or vals.get(0x3003)
                msg[kinds.get(vals.get(0x0C15), 'to')].append({'name': vals.get(0x3001), 'address': addr})
    elif hmsg:
        msg['to'], msg['cc'] = _addresses(_safe_header(hmsg, 'To')), _addresses(_safe_header(hmsg, 'Cc'))
    if msg['body_text'] is None and msg['body_html'] is None and m.rtf_body:
        msg['body_text'] = _rtf_text(_decode(m.rtf_body))
    for a in range(m.number_of_attachments):
        att = m.get_attachment(a)
        info = {}
        for vals in _pff_entries(att, (0x3704, 0x3707, 0x370E, 0x3712, 0x3705)):
            info.update({k: v for k, v in vals.items() if k not in info})
        name = getattr(att, 'long_filename', None) or info.get(0x3707) or info.get(0x3704) or f'attachment-{a + 1}'
        cid = info.get(0x3712) if isinstance(info.get(0x3712), str) else None
        try:
            size = att.size
            if size > MAX_ATTACHMENT:
                msg['attachments'].append({'name': name, 'size': size, 'mime': info.get(0x370E), 'content_id': cid, 'inline': bool(cid),
                                           'stored': False, 'note': f'over {MAX_ATTACHMENT >> 20} MiB: not extracted'})
                continue
            data = att.read_buffer(size) if size else b''
        except (IOError, OSError, ValueError):
            msg['attachments'].append({'name': name, 'size': None, 'mime': info.get(0x370E), 'content_id': cid, 'inline': False,
                                       'stored': False, 'note': 'embedded Outlook item or unreadable: not extracted'})
            continue
        msg['attachments'].append(_attachment(store, data, name, info.get(0x370E), cid, bool(cid)))
    return _finish(msg)


def _rtf_text(rtf: str | None) -> str | None:
    """Rough text of an RTF body (control words and groups removed)."""
    if not rtf:
        return None
    s = re.sub(r'\\par[d]?\b', '\n', rtf)
    s = re.sub(r"\\'([0-9a-fA-F]{2})", lambda x: bytes([int(x.group(1), 16)]).decode('cp1252', 'replace'), s)
    s = re.sub(r'\\[a-zA-Z]+-?\d* ?|[{}]', '', s)
    return s.strip()
