"""Windows XML event logs (.evtx), read with libevtx (pyevtx).

Each record's XML (libevtx renders the binary XML with its template) is parsed with defusedxml into the System fields
(event ID, provider, channel, time, computer, user SID, process and thread), the EventData values (named, or a list of
unnamed values in classic logs such as "Windows PowerShell") and the UserData fields (flattened: event 1102 "log cleared"
keeps its subject there). When a record's XML cannot be rendered or parsed (a damaged record, or a libevtx rendering
quirk), libevtx's own record fields are used instead and the record says so.

Records libevtx recovers from the slack of chunks (events overwritten or left behind when the log was cleared or
wrapped) are read too and flagged as recovered.
"""
from __future__ import annotations
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_XML = 32_768        # characters of a record's XML kept with it
MAX_VALUE = 16_384      # characters of one data value (a long script block is truncated, and flagged)
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
FLAG_DIRTY, FLAG_FULL = 0x1, 0x2


def filetime(n: int | None) -> datetime | None:
    if not n or n <= 0:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


_SYSTEMTIME = re.compile(r'(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?')


def systemtime(text: str | None) -> datetime | None:
    """TimeCreated/@SystemTime (libevtx writes nanoseconds: 2026-09-01T14:12:44.123456700Z) as UTC, to the microsecond."""
    m = _SYSTEMTIME.match(text or '')
    if not m:
        return None
    frac = (m.group(7) or '0')[:6].ljust(6, '0')
    try:
        return datetime(*(int(m.group(i)) for i in range(1, 7)), int(frac), tzinfo=timezone.utc)
    except ValueError:
        return None


def _tag(el) -> str:
    return el.tag.rsplit('}', 1)[-1] if isinstance(el.tag, str) else ''


def _int(text, default=None):
    try:
        return int(str(text).strip(), 0)
    except (TypeError, ValueError):
        return default


def header(path: Path) -> dict:
    """The file header: format version, chunk count and the dirty / full flags."""
    with open(path, 'rb') as f:
        h = f.read(128)
    if len(h) < 128 or h[:8] != b'ElfFile\0':
        return {'valid': False}
    minor, major, _size, chunks = struct.unpack_from('<HHHH', h, 36)
    flags = struct.unpack_from('<I', h, 120)[0]
    return {'valid': True, 'version': f'{major}.{minor}', 'chunks': chunks, 'dirty': bool(flags & FLAG_DIRTY),
            'full': bool(flags & FLAG_FULL), 'next_record_id': struct.unpack_from('<Q', h, 24)[0]}


def field_name(name: str) -> str:
    """A data field name as stored: no dots or leading $ (MongoDB field names), at most 120 characters."""
    name = (name or '').replace('.', '_')[:120]
    return '_' + name[1:] if name.startswith('$') else name


def _cap(v: str, rec: dict) -> str:
    if len(v) > MAX_VALUE:
        rec['truncated'] = True
        return v[:MAX_VALUE]
    return v


def _flatten(el, out: dict, rec: dict, prefix: str = ''):
    """UserData: every attribute and leaf element as a field. Nested elements are named by their path
    (Request/Major), attributes of an element below the top one by element/attribute; collisions get #2, #3 ..."""
    def put(name, v):
        name = field_name(name)
        key, n = name, 2
        while key in out:
            key, n = f'{name}#{n}', n + 1
        out[key] = _cap(v, rec)

    for k, v in el.attrib.items():
        if not k.startswith('{'):
            put(prefix + k, v)
    children = list(el)
    if not children:
        if el.text and el.text.strip():
            put(prefix.rstrip('/') or _tag(el), el.text.strip())
        return
    for c in children:
        name = prefix + _tag(c)
        if len(c) or c.attrib:
            _flatten(c, out, rec, name + '/')
        else:
            put(name, (c.text or '').strip())


# Control characters are not allowed in XML 1.0, but event data can hold them (libevtx writes them as they are). They are
# swapped for private-use characters while the XML is parsed and swapped back in the values, so values stay exact.
_XML_INVALID = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f]')
_PLACEHOLDER = re.compile('[-]')


def _restore(rec: dict):
    back = lambda s: _PLACEHOLDER.sub(lambda m: chr(ord(m.group()) - 0xE000), s) if isinstance(s, str) else s
    rec['data'] = {k: back(v) for k, v in rec['data'].items()}
    rec['data_values'] = [back(v) for v in rec['data_values']]
    for k in ('provider', 'channel', 'computer', 'message'):
        if k in rec:
            rec[k] = back(rec[k])


def parse_xml(xml: str) -> dict:
    """The fields of one event's XML (raises on XML that is not well formed)."""
    import defusedxml.ElementTree as ET
    protected = bool(_XML_INVALID.search(xml))
    if protected:
        xml = _XML_INVALID.sub(lambda m: chr(0xE000 + ord(m.group())), xml)
    root = ET.fromstring(xml)
    rec: dict = {'data': {}, 'data_values': []}
    for part in root:
        name = _tag(part)
        if name == 'System':
            for el in part:
                t = _tag(el)
                if t == 'Provider':
                    rec['provider'] = el.get('Name') or el.get('EventSourceName') or ''
                    rec['provider_guid'] = el.get('Guid')
                elif t == 'EventID':
                    rec['event_id'] = _int(el.text)
                    if el.get('Qualifiers'):
                        rec['qualifiers'] = _int(el.get('Qualifiers'))
                elif t in ('Version', 'Level', 'Task', 'Opcode'):
                    rec[t.lower()] = _int(el.text)
                elif t == 'Keywords':
                    rec['keywords'] = (el.text or '').strip()
                elif t == 'TimeCreated':
                    rec['time_text'] = el.get('SystemTime')
                elif t == 'EventRecordID':
                    rec['record_id'] = _int(el.text)
                elif t == 'Correlation':
                    if el.get('ActivityID'):
                        rec['activity_id'] = el.get('ActivityID')
                elif t == 'Execution':
                    rec['process_id'], rec['thread_id'] = _int(el.get('ProcessID')), _int(el.get('ThreadID'))
                elif t == 'Channel':
                    rec['channel'] = (el.text or '').strip()
                elif t == 'Computer':
                    rec['computer'] = (el.text or '').strip()
                elif t == 'Security':
                    rec['user_sid'] = el.get('UserID')
        elif name == 'EventData':
            for el in part:
                t = _tag(el)
                text = ''.join(el.itertext())
                if el.get('Name') is not None:  # <Data Name=...>, and <ComplexData Name=...> (binary, shown as hex)
                    base = field_name(el.get('Name'))
                    key, n = base, 2
                    while key in rec['data']:
                        key, n = f'{base}#{n}', n + 1
                    rec['data'][key] = _cap(text, rec)
                elif t == 'Data':
                    rec['data_values'].append(_cap(text, rec))
                elif t == 'Binary':
                    rec['data']['Binary'] = _cap(text.strip(), rec)
                else:
                    rec['data'][field_name(t)] = _cap(text.strip(), rec)
        elif name == 'UserData':
            children = list(part)
            if children:
                rec['user_data'] = _tag(children[0])
                _flatten(children[0], rec['data'], rec)
        elif name == 'RenderingInfo':  # forwarded events carry the rendered message
            msg = part.find('{*}Message')
            if msg is not None and msg.text:
                rec['message'] = _cap(msg.text.strip(), rec)
    if protected:
        _restore(rec)
    return rec


def _from_api(r, rec: dict):
    """Fields libevtx gives directly, used where the XML gave nothing."""
    def get(fn):
        try:
            return fn()
        except Exception:
            return None
    defaults = {'record_id': get(lambda: r.identifier), 'event_id': get(lambda: r.event_identifier),
                'provider': get(lambda: r.source_name), 'channel': get(lambda: r.channel_name), 'computer': get(lambda: r.computer_name),
                'user_sid': get(lambda: r.user_security_identifier), 'level': get(lambda: r.event_level)}
    for k, v in defaults.items():
        if rec.get(k) in (None, '') and v not in (None, ''):
            rec[k] = v
    if not rec.get('data') and not rec.get('data_values'):
        n = get(lambda: r.number_of_strings) or 0
        rec['data_values'] = [_cap(get(lambda i=i: r.get_string(i)) or '', rec) for i in range(n)]
    if rec.get('time') is None:
        rec['time'] = filetime(get(lambda: r.get_creation_time_as_integer())) or filetime(get(lambda: r.get_written_time_as_integer()))


def read_record(r, recovered: bool = False) -> dict:
    """One record as a dict (never raises for a damaged record: what could be read is returned, with `parse_error`)."""
    rec: dict = {'recovered': recovered, 'data': {}, 'data_values': []}
    try:
        xml = r.xml_string or ''
    except Exception as exc:
        xml, rec['parse_error'] = '', f'libevtx could not render the record: {str(exc)[:200]}'
    if xml:
        rec['xml'] = xml[:MAX_XML]
        if len(xml) > MAX_XML:
            rec['xml_truncated'] = True
        try:
            rec.update(parse_xml(xml))
            rec['time'] = systemtime(rec.pop('time_text', None))
        except Exception as exc:
            rec['parse_error'] = f'record XML is not well formed: {str(exc)[:200]}'
    _from_api(r, rec)
    try:
        rec['offset'] = r.offset
    except Exception:
        pass
    kw = rec.get('keywords')
    rec['keywords_int'] = _int(kw) if kw else None
    return rec


class EvtxLog:
    """One .evtx file: iterate `records()`; afterwards `stats` holds the counts and what went wrong."""

    def __init__(self, path: Path, max_records: int):
        self.path, self.max_records = Path(path), max_records
        self.stats = {'records': 0, 'recovered': 0, 'unreadable': 0, 'capped': False, 'errors': []}
        self.stats.update(header(self.path))

    def records(self):
        import pyevtx
        f = pyevtx.file()
        try:
            f.open(str(self.path))
        except Exception as exc:
            self.stats['errors'].append(f'libevtx could not open the log: {exc}')
            return
        try:
            try:
                self.stats['corrupted'] = bool(f.is_corrupted())
            except Exception:
                pass
            yielded = 0
            for recovered, count, get in ((False, f.number_of_records, f.get_record),
                                          (True, f.number_of_recovered_records, f.get_recovered_record)):
                for i in range(count):
                    if yielded >= self.max_records:
                        self.stats['capped'] = True
                        return
                    try:
                        r = get(i)
                    except Exception as exc:
                        self.stats['unreadable'] += 1
                        if len(self.stats['errors']) < 20:
                            self.stats['errors'].append(f'record {i}{" (recovered)" if recovered else ""}: {str(exc)[:200]}')
                        continue
                    rec = read_record(r, recovered)
                    self.stats['recovered' if recovered else 'records'] += 1
                    yielded += 1
                    yield rec
        finally:
            f.close()
