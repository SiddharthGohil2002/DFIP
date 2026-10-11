"""A minimal writer for Windows XML Event Log (EVTX) files, for DFIP's test data.

Layout (libevtx "Windows XML Event Log (EVTX) format", python-evtx):
  file header (4096 bytes, "ElfFile"), then 64 KiB chunks ("ElfChnk": a 512-byte header with CRC32 checksums of
  the header and of the event records), each holding event records ("**\\0\\0", size, record id, written time,
  binary XML, size copy).

Each record's binary XML is what Windows writes: a template instance whose template definition (the event's XML
shape, with substitution tokens where values go) is resident in the record, followed by the substitution values
with their types (UInt16 event ID, FILETIME time, SID, strings...). Templates are not shared between records,
which keeps the writer simple and is still a valid file. Element and attribute names are stored inline.
"""
from __future__ import annotations
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'
NULL, STRING, UINT8, UINT16, UINT32, UINT64, FILETIME, SID, HEX64 = 0x00, 0x01, 0x04, 0x06, 0x08, 0x0A, 0x11, 0x13, 0x15
CHUNK = 65536
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(dt: datetime) -> int:
    d = dt - EPOCH_1601
    return (d.days * 86_400 + d.seconds) * 10_000_000 + d.microseconds * 10


def name_hash(name: str) -> int:
    h = 0
    for c in name.encode('utf-16-le')[::2]:
        h = (h * 65599 + c) & 0xFFFFFFFF
    return h & 0xFFFF


def binary_sid(sid: str) -> bytes:
    parts = sid.split('-')
    rev, auth, subs = int(parts[1]), int(parts[2]), [int(x) for x in parts[3:]]
    return struct.pack('<BB', rev, len(subs)) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


@dataclass
class Event:
    channel: str
    provider: str
    provider_guid: str
    event_id: int
    time: datetime
    data: dict | list = field(default_factory=dict)  # EventData: Name -> value, or a list of unnamed values (classic logs)
    level: int = 4                            # 0 LogAlways, 1 Critical, 2 Error, 3 Warning, 4 Information
    task: int = 0
    opcode: int = 0
    keywords: int = 0x8000000000000000
    version: int = 0
    computer: str = 'LAPTOP-07'
    user_sid: str | None = None
    process_id: int = 4
    thread_id: int = 8
    # UserData instead of EventData: (element name, its xmlns, {child: value}), as event 1102 (log cleared) has.
    user_data: tuple[str, str, dict] | None = None


class _Body:
    """Builds binary XML at a known chunk offset (inline names are referenced by their chunk offset)."""

    def __init__(self, base: int):
        self.base, self.buf = base, bytearray()

    def pos(self) -> int:
        return self.base + len(self.buf)

    def _name(self, name: str):
        self.buf += struct.pack('<IHH', 0, name_hash(name), len(name)) + name.encode('utf-16-le') + b'\0\0'

    def _value(self, v):
        kind = v[0]
        if kind == 'text':
            s = v[1]
            self.buf += bytes([0x05, STRING]) + struct.pack('<H', len(s)) + s.encode('utf-16-le')
        else:  # ('sub', index, type)
            self.buf += bytes([0x0D]) + struct.pack('<HB', v[1], v[2])

    def element(self, name: str, attrs=(), content=()):
        """attrs: [(name, value)]; content: [value | ('el', name, attrs, content)]; value: ('text', s) | ('sub', i, type)."""
        self.buf += bytes([0x41 if attrs else 0x01]) + struct.pack('<H', 0xFFFF)
        size_at = len(self.buf)
        self.buf += b'\0' * 8
        # An inline name follows its offset field directly; the attribute list size comes after the name.
        struct.pack_into('<I', self.buf, size_at + 4, self.pos())
        self._name(name)
        if attrs:
            attr_size_at = len(self.buf)
            self.buf += b'\0' * 4
            start = len(self.buf)
            for i, (an, av) in enumerate(attrs):
                self.buf += bytes([0x46 if i < len(attrs) - 1 else 0x06])
                at = len(self.buf)
                self.buf += b'\0' * 4
                struct.pack_into('<I', self.buf, at, self.pos())
                self._name(an)
                self._value(av)
            struct.pack_into('<I', self.buf, attr_size_at, len(self.buf) - start)
        if not content:
            self.buf += b'\x03'
        else:
            self.buf += b'\x02'
            for c in content:
                if c[0] == 'el':
                    self.element(c[1], c[2], c[3])
                else:
                    self._value(c)
            self.buf += b'\x04'
        struct.pack_into('<I', self.buf, size_at, len(self.buf) - (size_at + 4))


def _event_xml(base: int, e: Event, record_id: int) -> tuple[bytes, list[tuple[int, bytes]]]:
    """The template body (binary XML at chunk offset `base`) and the substitution values for one event."""
    values = [(UINT16, struct.pack('<H', e.event_id)), (UINT8, bytes([e.version])), (UINT8, bytes([e.level])),
              (UINT16, struct.pack('<H', e.task)), (UINT8, bytes([e.opcode])), (HEX64, struct.pack('<Q', e.keywords)),
              (FILETIME, struct.pack('<Q', filetime(e.time))), (UINT64, struct.pack('<Q', record_id)),
              (UINT32, struct.pack('<I', e.process_id)), (UINT32, struct.pack('<I', e.thread_id)),
              (STRING, e.channel.encode('utf-16-le')), (STRING, e.computer.encode('utf-16-le'))]
    security = ('el', 'Security', [('UserID', ('sub', 12, SID))], []) if e.user_sid else ('el', 'Security', [], [])
    if e.user_sid:
        values.append((SID, binary_sid(e.user_sid)))
    system = [
        # Classic (non-manifest) providers such as "EventLog" have no Guid attribute.
        ('el', 'Provider', [('Name', ('text', e.provider))] + ([('Guid', ('text', e.provider_guid))] if e.provider_guid else []), []),
        ('el', 'EventID', [], [('sub', 0, UINT16)]), ('el', 'Version', [], [('sub', 1, UINT8)]),
        ('el', 'Level', [], [('sub', 2, UINT8)]), ('el', 'Task', [], [('sub', 3, UINT16)]),
        ('el', 'Opcode', [], [('sub', 4, UINT8)]), ('el', 'Keywords', [], [('sub', 5, HEX64)]),
        ('el', 'TimeCreated', [('SystemTime', ('sub', 6, FILETIME))], []),
        ('el', 'EventRecordID', [], [('sub', 7, UINT64)]), ('el', 'Correlation', [], []),
        ('el', 'Execution', [('ProcessID', ('sub', 8, UINT32)), ('ThreadID', ('sub', 9, UINT32))], []),
        ('el', 'Channel', [], [('sub', 10, STRING)]), ('el', 'Computer', [], [('sub', 11, STRING)]), security,
    ]
    def sub(value):
        values.append((STRING, str(value).encode('utf-16-le')))
        return [('sub', len(values) - 1, STRING)]

    if e.user_data:
        name, ns, fields = e.user_data
        inner = [('el', k, [], sub(v)) for k, v in fields.items()]
        payload = ('el', 'UserData', [], [('el', name, [('xmlns', ('text', ns))] if ns else [], inner)])
    else:
        items = e.data.items() if isinstance(e.data, dict) else ((None, v) for v in e.data)
        payload = ('el', 'EventData', [], [('el', 'Data', [('Name', ('text', k))] if k is not None else [], sub(v)) for k, v in items])
    body = _Body(base)
    body.buf += b'\x0f\x01\x01\x00'
    body.element('Event', [('xmlns', ('text', NS))], [('el', 'System', [], system), payload])
    body.buf += b'\x00'
    return bytes(body.buf), values


def _record(offset_in_chunk: int, e: Event, record_id: int) -> bytes:
    template_at = offset_in_chunk + 24 + 4 + 10
    guid = uuid.uuid4().bytes_le
    template_id = struct.unpack_from('<I', guid, 0)[0]
    body, values = _event_xml(template_at + 24, e, record_id)
    xml = b'\x0f\x01\x01\x00' + struct.pack('<BBII', 0x0C, 0x01, template_id, template_at)
    xml += struct.pack('<I', 0) + guid + struct.pack('<I', len(body)) + body
    xml += struct.pack('<I', len(values)) + b''.join(struct.pack('<HBB', len(v), t, 0) for t, v in values) + b''.join(v for _, v in values)
    xml += b'\x00'  # end of the record's binary XML stream
    size = 24 + len(xml) + 4
    return b'**\0\0' + struct.pack('<IQQ', size, record_id, filetime(e.time)) + xml + struct.pack('<I', size)


def _chunk(records: list[bytes], first_id: int, last_offset: int) -> bytes:
    data = b''.join(records)
    head = bytearray(512)
    last_id = first_id + len(records) - 1
    struct.pack_into('<8sQQQQIIII', head, 0, b'ElfChnk\0', first_id, last_id, first_id, last_id, 128, last_offset,
                     512 + len(data), zlib.crc32(data) & 0xFFFFFFFF)
    struct.pack_into('<I', head, 124, zlib.crc32(bytes(head[:120]) + bytes(head[128:512])) & 0xFFFFFFFF)
    return bytes(head) + data + b'\0' * (CHUNK - 512 - len(data))


def write_evtx(events: list[Event], first_record_id: int = 1) -> bytes:
    """An EVTX file holding `events` in order, record numbers starting at first_record_id."""
    chunks, records, offset, last_offset = [], [], 512, 512
    first = rid = first_record_id
    for e in events:
        rec = _record(offset, e, rid)
        if offset + len(rec) > CHUNK:
            chunks.append(_chunk(records, first, last_offset))
            records, offset, first = [], 512, rid
            rec = _record(offset, e, rid)
        records.append(rec)
        last_offset = offset
        offset += len(rec)
        rid += 1
    if records or not chunks:
        chunks.append(_chunk(records, first, last_offset))
    head = bytearray(4096)
    struct.pack_into('<8sQQQIHHHH', head, 0, b'ElfFile\0', 0, len(chunks) - 1, rid, 128, 1, 3, 4096, len(chunks))
    struct.pack_into('<I', head, 124, zlib.crc32(bytes(head[:120])) & 0xFFFFFFFF)
    return bytes(head) + b''.join(chunks)
