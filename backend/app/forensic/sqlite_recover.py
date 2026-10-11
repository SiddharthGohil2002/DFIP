"""Deleted rows still present in a SQLite database file and its write-ahead log.

SQLite does not wipe a deleted row (unless secure_delete is on). Its bytes stay in one of three places:
  - a page on the freelist (every row of a table page that became empty): the page keeps its cell pointers, so its
    rows are read whole, row ID included;
  - free space inside a page still in use: a deleted row becomes a "freeblock" whose first 4 bytes are overwritten
    with the freeblock's own next/size fields (which loses the row's length and usually its row ID), or it is left
    whole in the unallocated gap when it was the last row written;
  - an older copy of a page in the -wal file, written before the row was deleted and not yet checkpointed.

Rows are matched against a table's columns (how many there are, which is the INTEGER PRIMARY KEY alias stored as
NULL, which hold text or numbers), so a carved record is attributed to a table only when every column fits. A row
whose row ID and values are still in the live table is not "recovered"; one whose row ID is live with other
values is an older version. Text must decode cleanly, and callers check what the values mean (a URL, a time).

Limits: only tables with a text column are searched (rows of numbers alone match random bytes too easily);
overflow chains are followed only for rows read through a cell pointer; rows of WITHOUT ROWID tables and indexes are
not read.
"""
from __future__ import annotations
import sqlite3
import struct
from dataclasses import dataclass, field
from pathlib import Path

LEAF_TABLE, INTERIOR_TABLE = 0x0D, 0x05
WAL_MAGIC = (0x377F0682, 0x377F0683)
MAX_PAGES = 262_144
MAX_RECORDS = 50_000
MAX_SCAN_OFFSETS = 20_000_000   # offsets tried in free space per database (about a minute of work)
MAX_BYTES = 512 << 20
TEXT_TYPES = ('CHAR', 'CLOB', 'TEXT')


@dataclass
class Table:
    name: str
    columns: list[str]
    affinity: list[str]           # 'INTEGER', 'TEXT', 'BLOB', 'REAL', 'NUMERIC'
    ipk: int | None               # index of the INTEGER PRIMARY KEY column (stored as NULL, the row ID holds it)
    root: int
    live: dict = field(default_factory=dict)   # rowid -> tuple of values


@dataclass
class Recovered:
    table: str
    rowid: int | None
    values: dict
    source: str                   # 'freelist page', 'free space', 'WAL frame'
    page: int
    offset: int                   # of the record in the file it was read from (the database or the -wal)
    file: str                     # 'database' or 'wal'
    frame: int | None = None
    previous_version: bool = False


def _affinity(decl: str) -> str:
    d = (decl or '').upper()
    if 'INT' in d:
        return 'INTEGER'
    if any(t in d for t in TEXT_TYPES):
        return 'TEXT'
    if 'BLOB' in d or not d:
        return 'BLOB'
    if any(t in d for t in ('REAL', 'FLOA', 'DOUB')):
        return 'REAL'
    return 'NUMERIC'


def varint(buf: bytes, pos: int, end: int | None = None) -> tuple[int, int]:
    """(value, length) of the SQLite varint at pos; (-1, 0) if it runs past end."""
    end = len(buf) if end is None else min(end, len(buf))
    v = 0
    for i in range(9):
        if pos + i >= end:
            return -1, 0
        b = buf[pos + i]
        if i == 8:
            return (v << 8) | b, 9
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, i + 1
    return -1, 0


def _size(serial: int) -> int:
    if serial < 12:
        return (0, 1, 2, 3, 4, 6, 8, 8, 0, 0, -1, -1)[serial]
    return (serial - 12) // 2 if serial % 2 == 0 else (serial - 13) // 2


def _value(serial: int, raw: bytes, encoding: str):
    if serial == 0:
        return None
    if 1 <= serial <= 6:
        return int.from_bytes(raw, 'big', signed=True)
    if serial == 7:
        return struct.unpack('>d', raw)[0]
    if serial in (8, 9):
        return serial - 8
    if serial % 2 == 0:
        return bytes(raw)
    return raw.decode(encoding)  # raises on bytes that are not text


def _fits(serial: int, affinity: str, is_ipk: bool) -> bool:
    if serial in (10, 11):
        return False
    if is_ipk:
        return serial == 0
    if affinity == 'INTEGER':
        return serial in (0, 1, 2, 3, 4, 5, 6, 8, 9)
    if affinity == 'TEXT':
        return serial == 0 or (serial >= 13 and serial % 2 == 1)
    if affinity == 'REAL':
        return serial in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    return True


class Database:
    """A SQLite file (and its -wal) read as bytes, with the tables of interest and their live rows."""

    def __init__(self, path: Path, tables: list[str] | None = None):
        self.path = Path(path)
        with self.path.open('rb') as f:
            self.data = f.read(MAX_BYTES)
        if self.data[:16] != b'SQLite format 3\x00':
            raise ValueError('Not a SQLite 3 database')
        ps = struct.unpack('>H', self.data[16:18])[0]
        self.page_size = 65536 if ps == 1 else ps
        self.usable = self.page_size - self.data[20]
        self.encoding = {1: 'utf-8', 2: 'utf-16-le', 3: 'utf-16-be'}.get(struct.unpack('>I', self.data[56:60])[0], 'utf-8')
        wal = self.path.with_name(self.path.name + '-wal')
        self.wal = wal.read_bytes() if wal.is_file() else b''
        self.tables = self._tables(tables)

    # -- schema and live rows, through SQLite itself (on a copy the caller made) ---------------------------
    def _tables(self, wanted):
        out = {}
        con = sqlite3.connect(f'file:{self.path}?mode=ro', uri=True)
        try:
            for name, root, sql in con.execute("SELECT name, rootpage, sql FROM sqlite_master WHERE type='table'"):
                if (wanted and name not in wanted) or not root or 'WITHOUT ROWID' in (sql or '').upper():
                    continue
                info = con.execute(f'PRAGMA table_info("{name}")').fetchall()
                cols = [c[1] for c in info]
                aff = [_affinity(c[2]) for c in info]
                pk = [c for c in info if c[5]]
                ipk = cols.index(pk[0][1]) if len(pk) == 1 and (pk[0][2] or '').upper() == 'INTEGER' else None
                if 'TEXT' not in aff:
                    continue
                t = Table(name, cols, aff, ipk, root)
                for row in con.execute(f'SELECT rowid, * FROM "{name}"'):
                    t.live[row[0]] = tuple(row[1:])
                out[name] = t
        finally:
            con.close()
        return out

    # -- pages -----------------------------------------------------------------------------------------------
    def page(self, n: int) -> bytes:
        return self.data[(n - 1) * self.page_size:n * self.page_size]

    def page_count(self) -> int:
        return len(self.data) // self.page_size

    def freelist(self) -> tuple[set[int], set[int]]:
        """(trunk pages, leaf pages) on the freelist."""
        trunks, leaves = set(), set()
        n = struct.unpack('>I', self.data[32:36])[0]
        while n and n not in trunks and n <= self.page_count():
            trunks.add(n)
            p = self.page(n)
            nxt, count = struct.unpack('>II', p[:8])
            count = min(count, (self.usable - 8) // 4)
            leaves.update(struct.unpack(f'>{count}I', p[8:8 + 4 * count]))
            n = nxt
        return trunks, leaves

    def owners(self) -> dict[int, str]:
        """Live table pages (leaf and interior) and the table that owns each."""
        owner = {}
        for t in self.tables.values():
            stack = [t.root]
            while stack and len(owner) < MAX_PAGES:
                n = stack.pop()
                if n in owner or not 0 < n <= self.page_count():
                    continue
                p, h = self.page(n), 100 if n == 1 else 0
                owner[n] = t.name
                if p[h] == INTERIOR_TABLE:
                    ncells = struct.unpack('>H', p[h + 3:h + 5])[0]
                    stack.append(struct.unpack('>I', p[h + 8:h + 12])[0])
                    for i in range(ncells):
                        off = struct.unpack('>H', p[h + 12 + 2 * i:h + 14 + 2 * i])[0]
                        if off + 4 <= len(p):
                            stack.append(struct.unpack('>I', p[off:off + 4])[0])
        return owner


class _Carver:
    def __init__(self, db: Database):
        self.db = db
        self.found: list[Recovered] = []
        self.seen: set = set()
        self.budget = MAX_SCAN_OFFSETS
        self.capped = False

    # -- record decoding -------------------------------------------------------------------------------------
    def record(self, buf: bytes, pos: int, end: int, table: Table, lost: int = 0):
        """Decodes a record header at pos for `table`. lost=1: the header-length byte was overwritten (the serial
        types start at pos); lost=2: it and the first serial type (the INTEGER PRIMARY KEY, always NULL) were.
        Returns (values, end of record) or None."""
        n = len(table.columns)
        serials, p = [], pos
        if lost == 0:
            hlen, ln = varint(buf, pos, end)
            if ln == 0 or hlen < 2 or hlen > 2 + 9 * n:
                return None
            hend = pos + hlen
            p = pos + ln
        else:
            if lost == 2:
                if table.ipk != 0:
                    return None
                serials.append(0)
            hend = None
        while len(serials) < n:
            if hend is not None and p >= hend:
                break
            s, ln = varint(buf, p, end)
            if ln == 0:
                return None
            serials.append(s)
            p += ln
        if len(serials) != n or (hend is not None and p != hend):
            return None
        for i, s in enumerate(serials):
            if not _fits(s, table.affinity[i], i == table.ipk):
                return None
        body = sum(_size(s) for s in serials)
        if p + body > end:
            return None
        values, q = [], p
        try:
            for s in serials:
                size = _size(s)
                values.append(_value(s, buf[q:q + size], self.db.encoding))
                q += size
        except (UnicodeDecodeError, struct.error):
            return None
        if all(v is None or v == '' for i, v in enumerate(values) if i != table.ipk):
            return None
        for v in values:  # carved text is real text: no control characters other than whitespace
            if isinstance(v, str) and any(ord(c) < 32 and c not in '\t\r\n' for c in v):
                return None
        return values, q

    def _payload(self, buf, pos, payload_len, local, page_end):
        """A cell's payload, following its overflow chain when it spills (only for cells read through a pointer)."""
        if payload_len <= local:
            return buf[pos:pos + payload_len]
        db, usable = self.db, self.db.usable
        m = ((usable - 12) * 32 // 255) - 23
        k = m + (payload_len - m) % (usable - 4)
        here = k if k <= local else m
        data = bytearray(buf[pos:pos + here])
        nxt = struct.unpack('>I', buf[pos + here:pos + here + 4])[0] if pos + here + 4 <= page_end else 0
        seen = set()
        while nxt and len(data) < payload_len and nxt not in seen and nxt <= db.page_count():
            seen.add(nxt)
            p = db.page(nxt)
            nxt = struct.unpack('>I', p[:4])[0]
            data += p[4:usable][:payload_len - len(data)]
        return bytes(data)

    # -- one page ----------------------------------------------------------------------------------------------
    def page(self, buf: bytes, base: int, number: int, tables: list[Table], source: str, file: str, frame=None,
             use_cells: bool = False):
        """Rows in one page image: through its cell pointers (use_cells, for pages no longer in use), then in its
        freeblocks and unallocated gap. `base` is the page's offset in the file it was read from."""
        h = 100 if number == 1 else 0
        ptype = buf[h] if len(buf) > h else 0
        usable = self.db.usable
        if ptype == LEAF_TABLE and len(buf) >= h + 8:
            ncells, content = struct.unpack('>HH', buf[h + 3:h + 7])
            content = content or 65536
            parray_end = h + 8 + 2 * ncells
            if parray_end <= usable:
                if use_cells:
                    for i in range(ncells):
                        off = struct.unpack('>H', buf[h + 8 + 2 * i:h + 10 + 2 * i])[0]
                        if parray_end <= off < usable:
                            self._cell(buf, off, usable, tables, base, number, source, file, frame)
                label = 'free space' if source == 'page' else source
                fb, hops = struct.unpack('>H', buf[h + 1:h + 3])[0], 0
                while fb and fb + 4 <= usable and hops < 1000:
                    nxt, size = struct.unpack('>HH', buf[fb:fb + 4])
                    self._scan(buf, fb, min(fb + size, usable), tables, base, number, label, file, frame)
                    fb = nxt if nxt > fb else 0
                    hops += 1
                # The gap between the cell pointers and the cell content. When a page's last row is deleted SQLite
                # resets its header, so the whole page becomes this gap, old freeblock headers and all.
                if parray_end < min(content, usable):
                    self._scan(buf, parray_end, min(content, usable), tables, base, number, label, file, frame)
                return
        if ptype != INTERIOR_TABLE:  # not a table page any more (a freelist trunk, or reused): scan it whole
            self._scan(buf, 8 if source == 'freelist page' else 0, usable, tables, base, number, source, file, frame)

    def _cell(self, buf, off, usable, tables, base, number, source, file, frame):
        payload_len, a = varint(buf, off, usable)
        rowid, b = varint(buf, off + a, usable) if a else (-1, 0)
        if not b or payload_len <= 0:
            return None
        start = off + a + b
        local_max = usable - 35
        payload = self._payload(buf, start, payload_len, local_max, usable)
        for t in tables:
            got = self.record(payload, 0, len(payload), t)
            if got:
                self._add(t, rowid, got[0], source, number, base + off, file, frame)
                return t
        return None

    def _scan(self, buf, start, end, tables, base, number, source, file, frame):
        """Rows in [start, end), in two passes. First whole cells (length, row ID, record) at every offset; then, outside
        them, records after something that looks like a freeblock header (current or stale) whose first bytes that header
        overwrote. A partial match inside or across a whole cell is a misreading of that cell's bytes, never a row."""
        covered = []

        def inside(pos):
            return next((e for s, e in covered if s <= pos < e), None)

        for partial in (False, True):
            pos = start + 4 if partial else start
            while pos < end - 2:
                skip = inside(pos) if partial else None
                if skip:
                    pos = skip
                    continue
                if not buf[pos] and not buf[pos + 1] and not buf[pos + 2]:  # zeroed space: jump to the next byte in use
                    nz = next((i for i in range(pos + 3, end) if buf[i]), end)
                    pos = max(pos + 1, nz - 4)
                    continue
                self.budget -= 1
                if self.budget <= 0:
                    self.capped = True
                    return
                hit = None
                for t in tables:
                    if not partial:
                        hit = self._whole_cell(buf, pos, end, t)
                        if hit:
                            self._add(t, hit[0], hit[1], source, number, base + pos, file, frame)
                            covered.append((pos, hit[2]))
                            break
                    elif self._freeblock_header(buf, pos - 4, end):
                        for lost in (0, 1, 2):
                            got = self.record(buf, pos, end, t, lost)
                            if got and not any(s < got[1] and pos < e for s, e in covered):
                                hit = (None, got[0], got[1])
                                self._add(t, None, got[0], source, number, base + pos, file, frame)
                                covered.append((pos, got[1]))
                                break
                        if hit:
                            break
                pos = hit[2] if hit else pos + 1

    def _freeblock_header(self, buf, at, end) -> bool:
        if at < 0:
            return False
        nxt, size = struct.unpack('>HH', buf[at:at + 4])
        return (nxt == 0 or at < nxt < self.db.usable) and 4 <= size <= self.db.usable - at

    def _whole_cell(self, buf, pos, end, t):
        payload_len, a = varint(buf, pos, end)
        if not a or payload_len < 3 or payload_len > end - pos:
            return None
        rowid, b = varint(buf, pos + a, end)
        if not b or rowid <= 0:
            return None
        got = self.record(buf, pos + a + b, end, t)
        if not got or got[1] - (pos + a + b) != payload_len:
            return None
        return rowid, got[0], got[1]

    def _add(self, t: Table, rowid, values, source, page, offset, file, frame):
        if len(self.found) >= MAX_RECORDS:
            return
        vals = list(values)
        if t.ipk is not None and rowid is not None:
            vals[t.ipk] = rowid
        tup = tuple(vals)
        live = t.live.get(rowid) if rowid is not None else None
        if live is not None and _same(live, tup, t.ipk):
            return
        if rowid is None and any(_same(v, tup, t.ipk) for v in t.live.values()):
            return
        key = (t.name, rowid, tuple(v for i, v in enumerate(tup) if i != t.ipk))
        if key in self.seen:
            return
        self.seen.add(key)
        self.found.append(Recovered(t.name, rowid, dict(zip(t.columns, vals)), source, page, offset, file, frame,
                                    previous_version=live is not None))


def _same(a: tuple, b: tuple, ipk) -> bool:
    return all(x == y for i, (x, y) in enumerate(zip(a, b)) if i != ipk)


def _values(payload: bytes):
    """The values of one record, without knowing its table (for text extraction)."""
    hlen, ln = varint(payload, 0)
    if ln == 0 or hlen < 2 or hlen > len(payload):
        return
    p, q = ln, hlen
    while p < hlen:
        s, n = varint(payload, p, hlen)
        if n == 0 or s in (10, 11):
            return
        p += n
        size = _size(s)
        if q + size > len(payload):
            return
        if s >= 13 and s % 2:
            yield payload[q:q + size]
        q += size


def wal_text(data: bytes, max_chars: int = 8_000_000) -> str | None:
    """The text values of the table rows in a -wal file's frames, one per line, each value once; None when the data is
    not a write-ahead log. (A -wal holds whole database pages: raw strings would run a row's fields into each other.)"""
    if len(data) < 32 or struct.unpack('>I', data[:4])[0] not in WAL_MAGIC:
        return None
    ps = struct.unpack('>I', data[8:12])[0]
    if not 512 <= ps <= 65536 or ps & (ps - 1):
        return None
    out, seen, size = [], set(), 0
    off = 32
    while off + 24 + ps <= len(data) and size < max_chars:
        page = data[off + 24:off + 24 + ps]
        h = 100 if struct.unpack('>I', data[off:off + 4])[0] == 1 else 0
        if page[h] == LEAF_TABLE:
            ncells = struct.unpack('>H', page[h + 3:h + 5])[0]
            for i in range(min(ncells, (ps - h - 8) // 2)):
                c = struct.unpack('>H', page[h + 8 + 2 * i:h + 10 + 2 * i])[0]
                payload_len, a = varint(page, c)
                _, b = varint(page, c + a) if a else (0, 0)
                if not b or payload_len <= 0:
                    continue
                start = c + a + b
                for raw in _values(page[start:start + min(payload_len, ps - 35)]):
                    try:
                        text = raw.decode('utf-8').replace('\x00', ' ').replace('\r', ' ').replace('\n', ' ')
                    except UnicodeDecodeError:
                        continue
                    if text.strip() and text not in seen:
                        seen.add(text)
                        out.append(text)
                        size += len(text) + 1
        off += 24 + ps
    return '\n'.join(out)


def recover(path: Path, tables: list[str] | None = None) -> dict:
    """Deleted rows of `tables` (all tables with a text column when None) in the database at `path` (a copy) and
    its -wal. Returns {'records': [Recovered], 'free_pages': n, 'wal_frames': n, 'errors': [...]}."""
    errors = []
    db = Database(path, tables)
    carver = _Carver(db)
    tlist = list(db.tables.values())
    if not tlist:
        return {'records': [], 'free_pages': 0, 'wal_frames': 0, 'errors': errors}
    trunks, leaves = db.freelist()
    owners = db.owners()
    for n in sorted(trunks | leaves):
        if n <= db.page_count():
            carver.page(db.page(n), (n - 1) * db.page_size, n, tlist, 'freelist page', 'database', use_cells=True)
    for n, name in sorted(owners.items()):
        carver.page(db.page(n), (n - 1) * db.page_size, n, [db.tables[name]], 'page', 'database')
    frames = 0
    if len(db.wal) >= 32 and struct.unpack('>I', db.wal[:4])[0] in WAL_MAGIC:
        wps = struct.unpack('>I', db.wal[8:12])[0]
        salt = db.wal[16:24]
        if wps != db.page_size:
            errors.append(f'WAL page size {wps} differs from the database page size {db.page_size}')
        else:
            off = 32
            while off + 24 + wps <= len(db.wal):
                pno = struct.unpack('>I', db.wal[off:off + 4])[0]
                frames += 1
                if db.wal[off + 8:off + 16] == salt:  # frames of the current WAL generation (older ones are reused)
                    owner = owners.get(pno)
                    cands = [db.tables[owner]] if owner else tlist
                    carver.page(db.wal[off + 24:off + 24 + wps], off + 24, pno, cands, 'WAL frame', 'wal', frame=frames,
                                use_cells=True)
                off += 24 + wps
    if carver.capped:
        errors.append(f'Free space was searched only up to {MAX_SCAN_OFFSETS:,} offsets')
    if len(db.data) == MAX_BYTES:
        errors.append(f'Only the first {MAX_BYTES >> 20} MiB of the database were searched')
    return {'records': carver.found, 'free_pages': len(trunks | leaves), 'wal_frames': frames, 'errors': errors}
