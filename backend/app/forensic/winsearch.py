"""Windows Search index: what Windows indexed about files (path, size, times, owner, kind, a summary of the text and the
thumbnail cache ID), which outlives the files themselves.

Windows 7 to 10 keep it in ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb (ESE): one row per item
in SystemIndex_0A (or SystemIndex_PropertyStore in later Windows 10 builds), one column per property, named
"System_ItemPathDisplay" or "4447-System_ItemPathDisplay". Text columns are compressed (libesedb decompresses them);
numbers and FILETIMEs in binary columns are stored big-endian; System_Search_AutoSummary is obfuscated with an XOR
mask derived from the value's size (the scheme libesedb's esedbexport documents) and starts with a flag byte (1: 8-bit
text, 0: UTF-16). Windows 11 keeps it in Windows.db (SQLite): SystemIndex_1_PropertyStore holds (WorkId, ColumnId,
Value) rows and SystemIndex_1_PropertyStore_Metadata names each column. The Windows 11 layout follows published
research; DFIP has tested it only with a database written to that description.
"""
from __future__ import annotations
import re
import sqlite3
from pathlib import Path

from . import ese

MAX_ROWS = 200_000
PROPERTIES = {  # result field -> property names, in order of preference
    'work_id': ('WorkID', 'DocID'),
    'path': ('System_ItemPathDisplay',),
    'name': ('System_ItemName', 'System_FileName', 'System_ItemNameDisplay'),
    'folder': ('System_ItemFolderPathDisplay',),
    'size': ('System_Size',),
    'created': ('System_DateCreated',),
    'modified': ('System_DateModified',),
    'accessed': ('System_DateAccessed',),
    'gather_time': ('System_Search_GatherTime',),
    'owner': ('System_FileOwner',),
    'kind': ('System_KindText', 'System_ItemTypeText'),
    'extension': ('System_FileExtension',),
    'summary': ('System_Search_AutoSummary',),
    'thumbnail_cache_id': ('System_ThumbnailCacheId',),
    'url': ('System_ItemUrl',),
    'computer': ('System_ComputerName',),
}
TIMES = ('created', 'modified', 'accessed', 'gather_time')
NUMBERS = ('size',)
_PREFIX = re.compile(r'^\d+-')
NOT_SET = b'*' * 8


def ws_decode(data: bytes) -> bytes:
    """Windows Search's obfuscation of some binary columns: XOR with a mask made from the value's size and position."""
    mask = 0x05000113 ^ len(data)
    return bytes(b ^ ((mask >> (8 * (i & 3))) & 0xFF) ^ (i & 0xFF) for i, b in enumerate(data))


def summary_text(data) -> str | None:
    if data is None:
        return None
    if isinstance(data, str):
        return data
    for candidate in (ws_decode(data), data):
        flag, body = candidate[:1], candidate[1:]
        try:
            if flag == b'\x01':
                text = body.decode('cp1252')
            elif flag == b'\x00' and len(body) % 2 == 0:
                text = body.decode('utf-16-le')
            else:
                continue
        except UnicodeDecodeError:
            continue
        if text and sum(c.isprintable() or c in '\r\n\t' for c in text) >= 0.9 * len(text):
            return text.rstrip('\0')
    try:
        text = data.decode('utf-16-le')
        return text.rstrip('\0') if text.isprintable() else None
    except UnicodeDecodeError:
        return None


def _number(data) -> int | None:
    """An 8-byte number as Windows Search stores it (big-endian); a little-endian one is accepted when that is the
    only reading that gives a plausible value."""
    if data is None or data == NOT_SET:
        return None
    if isinstance(data, int):
        return data
    if isinstance(data, (bytes, bytearray)) and len(data) in (4, 8):
        be, le = int.from_bytes(data, 'big'), int.from_bytes(data, 'little')
        return be if be < (1 << 56) or le >= (1 << 56) else le
    return None


def _filetime(data):
    """A FILETIME: big-endian as Windows Search stores it, else little-endian, whichever gives a plausible date."""
    if data is None or data == NOT_SET:
        return None
    if isinstance(data, int):
        candidates = [data]
    elif isinstance(data, (bytes, bytearray)) and len(data) == 8:
        candidates = [int.from_bytes(data, 'big'), int.from_bytes(data, 'little')]
    else:
        return None
    for n in candidates:
        t = ese.filetime(n)
        if t is not None and 1980 <= t.year <= 2200:
            return t
    return None


def _text(v):
    if v is None or isinstance(v, str):
        return v
    if isinstance(v, (bytes, bytearray)):
        for enc in ('utf-16-le', 'utf-8'):
            try:
                s = v.decode(enc).rstrip('\0')
                if s and s.isprintable():
                    return s
            except UnicodeDecodeError:
                continue
    return str(v)


def _entry(props: dict) -> dict:
    out = {}
    for field, names in PROPERTIES.items():
        v = next((props[n] for n in names if props.get(n) not in (None, b'', '')), None)
        if field in TIMES:
            v = _filetime(v)
        elif field in NUMBERS or field == 'work_id':
            v = _number(v) if not isinstance(v, int) else v
        elif field == 'thumbnail_cache_id':  # a 64-bit hash: no reading is more plausible than another, so big-endian as stored
            n = v if isinstance(v, int) else int.from_bytes(v, 'big') if isinstance(v, (bytes, bytearray)) and len(v) == 8 else None
            v = f'{n:016x}' if n else None
        elif field == 'summary':
            v = summary_text(v)
            v = v[:2000] if v else v
        else:
            v = _text(v)
        out[field] = v
    if not out.get('name') and out.get('path'):
        out['name'] = re.split(r'[\\/]', out['path'])[-1]
    return out


def parse_windows_edb(path, max_rows: int = MAX_ROWS) -> dict:
    out = {'status': 'COMPLETED', 'format': 'Windows.edb', 'entries': [], 'errors': [], 'capped': False}
    try:
        db = ese.open_db(path)
    except (IOError, OSError) as exc:
        return dict(out, status='FAILED', errors=[f'not a readable ESE database: {exc}'])
    try:
        found = ese.tables(db)
        name = next((n for n in ('SystemIndex_PropertyStore', 'SystemIndex_0A') if n in found), None)
        if name is None:
            return dict(out, status='FAILED', errors=['no SystemIndex_0A or SystemIndex_PropertyStore table'])
        out['table'] = name
        t = found[name]
        wanted = {n for names in PROPERTIES.values() for n in names}
        cols = [(j, _PREFIX.sub('', cname), ctype) for j, (cname, ctype) in enumerate(ese.columns(t))]
        cols = [c for c in cols if c[1] in wanted]
        for k in range(t.number_of_records):
            if len(out['entries']) >= max_rows:
                out['capped'] = True
                break
            try:
                r = t.get_record(k)
                props = {}
                for j, pname, ctype in cols:
                    if ctype in (ese.TEXT, ese.LONG_TEXT):
                        try:
                            props[pname] = ese.value(r, j, ctype)
                        except Exception:
                            props[pname] = None  # a multi-valued text property
                    elif ctype in ese.INTEGERS:
                        props[pname] = ese.value(r, j, ctype)
                    else:
                        props[pname] = ese.raw(r, j)
            except (IOError, OSError) as exc:
                out['errors'].append(f'record {k}: {exc}')
                continue
            e = _entry(props)
            if e.get('path') or e.get('name'):
                out['entries'].append(e)
        return out
    finally:
        db.close()


def parse_windows_db(path, max_rows: int = MAX_ROWS) -> dict:
    out = {'status': 'COMPLETED', 'format': 'Windows.db', 'entries': [], 'errors': [], 'capped': False}
    try:
        con = sqlite3.connect(f'file:{Path(path).as_posix()}?mode=ro', uri=True)
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.Error as exc:
        return dict(out, status='FAILED', errors=[f'not a readable SQLite database: {exc}'])
    try:
        store = next((t for t in sorted(tables) if re.fullmatch(r'SystemIndex_\d+_PropertyStore', t)), None)
        if store is None or f'{store}_Metadata' not in tables:
            return dict(out, status='FAILED', errors=['no SystemIndex_N_PropertyStore table (not a Windows Search database)'])
        out['table'] = store
        wanted = {n for names in PROPERTIES.values() for n in names}
        names = {}
        for cid, key in con.execute(f'SELECT Id, UniqueKey FROM "{store}_Metadata"'):
            pname = _PREFIX.sub('', str(key or ''))
            if pname in wanted:
                names[cid] = pname
        items: dict[int, dict] = {}
        for work_id, cid, value in con.execute(f'SELECT WorkId, ColumnId, Value FROM "{store}" ORDER BY WorkId'):
            if cid not in names:
                continue
            if work_id not in items:
                if len(items) >= max_rows:
                    out['capped'] = True
                    break
                items[work_id] = {'WorkID': work_id}
            items[work_id][names[cid]] = value
        for props in items.values():
            e = _entry(props)
            if e.get('path') or e.get('name'):
                out['entries'].append(e)
        return out
    except sqlite3.Error as exc:
        out['errors'].append(str(exc))
        return out
    finally:
        con.close()
