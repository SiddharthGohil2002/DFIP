"""Reading Extensible Storage Engine (ESE / JET Blue) databases with libesedb (pyesedb): column values as Python values
by column type, long values included."""
from __future__ import annotations
import struct
import uuid
from datetime import datetime, timedelta, timezone

OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
# JET column types.
BIT, UBYTE, SHORT, LONG, CURRENCY, FLOAT, DOUBLE, DATETIME, BINARY, TEXT, LONG_BINARY, LONG_TEXT, SLV, ULONG, LONGLONG, GUID, USHORT = range(1, 18)
INTEGERS = {BIT, UBYTE, SHORT, LONG, CURRENCY, ULONG, LONGLONG, USHORT}


def open_db(path):
    import pyesedb
    f = pyesedb.file()
    f.open(str(path))
    return f


def tables(db) -> dict:
    return {db.get_table(i).name: db.get_table(i) for i in range(db.number_of_tables)}


def columns(table) -> list[tuple[str, int]]:
    return [(table.get_column(j).name, table.get_column(j).type) for j in range(table.number_of_columns)]


def ole_date(days: float | None) -> datetime | None:
    if days is None or days <= 0:
        return None
    try:
        return OLE_EPOCH + timedelta(days=days)
    except OverflowError:
        return None


def filetime(n: int | None) -> datetime | None:
    if not n or n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


def raw(record, i: int) -> bytes | None:
    """A value's bytes, long values (stored in the long-value tree) included."""
    try:
        if record.is_long_value(i):
            lv = record.get_value_data_as_long_value(i)
            return lv.get_data() if lv is not None else None
        return record.get_value_data(i)
    except (IOError, OSError):
        return None


def value(record, i: int, ctype: int):
    """A column value as int, float, datetime (DATETIME), str (text), uuid string (GUID) or bytes."""
    data = raw(record, i)
    if data is None:
        return None
    try:
        if ctype in INTEGERS:
            n = record.get_value_data_as_integer(i)
            return n
        if ctype in (FLOAT, DOUBLE):
            return record.get_value_data_as_floating_point(i)
        if ctype == DATETIME:
            return ole_date(struct.unpack('<d', data[:8])[0]) if len(data) >= 8 else None
        if ctype in (TEXT, LONG_TEXT):
            if record.is_long_value(i):
                lv = record.get_value_data_as_long_value(i)
                return lv.get_data_as_string() if lv is not None else None
            return record.get_value_data_as_string(i)
        if ctype == GUID:
            return str(uuid.UUID(bytes_le=data[:16])) if len(data) >= 16 else None
    except (IOError, OSError, ValueError, struct.error):
        return data
    return data
