"""Timelines made by Plaso (log2timeline, psort, psteal), imported next to DFIP's own events.

Two psort output formats are read, streamed line by line:
- json_line: one JSON event per line: `timestamp` (microseconds since 1970, UTC; 0 when the event has no time),
  `timestamp_desc`, `parser`, `data_type`, `message`, `display_name`, `filename`, `inode` and the parser's own fields;
- l2tcsv: the log2timeline CSV (date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version,
  filename, inode, notes, format, extra), its date and time read in the timezone column.
Events without a time are counted, not imported. Values are only ever read as text (a JSON line is never evaluated).
"""
from __future__ import annotations
import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from .timezone import local_to_utc

L2T_HEADER = ['date', 'time', 'timezone', 'MACB', 'source', 'sourcetype', 'type', 'user', 'host', 'short', 'desc', 'version',
              'filename', 'inode', 'notes', 'format', 'extra']
MAX_LINE = 1 << 20
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class TimelineError(ValueError):
    pass


def detect(path: Path) -> str:
    """'json_line' or 'l2tcsv' from the first line; TimelineError for anything else."""
    with Path(path).open('rb') as f:
        first = f.readline(MAX_LINE).decode('utf-8-sig', errors='replace').strip()
    if first.startswith('{'):
        try:
            json.loads(first)
        except ValueError:
            raise TimelineError('The first line is not a JSON object: not a Plaso json_line file')
        return 'json_line'
    if [c.strip() for c in first.split(',')][:len(L2T_HEADER)] == L2T_HEADER:
        return 'l2tcsv'
    raise TimelineError('Not a Plaso timeline: export it with psort -o json_line or -o l2tcsv')


def _text(v, limit=2000):
    if v is None:
        return None
    return str(v)[:limit]


def iter_events(path: Path, fmt: str) -> Iterator[dict]:
    """Normalised events: {timestamp (UTC, or None), timestamp_desc, parser, data_type, message, source_name, filename,
    inode, line}."""
    if fmt == 'json_line':
        with Path(path).open('r', encoding='utf-8-sig', errors='replace') as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    yield {'error': f'line {n} is not JSON', 'line': n}
                    continue
                if not isinstance(d, dict):
                    continue
                ts = d.get('timestamp')
                when = EPOCH + timedelta(microseconds=int(ts)) if isinstance(ts, (int, float)) and ts else None
                yield {'timestamp': when, 'timestamp_desc': _text(d.get('timestamp_desc'), 200), 'parser': _text(d.get('parser'), 200),
                       'data_type': _text(d.get('data_type'), 200), 'message': _text(d.get('message')),
                       'source_name': _text(d.get('display_name'), 1000), 'filename': _text(d.get('filename'), 1000),
                       'inode': _text(d.get('inode'), 100), 'line': n}
    else:
        with Path(path).open('r', encoding='utf-8-sig', errors='replace', newline='') as f:
            reader = csv.reader(f)
            next(reader, None)
            for n, row in enumerate(reader, 2):
                if len(row) < len(L2T_HEADER):
                    yield {'error': f'line {n} has {len(row)} columns', 'line': n}
                    continue
                r = dict(zip(L2T_HEADER, row))
                when = None
                try:
                    local = datetime.strptime(f"{r['date']} {r['time']}", '%m/%d/%Y %H:%M:%S')
                    zone = (r['timezone'] or 'UTC').strip()
                    when = local.replace(tzinfo=timezone.utc) if zone.upper() in ('UTC', 'GMT', 'ETC/UTC') else local_to_utc(local, zone)
                except ValueError:
                    when = None
                yield {'timestamp': when, 'timestamp_desc': _text(r['type'], 200), 'parser': _text(r['format'], 200),
                       'data_type': _text(r['sourcetype'], 200), 'message': _text(r['desc']), 'source_name': _text(r['source'], 1000),
                       'filename': _text(r['filename'], 1000), 'inode': _text(r['inode'], 100), 'macb': _text(r['MACB'], 4), 'line': n}
