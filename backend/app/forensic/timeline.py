"""Builds timeline events from parsed forensic data.

Filesystem events follow Sleuth Kit `mactime` semantics: one event per distinct
timestamp of an entry, labelled with which of Modified/Accessed/Changed/Born
(created) happened at that instant, e.g. "m.cb". Timestamps are only ever taken
from the evidence itself; entries with no recorded time produce no events.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone


def event_nk(e: dict) -> str | None:
    """A stable natural key for a non-file timeline event, used to re-link tags after a re-analysis.

    It is built only from what identifies the event in its source (the record's file, URL, device, ...) and never
    from times that a later correction could change (file-system times on FAT depend on the time zone). Program
    run times are FILETIMEs from inside the Prefetch file, so they stay part of the key. The same function works
    on documents written before keys existed, which is how existing tags are migrated.
    """
    t = e.get('type')
    if t == 'FILE_MACB':
        return None
    ts = e.get('timestamp')
    ts = ts.isoformat() if hasattr(ts, 'isoformat') else ts
    if t == 'BROWSER_VISIT':
        parts = (t, e.get('source_file'), e.get('url'))
    elif t == 'BROWSER_DOWNLOAD':
        parts = (t, e.get('source_file'), e.get('description'))
    elif t == 'USB_ACTIVITY':
        parts = (t, e.get('serial'), e.get('usb_event'), e.get('description'))
    elif t == 'PROGRAM_RUN':
        parts = (t, e.get('source_file'), ts)
    elif t == 'RECENT_FILE_OPENED':
        parts = (t, e.get('source_file'), 'first' if str(e.get('description', '')).startswith('File first opened') else 'last')
    elif t == 'FILE_DELETED_TO_RECYCLE_BIN':
        parts = (t, e.get('source_file'))
    else:
        parts = (t, e.get('source_file'), ts, e.get('description'))
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


def _with_nk(events: list[dict]) -> list[dict]:
    for e in events:
        e['nk'] = event_nk(e)
    return events


def _parse_iso(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def macb_events(entry: dict, case_id: str, evidence_id: str, partition_offset: int) -> list[dict]:
    """One FILE_MACB event per distinct timestamp of a filesystem entry."""
    if entry.get('is_virtual'):
        return []
    by_time: dict[datetime, set[str]] = {}
    for letter, field in (('m', 'mtime'), ('a', 'atime'), ('c', 'ctime'), ('b', 'crtime')):
        ts = entry.get(field)
        if ts:
            by_time.setdefault(ts, set()).add(letter)
    events = []
    for ts, letters in sorted(by_time.items()):
        macb = ''.join(ch if ch in letters else '.' for ch in 'macb')
        suffix = ' (deleted)' if entry.get('deleted') else ''
        events.append({
            'case_id': case_id, 'evidence_id': evidence_id, 'timestamp': ts,
            'type': 'FILE_MACB', 'macb': macb,
            'description': f'[{macb}] {entry["path"]}{suffix}',
            'path': entry['path'], 'inode': entry.get('inode'), 'partition_offset': partition_offset,
            'volume_id': f'p{int(partition_offset or 0)}',
            'deleted': bool(entry.get('deleted')), 'is_dir': bool(entry.get('is_dir')),
            'size': entry.get('size'), 'source': 'SLEUTH_KIT_FLS',
        })
    return events


def browser_events(rows: list[dict]) -> list[dict]:
    events = []
    for r in rows:
        if r.get('type') == 'BROWSER_HISTORY':
            ts = _parse_iso(r.get('last_visit_time'))
            if ts:
                events.append({'case_id': r['case_id'], 'evidence_id': r['evidence_id'], 'timestamp': ts,
                               'type': 'BROWSER_VISIT', 'browser': r.get('browser'),
                               'description': f'{r.get("browser") or "Browser"} visit: {r.get("url")}'
                                              + (f' ({r["title"]})' if r.get('title') else ''),
                               'url': r.get('url'), 'source': r.get('source'), 'source_file': r.get('source_path')})
        elif r.get('type') == 'BROWSER_DOWNLOAD':
            ts = _parse_iso(r.get('start_time'))
            if ts:
                events.append({'case_id': r['case_id'], 'evidence_id': r['evidence_id'], 'timestamp': ts,
                               'type': 'BROWSER_DOWNLOAD', 'browser': r.get('browser'),
                               'description': f'{r.get("browser") or "Browser"} download: {r.get("target_path")}'
                                              + (f' from {r["tab_url"]}' if r.get('tab_url') else ''),
                               'url': r.get('tab_url'), 'source': r.get('source'), 'source_file': r.get('source_path')})
    return _with_nk(events)


USB_TIME_LABELS = {
    'first_install': 'first installed',
    'last_install': 'last installed',
    'last_arrival': 'last connected',
    'last_removal': 'last removed',
    'setupapi_first_install': 'first install (setupapi.dev.log)',
}


def usb_events(devices: list[dict], case_id: str, evidence_id: str) -> list[dict]:
    events = []
    for d in devices:
        label = d.get('friendly_name') or f'{d.get("vendor", "")} {d.get("product", "")}'.strip()
        for field, words in USB_TIME_LABELS.items():
            ts = _parse_iso(d.get(field))
            if ts:
                events.append({'case_id': case_id, 'evidence_id': evidence_id, 'timestamp': ts,
                               'type': 'USB_ACTIVITY', 'usb_event': field.upper(),
                               'description': f'USB device {words}: {label} (serial {d.get("serial")})',
                               'serial': d.get('serial'), 'source': d.get('source_detail', {}).get(field, d.get('source'))})
    return _with_nk(events)


# Windows activity. LNK header times describe the target file, not when it was opened, so they are kept
# on the record but do not become events; the LNK file's own times do (Windows writes the shortcut when
# the file is opened: created = first opened, modified = last opened).
ACTIVITY_EVENT_TYPES = ('PROGRAM_RUN', 'RECENT_FILE_OPENED', 'FILE_DELETED_TO_RECYCLE_BIN')


def activity_events(rows: list[dict]) -> list[dict]:
    events = []

    def add(r, ts, kind, description, path):
        dt = _parse_iso(ts)
        if dt:
            events.append({'case_id': r['case_id'], 'evidence_id': r['evidence_id'], 'timestamp': dt, 'type': kind,
                           'description': description, 'path': path, 'source': r.get('source'),
                           'source_file': r.get('source_path')})

    for r in rows:
        if r.get('type') == 'PROGRAM_RUN':
            program = r.get('executable_path') or r.get('executable')
            for i, ts in enumerate(r.get('last_run_times') or []):
                when = 'last run' if i == 0 else 'earlier run'
                add(r, ts, 'PROGRAM_RUN', f'Program run ({when}): {program} (run count {r.get("run_count")})', program)
        elif r.get('type') == 'RECENT_FILE':
            target = r.get('target_path')
            where = f' on {r["drive_type"].lower()} drive' if r.get('drive_type') else ''
            label = f' "{r["volume_label"]}"' if r.get('volume_label') else ''
            add(r, r.get('lnk_modified'), 'RECENT_FILE_OPENED', f'File opened: {target}{where}{label} (Recent shortcut)', target)
            first, last = _parse_iso(r.get('lnk_created')), _parse_iso(r.get('lnk_modified'))
            if first and (not last or abs((last - first).total_seconds()) > 2):
                add(r, r.get('lnk_created'), 'RECENT_FILE_OPENED', f'File first opened: {target}{where}{label} (Recent shortcut)', target)
        elif r.get('type') == 'RECYCLE_BIN_ITEM':
            size = f' ({r["original_size"]:,} bytes)' if isinstance(r.get('original_size'), int) else ''
            add(r, r.get('deleted_time'), 'FILE_DELETED_TO_RECYCLE_BIN',
                f'Deleted to Recycle Bin: {r.get("original_path")}{size}', r.get('original_path'))
    return _with_nk(events)
