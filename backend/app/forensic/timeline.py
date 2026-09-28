"""Builds timeline events from parsed forensic data.

Filesystem events follow Sleuth Kit `mactime` semantics: one event per distinct
timestamp of an entry, labelled with which of Modified/Accessed/Changed/Born
(created) happened at that instant, e.g. "m.cb". Timestamps are only ever taken
from the evidence itself; entries with no recorded time produce no events.
"""
from __future__ import annotations
from datetime import datetime, timezone


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
    return events


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
    return events
