"""Windows Timeline: ActivitiesCache.db (Windows 10 1803 and later), one per user account under
AppData/Local/ConnectedDevicesPlatform/<account>/.

Each activity says which application was used (AppId: a JSON list of the application's identifiers per platform),
what for (Payload JSON: display text, description, content URI) and when (StartTime, EndTime, as Unix seconds). Type 5
is an application or file opened, type 6 the time the application was in use (with activeDurationSeconds), type 10 a
clipboard copy (the copied text, Base64, in ClipboardPayload) and type 16 a copy and paste. ActivityOperation holds
activities waiting to be synchronised, including ones the user deleted from the Timeline (operation type 3).
"""
from __future__ import annotations
import base64
import binascii
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ACTIVITY_TYPES = {2: 'Notification', 3: 'Mobile backup', 5: 'Opened', 6: 'In use', 10: 'Copied to the clipboard',
                  11: 'System', 12: 'System', 15: 'System', 16: 'Copy and paste'}
OPERATION_TYPES = {1: 'created', 2: 'updated', 3: 'deleted by the user', 4: 'ignored'}
PLATFORM_ORDER = ('x_exe_path', 'windows_win32', 'packageId', 'windows_universal')
MAX_ROWS = 100_000
MAX_TEXT = 4000


def _time(v) -> datetime | None:
    try:
        n = int(v or 0)
    except (TypeError, ValueError):
        return None
    if n <= 0 or n > 32503680000:  # after the year 3000: not a time
        return None
    return datetime.fromtimestamp(n, tz=timezone.utc)


def _json(v):
    if v is None:
        return None
    if isinstance(v, bytes):
        v = v.decode('utf-8', 'replace')
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return None


def application(app_id) -> tuple[str | None, dict]:
    """The application named by an AppId value: the executable path or Win32 identifier, else the package name."""
    entries = _json(app_id) or []
    by_platform = {}
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and e.get('application') and e.get('platform') not in by_platform:
            by_platform[e['platform']] = e['application']
    from .user_registry import resolve_known_folder  # {F38BF404-...}\explorer.exe -> C:\Windows\explorer.exe
    for p in PLATFORM_ORDER:
        if by_platform.get(p):
            return resolve_known_folder(by_platform[p], None), by_platform
    first = next(iter(by_platform.values()), None)
    return (resolve_known_folder(first, None) if first else None), by_platform


def clipboard_text(payload) -> str | None:
    items = _json(payload)
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and item.get('formatName') == 'Text' and item.get('content'):
            try:
                raw = base64.b64decode(item['content'], validate=False)
            except (binascii.Error, ValueError):
                return None
            for enc in ('utf-8', 'utf-16-le'):
                try:
                    text = raw.decode(enc)
                    if text and all(c.isprintable() or c in '\r\n\t' for c in text):
                        return text[:MAX_TEXT]
                except UnicodeDecodeError:
                    continue
    return None


def _row(r: dict, table: str) -> dict:
    app, platforms = application(r.get('AppId'))
    payload = _json(r.get('Payload')) or {}
    if not isinstance(payload, dict):
        payload = {}
    kind = r.get('ActivityType')
    rid = r.get('Id')
    out = {
        'table': table, 'activity_id': rid.hex() if isinstance(rid, bytes) else rid, 'activity_type': kind,
        'activity_label': ACTIVITY_TYPES.get(kind, f'type {kind}'), 'app': app, 'app_platforms': platforms,
        'app_display_name': payload.get('appDisplayName'), 'display_text': payload.get('displayText'),
        'description': payload.get('description'), 'content_uri': payload.get('contentUri'),
        'activation_uri': payload.get('activationUri'), 'reporting_app': payload.get('reportingApp'),
        'duration_seconds': payload.get('activeDurationSeconds'), 'user_time_zone': payload.get('userTimezone'),
        'start_time': _time(r.get('StartTime')), 'end_time': _time(r.get('EndTime')),
        'last_modified': _time(r.get('LastModifiedTime')), 'last_modified_on_client': _time(r.get('LastModifiedOnClient')),
        'expiration_time': _time(r.get('ExpirationTime')), 'platform_device_id': r.get('PlatformDeviceId'),
        'app_activity_id': r.get('AppActivityId'), 'group': r.get('Group'),
    }
    if kind == 10 or r.get('ClipboardPayload'):
        out['clipboard_text'] = clipboard_text(r.get('ClipboardPayload'))
    if table == 'ActivityOperation':
        op = r.get('OperationType')
        out.update(operation_type=op, operation_label=OPERATION_TYPES.get(op, f'operation {op}'), created_time=_time(r.get('CreatedTime')))
    return {k: (v[:MAX_TEXT] if isinstance(v, str) else v) for k, v in out.items()}


def parse_activities_cache(path: Path, max_rows: int = MAX_ROWS) -> dict:
    """{status, activities: [...], packages: {...}, errors, capped}. Open a copy: the database is opened read-only, with
    its write-ahead log replayed if it was copied next to it."""
    out = {'status': 'COMPLETED', 'activities': [], 'errors': [], 'capped': False}
    con = None
    # A database in write-ahead-log mode needs a writable folder; where there is none, it is read as it is on disk.
    for mode in ('mode=ro', 'mode=ro&immutable=1'):
        try:
            con = sqlite3.connect(f'file:{Path(path).as_posix()}?{mode}', uri=True)
            con.row_factory = sqlite3.Row
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            break
        except sqlite3.Error as exc:
            if con is not None:
                con.close()
            con, error = None, exc
    if con is None:
        return dict(out, status='FAILED', errors=[f'not a readable SQLite database: {error}'])
    try:
        if 'Activity' not in tables:
            return dict(out, status='FAILED', errors=['no Activity table (not an ActivitiesCache database)'])
        for table, order in (('Activity', 'StartTime'), ('ActivityOperation', 'OperationOrder')):
            if table not in tables:
                continue
            for r in con.execute(f'SELECT * FROM "{table}" ORDER BY "{order}"'):
                if len(out['activities']) >= max_rows:
                    out['capped'] = True
                    break
                try:
                    out['activities'].append(_row(dict(r), table))
                except Exception as exc:  # one odd row must not lose the rest
                    out['errors'].append(f'{table} row: {exc}')
        return out
    except sqlite3.Error as exc:
        return dict(out, status='FAILED' if not out['activities'] else 'COMPLETED', errors=out['errors'] + [str(exc)])
    finally:
        con.close()
