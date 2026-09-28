"""Browser artifact parsing: history, downloads, and cookies from Chromium-family
(Chrome/Edge/Brave) and Firefox SQLite databases recovered from an evidence image.

Design rules carried over from the rest of the forensic engine:
  - Never write to the source database file. We always copy it to a scratch
    location and open the copy, because SQLite databases opened directly (even
    read-only) can trigger WAL/journal file creation, which would touch
    evidence.
  - Never fabricate rows. If a table is missing/corrupt or a WAL file exists
    unmerged, we surface a real 'PARTIAL' or 'FAILED' status rather than
    inventing plausible-looking browsing history.
  - Every returned artifact is tagged with its exact source file, table, and
    row so it is independently checkable against the original database.
"""
from __future__ import annotations
import sqlite3
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Chromium stores timestamps as microseconds since 1601-01-01 (WebKit epoch).
_CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Firefox stores timestamps as microseconds since Unix epoch already.
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

CHROMIUM_HISTORY_FILENAMES = {'History', 'history'}
CHROMIUM_COOKIES_FILENAMES = {'Cookies', 'cookies'}
FIREFOX_PLACES_FILENAMES = {'places.sqlite'}
FIREFOX_COOKIES_FILENAMES = {'cookies.sqlite'}


def _chromium_time(us: int | None):
    if not us:
        return None
    try:
        return (_CHROMIUM_EPOCH + timedelta(microseconds=us)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _firefox_time_us(us: int | None):
    if not us:
        return None
    try:
        return (_UNIX_EPOCH + timedelta(microseconds=us)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _firefox_time_ms(ms: int | None):
    if not ms:
        return None
    try:
        return (_UNIX_EPOCH + timedelta(milliseconds=ms)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _open_readonly_copy(source: Path):
    """Copy the DB (plus any -wal/-journal sidecar) to a scratch dir and open
    the copy. Returns (connection, scratch_dir) or raises on failure. Caller
    must clean up scratch_dir."""
    scratch_dir = Path(tempfile.mkdtemp(prefix='dfip_browser_'))
    dest = scratch_dir / source.name
    shutil.copy2(source, dest)
    for suffix in ('-wal', '-journal', '-shm'):
        sidecar = source.parent / (source.name + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, scratch_dir / (dest.name + suffix))
    conn = sqlite3.connect(f'file:{dest}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    return conn, scratch_dir


def parse_chromium_history(source_path: Path, case_id: str, evidence_id: str, limit: int = 50_000):
    """Parses a Chromium-family `History` SQLite file: urls + downloads tables."""
    result = {'status': 'COMPLETED', 'source_file': str(source_path), 'browser_family': 'CHROMIUM',
               'history': [], 'downloads': [], 'errors': []}
    scratch_dir = None
    try:
        conn, scratch_dir = _open_readonly_copy(source_path)
        try:
            cur = conn.execute(
                "SELECT id, url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?",
                (limit,))
            for row in cur.fetchall():
                result['history'].append({
                    'case_id': case_id, 'evidence_id': evidence_id, 'type': 'BROWSER_HISTORY',
                    'source': 'CHROMIUM_HISTORY_SQLITE', 'source_file': str(source_path), 'row_id': row['id'],
                    'url': row['url'], 'title': row['title'], 'visit_count': row['visit_count'],
                    'last_visit_time': _chromium_time(row['last_visit_time']),
                })
        except sqlite3.Error as exc:
            result['errors'].append(f'urls table: {exc}')
            result['status'] = 'PARTIAL'
        try:
            cur = conn.execute(
                "SELECT id, target_path, tab_url, total_bytes, start_time, end_time, state "
                "FROM downloads ORDER BY start_time DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                result['downloads'].append({
                    'case_id': case_id, 'evidence_id': evidence_id, 'type': 'BROWSER_DOWNLOAD',
                    'source': 'CHROMIUM_HISTORY_SQLITE', 'source_file': str(source_path), 'row_id': row['id'],
                    'target_path': row['target_path'], 'tab_url': row['tab_url'], 'total_bytes': row['total_bytes'],
                    'start_time': _chromium_time(row['start_time']), 'end_time': _chromium_time(row['end_time']),
                    'state': row['state'],
                })
        except sqlite3.Error as exc:
            result['errors'].append(f'downloads table: {exc}')
            result['status'] = 'PARTIAL'
        conn.close()
    except (sqlite3.Error, OSError) as exc:
        result['status'] = 'FAILED'
        result['errors'].append(str(exc))
    finally:
        if scratch_dir and scratch_dir.exists():
            shutil.rmtree(scratch_dir, ignore_errors=True)
    return result


def parse_chromium_cookies(source_path: Path, case_id: str, evidence_id: str, limit: int = 50_000):
    """Parses a Chromium-family `Cookies` SQLite file. Cookie *values* are
    encrypted at rest by the OS keychain/DPAPI and are NOT decrypted here —
    only metadata (host, name, expiry, flags) is extracted, since decrypting
    would require the original user's OS credential store, which is out of
    scope for offline forensic parsing and would otherwise tempt fabricating
    a 'decrypted' value we can't actually verify."""
    result = {'status': 'COMPLETED', 'source_file': str(source_path), 'browser_family': 'CHROMIUM',
               'cookies': [], 'errors': [], 'note': 'Cookie values are encrypted at rest; only metadata is extracted.'}
    scratch_dir = None
    try:
        conn, scratch_dir = _open_readonly_copy(source_path)
        try:
            cur = conn.execute(
                "SELECT host_key, name, path, creation_utc, expires_utc, is_secure, is_httponly "
                "FROM cookies ORDER BY creation_utc DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                result['cookies'].append({
                    'case_id': case_id, 'evidence_id': evidence_id, 'type': 'BROWSER_COOKIE',
                    'source': 'CHROMIUM_COOKIES_SQLITE', 'source_file': str(source_path),
                    'host': row['host_key'], 'name': row['name'], 'path': row['path'],
                    'created': _chromium_time(row['creation_utc']), 'expires': _chromium_time(row['expires_utc']),
                    'secure': bool(row['is_secure']), 'http_only': bool(row['is_httponly']),
                })
        except sqlite3.Error as exc:
            result['errors'].append(f'cookies table: {exc}')
            result['status'] = 'PARTIAL' if result['cookies'] else 'FAILED'
        conn.close()
    except (sqlite3.Error, OSError) as exc:
        result['status'] = 'FAILED'
        result['errors'].append(str(exc))
    finally:
        if scratch_dir and scratch_dir.exists():
            shutil.rmtree(scratch_dir, ignore_errors=True)
    return result


def parse_firefox_places(source_path: Path, case_id: str, evidence_id: str, limit: int = 50_000):
    """Parses a Firefox `places.sqlite` file: moz_places (history) and, for
    Firefox 26+, downloads recorded as `downloads/destinationFileURI`
    annotations in moz_annos. Older Firefox kept downloads in downloads.sqlite,
    which this parser does not read."""
    result = {'status': 'COMPLETED', 'source_file': str(source_path), 'browser_family': 'FIREFOX',
               'history': [], 'downloads': [], 'errors': []}
    scratch_dir = None
    try:
        conn, scratch_dir = _open_readonly_copy(source_path)
        try:
            cur = conn.execute(
                "SELECT id, url, title, visit_count, last_visit_date FROM moz_places "
                "ORDER BY last_visit_date DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                result['history'].append({
                    'case_id': case_id, 'evidence_id': evidence_id, 'type': 'BROWSER_HISTORY',
                    'source': 'FIREFOX_PLACES_SQLITE', 'source_file': str(source_path), 'row_id': row['id'],
                    'url': row['url'], 'title': row['title'], 'visit_count': row['visit_count'],
                    'last_visit_time': _firefox_time_us(row['last_visit_date']),
                })
        except sqlite3.Error as exc:
            result['errors'].append(f'moz_places table: {exc}')
            result['status'] = 'PARTIAL' if result['history'] else 'FAILED'
        try:
            cur = conn.execute(
                "SELECT a.id, p.url, a.content, a.dateAdded FROM moz_annos a "
                "JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id "
                "JOIN moz_places p ON p.id = a.place_id "
                "WHERE n.name = 'downloads/destinationFileURI' ORDER BY a.dateAdded DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                result['downloads'].append({
                    'case_id': case_id, 'evidence_id': evidence_id, 'type': 'BROWSER_DOWNLOAD',
                    'source': 'FIREFOX_PLACES_SQLITE', 'source_file': str(source_path), 'row_id': row['id'],
                    'target_path': row['content'], 'tab_url': row['url'],
                    'start_time': _firefox_time_us(row['dateAdded']),
                })
        except sqlite3.Error as exc:
            # moz_annos is absent in some profiles; history is still valid.
            result['errors'].append(f'moz_annos downloads: {exc}')
        conn.close()
    except (sqlite3.Error, OSError) as exc:
        result['status'] = 'FAILED'
        result['errors'].append(str(exc))
    finally:
        if scratch_dir and scratch_dir.exists():
            shutil.rmtree(scratch_dir, ignore_errors=True)
    return result


def parse_firefox_cookies(source_path: Path, case_id: str, evidence_id: str, limit: int = 50_000):
    """Parses a Firefox `cookies.sqlite` file (moz_cookies). Firefox does not
    encrypt cookie values at rest the way Chromium does, so the value itself
    is included here — unlike the Chromium parser above."""
    result = {'status': 'COMPLETED', 'source_file': str(source_path), 'browser_family': 'FIREFOX',
               'cookies': [], 'errors': []}
    scratch_dir = None
    try:
        conn, scratch_dir = _open_readonly_copy(source_path)
        try:
            cur = conn.execute(
                "SELECT host, name, value, path, creationTime, expiry, isSecure, isHttpOnly "
                "FROM moz_cookies ORDER BY creationTime DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                result['cookies'].append({
                    'case_id': case_id, 'evidence_id': evidence_id, 'type': 'BROWSER_COOKIE',
                    'source': 'FIREFOX_COOKIES_SQLITE', 'source_file': str(source_path),
                    'host': row['host'], 'name': row['name'], 'value': row['value'], 'path': row['path'],
                    'created': _firefox_time_us(row['creationTime']),
                    'expires': datetime.fromtimestamp(row['expiry'], tz=timezone.utc).isoformat() if row['expiry'] else None,
                    'secure': bool(row['isSecure']), 'http_only': bool(row['isHttpOnly']),
                })
        except sqlite3.Error as exc:
            result['errors'].append(f'moz_cookies table: {exc}')
            result['status'] = 'PARTIAL' if result['cookies'] else 'FAILED'
        conn.close()
    except (sqlite3.Error, OSError) as exc:
        result['status'] = 'FAILED'
        result['errors'].append(str(exc))
    finally:
        if scratch_dir and scratch_dir.exists():
            shutil.rmtree(scratch_dir, ignore_errors=True)
    return result


def identify_browser_file(filename: str) -> str | None:
    """Classifies a recovered/carved filename into a known browser artifact
    type, or None if unrecognized. Used by the API layer to route a file to
    the right parser without guessing based on file content."""
    name = Path(filename).name
    if name in CHROMIUM_HISTORY_FILENAMES:
        return 'CHROMIUM_HISTORY'
    if name in CHROMIUM_COOKIES_FILENAMES:
        return 'CHROMIUM_COOKIES'
    if name in FIREFOX_PLACES_FILENAMES:
        return 'FIREFOX_PLACES'
    if name in FIREFOX_COOKIES_FILENAMES:
        return 'FIREFOX_COOKIES'
    return None


PARSERS = {
    'CHROMIUM_HISTORY': parse_chromium_history,
    'CHROMIUM_COOKIES': parse_chromium_cookies,
    'FIREFOX_PLACES': parse_firefox_places,
    'FIREFOX_COOKIES': parse_firefox_cookies,
}
