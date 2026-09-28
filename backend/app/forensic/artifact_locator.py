"""Finds well-known Windows artifacts in a filesystem listing and extracts them.

Paths are matched against the Sleuth Kit listing (allocated entries only), then
each file is copied out with `icat` into DFIP's analysis directory under its
original name, so parsers that key on filenames (and SQLite journal/WAL
sidecars) keep working. The source image is only ever read.
"""
from __future__ import annotations
import hashlib
import re
from pathlib import Path

from .tools import recover_file

_USERS = r'/(?:Users|Documents and Settings)/[^/]+'
TARGETS = [
    ('CHROMIUM_HISTORY', re.compile(
        _USERS + r'/AppData/Local/(?P<browser>Google/Chrome|Microsoft/Edge|BraveSoftware/Brave-Browser|Chromium)'
                 r'/User Data/[^/]+/History$', re.I)),
    ('FIREFOX_PLACES', re.compile(_USERS + r'/AppData/Roaming/Mozilla/Firefox/Profiles/[^/]+/places\.sqlite$', re.I)),
    ('SYSTEM_HIVE', re.compile(r'^/Windows/System32/config/SYSTEM$', re.I)),
    ('SETUPAPI_LOG', re.compile(r'^/Windows/INF/setupapi\.dev(?:\.\d{8}_\d{6})?\.log$', re.I)),
]
SQLITE_SIDECARS = ('-journal', '-wal')
BROWSER_NAMES = {
    'google/chrome': 'Chrome', 'microsoft/edge': 'Edge',
    'bravesoftware/brave-browser': 'Brave', 'chromium': 'Chromium',
}


def classify(path: str) -> tuple[str, dict] | None:
    """Returns (artifact kind, details) for a known artifact path, else None."""
    for kind, rx in TARGETS:
        m = rx.search(path)
        if m:
            details = {}
            if kind == 'CHROMIUM_HISTORY':
                details['browser'] = BROWSER_NAMES.get(m.group('browser').lower(), 'Chromium')
            elif kind == 'FIREFOX_PLACES':
                details['browser'] = 'Firefox'
            return kind, details
    return None


class ArtifactCollector:
    """Accumulates matches while a bodyfile is streamed through `observe`."""

    def __init__(self):
        self.matches: list[dict] = []
        self._by_path: dict[str, dict] = {}

    def observe(self, entry: dict, partition_offset: int):
        if entry.get('deleted') or entry.get('is_dir') or entry.get('is_virtual'):
            return
        path = entry['path']
        hit = classify(path)
        if hit:
            kind, details = hit
            item = {'kind': kind, 'path': path, 'inode': entry['inode'], 'size': entry.get('size'),
                    'partition_offset': partition_offset, 'sidecars': [], **details}
            self.matches.append(item)
            self._by_path[path.lower()] = item
            return
        for suffix in SQLITE_SIDECARS:
            if path.endswith(suffix):
                # Sidecars are listed after or before their database; resolve at the end.
                self._by_path.setdefault('#sidecar#' + path.lower(),
                                         {'path': path, 'inode': entry['inode'], 'partition_offset': partition_offset})

    def resolved(self) -> list[dict]:
        for key, side in list(self._by_path.items()):
            if not key.startswith('#sidecar#'):
                continue
            for suffix in SQLITE_SIDECARS:
                if side['path'].endswith(suffix):
                    owner = self._by_path.get(side['path'][:-len(suffix)].lower())
                    if owner and owner['partition_offset'] == side['partition_offset']:
                        owner['sidecars'].append({'path': side['path'], 'inode': side['inode']})
        return self.matches


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def extract(image: Path, item: dict, dest_dir: Path) -> dict:
    """icat-extracts an artifact (and its sidecars) into dest_dir, keeping basenames."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = item['path'].rsplit('/', 1)[-1]
    target = dest_dir / name
    r = recover_file(image, item['inode'], target, item['partition_offset'])
    if r.get('status') != 'COMPLETED':
        return {'status': r.get('status', 'FAILED'), 'error': r.get('stderr') or r.get('status')}
    out = {'status': 'COMPLETED', 'local_path': str(target), 'sha256': _sha256(target), 'size': target.stat().st_size,
           'sidecars': []}
    for side in item.get('sidecars', []):
        side_target = dest_dir / side['path'].rsplit('/', 1)[-1]
        sr = recover_file(image, side['inode'], side_target, item['partition_offset'])
        if sr.get('status') == 'COMPLETED':
            out['sidecars'].append({'path': side['path'], 'local_path': str(side_target), 'sha256': _sha256(side_target)})
    return out
