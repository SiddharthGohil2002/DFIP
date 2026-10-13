"""Finds well-known Windows artifacts in a filesystem listing and extracts them.

Paths are matched against the file index (allocated entries only), then each
file is copied out of the evidence (the disk image through pytsk3, or a logical
package's folders) into DFIP's analysis directory under its original name, so
parsers that key on filenames (and SQLite journal/WAL sidecars) keep working.
The evidence is only ever read.
"""
from __future__ import annotations
import re
from pathlib import Path


_USERS = r'/(?:Users|Documents and Settings)/[^/]+'
TARGETS = [
    ('CHROMIUM_HISTORY', re.compile(
        _USERS + r'/AppData/(?:Local/(?P<browser>Google/Chrome|Microsoft/Edge|BraveSoftware/Brave-Browser|Chromium|Vivaldi)'
                 r'/User Data/[^/]+|Roaming/Opera Software/(?P<opera>Opera Stable|Opera GX Stable)(?:/(?:Default|Profile [0-9]+))?)'
                 r'/History$', re.I)),
    ('FIREFOX_PLACES', re.compile(_USERS + r'/AppData/Roaming/Mozilla/Firefox/Profiles/[^/]+/places\.sqlite$', re.I)),
    # Linux (~/.config, ~/.mozilla) and macOS (~/Library/Application Support) profiles.
    ('CHROMIUM_HISTORY', re.compile(r'^/(?:home/[^/]+|root)/\.config/(?P<browser>google-chrome|chromium|microsoft-edge|BraveSoftware/Brave-Browser|vivaldi)'
                                    r'/[^/]+/History$', re.I)),
    ('CHROMIUM_HISTORY', re.compile(r'^/Users/[^/]+/Library/Application Support/(?P<browser>Google/Chrome|Microsoft Edge|BraveSoftware/Brave-Browser|Chromium|Vivaldi)'
                                    r'/[^/]+/History$', re.I)),
    ('FIREFOX_PLACES', re.compile(r'^/(?:home/[^/]+|root)/\.mozilla/firefox/[^/]+/places\.sqlite$', re.I)),
    ('FIREFOX_PLACES', re.compile(r'^/Users/[^/]+/Library/Application Support/Firefox/Profiles/[^/]+/places\.sqlite$', re.I)),
    ('SYSTEM_HIVE', re.compile(r'^/Windows/System32/config/SYSTEM$', re.I)),
    ('SETUPAPI_LOG', re.compile(r'^/Windows/INF/setupapi\.dev(?:\.\d{8}_\d{6})?\.log$', re.I)),
    # Windows activity: files moved to the Recycle Bin, files opened (Recent shortcuts), programs run.
    ('RECYCLE_BIN_INFO', re.compile(r'^/\$Recycle\.Bin/(?P<sid>[^/]+)/\$I(?P<suffix>[^/]+)$', re.I)),
    ('LNK_RECENT', re.compile(_USERS + r'/AppData/Roaming/Microsoft/(?:Windows|Office)/Recent/[^/]+\.lnk$', re.I)),
    ('PREFETCH', re.compile(r'^/Windows/Prefetch/[^/]+\.pf$', re.I)),
]
# The content of a recycled item: $R<suffix> next to its $I<suffix> (a file, or a folder for a recycled folder).
RECYCLE_DATA = re.compile(r'^/\$Recycle\.Bin/(?P<sid>[^/]+)/\$R(?P<suffix>[^/]+)$', re.I)
SQLITE_SIDECARS = ('-journal', '-wal')
BROWSER_NAMES = {
    'google/chrome': 'Chrome', 'microsoft/edge': 'Edge', 'google-chrome': 'Chrome', 'microsoft-edge': 'Edge', 'microsoft edge': 'Edge',
    'bravesoftware/brave-browser': 'Brave', 'chromium': 'Chromium', 'vivaldi': 'Vivaldi',
}


def classify(path: str) -> tuple[str, dict] | None:
    """Returns (artifact kind, details) for a known artifact path, else None."""
    for kind, rx in TARGETS:
        m = rx.search(path)
        if m:
            details = {}
            if kind == 'CHROMIUM_HISTORY' and m.groupdict().get('opera'):
                details['browser'] = 'Opera GX' if 'GX' in m.group('opera') else 'Opera'
            elif kind == 'CHROMIUM_HISTORY':
                details['browser'] = BROWSER_NAMES.get(m.group('browser').lower(), 'Chromium')
            elif kind == 'FIREFOX_PLACES':
                details['browser'] = 'Firefox'
            elif kind == 'RECYCLE_BIN_INFO':
                details.update(sid=m.group('sid'), suffix=m.group('suffix'))
            return kind, details
    return None


class ArtifactCollector:
    """Accumulates matches while a bodyfile is streamed through `observe`."""

    def __init__(self):
        self.matches: list[dict] = []
        self._by_path: dict[str, dict] = {}
        self._recycle_data: dict[tuple, dict] = {}

    def observe(self, entry: dict, partition_offset: int):
        if entry.get('deleted') or entry.get('is_virtual'):
            return
        path = entry['path']
        data = RECYCLE_DATA.search(path)
        if data:
            self._recycle_data[(partition_offset, data.group('sid').lower(), data.group('suffix').lower())] = {
                'path': path, 'inode': entry['inode'], 'size': entry.get('size'), 'is_dir': bool(entry.get('is_dir'))}
            return
        if entry.get('is_dir'):
            return
        hit = classify(path)
        if hit:
            kind, details = hit
            # The file's own times matter for some kinds: a Recent shortcut is written when its target is opened.
            item = {'kind': kind, 'path': path, 'inode': entry['inode'], 'size': entry.get('size'),
                    'partition_offset': partition_offset, 'volume_id': entry.get('volume_id'), 'sidecars': [],
                    'fs_mtime': entry.get('mtime'), 'fs_crtime': entry.get('crtime'), **details}
            self.matches.append(item)
            self._by_path[path.lower()] = item
            return
        for suffix in SQLITE_SIDECARS:
            if path.endswith(suffix):
                # Sidecars are listed after or before their database; resolve at the end.
                self._by_path.setdefault('#sidecar#' + path.lower(),
                                         {'path': path, 'inode': entry['inode'], 'partition_offset': partition_offset})

    def resolved(self) -> list[dict]:
        for item in self.matches:
            if item['kind'] == 'RECYCLE_BIN_INFO':
                item['recycle_data'] = self._recycle_data.get(
                    (item['partition_offset'], item['sid'].lower(), item['suffix'].lower()))
        for key, side in list(self._by_path.items()):
            if not key.startswith('#sidecar#'):
                continue
            for suffix in SQLITE_SIDECARS:
                if side['path'].endswith(suffix):
                    owner = self._by_path.get(side['path'][:-len(suffix)].lower())
                    if owner and owner['partition_offset'] == side['partition_offset']:
                        owner['sidecars'].append({'path': side['path'], 'inode': side['inode']})
        return self.matches


def extract(src, evidence_id: str, item: dict, dest_dir: Path) -> dict:
    """Copies an artifact (and its sidecars) out of the evidence (disk image or package) into dest_dir, keeping basenames."""
    from .source import BlobRef, volume_id
    vid = item.get('volume_id') or volume_id(item['partition_offset'])
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / item['path'].rsplit('/', 1)[-1]
    try:
        size, digest = src.copy_to(BlobRef(evidence_id, vid, inode=item['inode']), target)
    except (OSError, ValueError) as exc:
        return {'status': 'FAILED', 'error': str(exc)}
    out = {'status': 'COMPLETED', 'local_path': str(target), 'sha256': digest, 'size': size, 'sidecars': []}
    for side in item.get('sidecars', []):
        side_target = dest_dir / side['path'].rsplit('/', 1)[-1]
        try:
            _, side_digest = src.copy_to(BlobRef(evidence_id, vid, inode=side['inode']), side_target)
        except (OSError, ValueError):
            continue
        out['sidecars'].append({'path': side['path'], 'local_path': str(side_target), 'sha256': side_digest})
    return out
