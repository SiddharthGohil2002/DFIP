"""Writes the test disk's manifest: every file the generator put on it, with size, SHA-256 and stamped time.

Tests use it as ground truth that does not come from DFIP (or from the Sleuth Kit), and to avoid hard-coding
values that change whenever the generator adds an artefact.

    python3 write_manifest.py <tree> <image> <partition offset> <deleted path> ...
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def main():
    tree, image, offset, *deleted = sys.argv[1:]
    tree, image = Path(tree), Path(image)
    deleted = {'/' + d.strip('/') for d in deleted}
    files = []
    for p in sorted(tree.rglob('*')):
        if p.is_file():
            path = '/' + p.relative_to(tree).as_posix()
            files.append({'path': path, 'size': p.stat().st_size, 'sha256': sha256(p),
                          'mtime': datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
                          'deleted': path in deleted})
    manifest = {'image': image.name, 'sha256': sha256(image), 'partition_offset': int(offset),
                'generated_at': datetime.now(timezone.utc).isoformat(), 'files': files}
    out = image.with_suffix('.manifest.json')
    out.write_text(json.dumps(manifest, indent=1) + '\n')
    print(f'Wrote {out} ({len(files)} files)')


if __name__ == '__main__':
    main()
