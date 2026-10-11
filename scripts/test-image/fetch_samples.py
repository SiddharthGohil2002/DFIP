"""Downloads the public test samples that can't be built synthetically, pinned by commit and SHA-256.

Real-world files from the dfVFS, Plaso and python-evtx projects (all Apache-2.0): Volume Shadow Copies,
BitLocker To Go, LUKS, virtual disks, split images, APFS/HFS+, SRUM, Windows Search, $MFT/$UsnJrnl, a PST,
a PCAP, real registry hives and event logs. They land in storage/test-images/samples/ (never committed), with a
NOTICE file naming their source and licence.

    docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim python scripts/test-image/fetch_samples.py
    ... fetch_samples.py --pin      # first run only: record the SHA-256 of every sample in samples.json

A file that is missing upstream, or whose hash differs from samples.json, is reported and left out; tests that
need it report "sample unavailable" instead of passing.
"""
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / 'samples.json'
OUT = HERE.parents[1] / 'storage' / 'test-images' / 'samples'


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def main():
    pin = '--pin' in sys.argv
    manifest = json.loads(MANIFEST.read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    ok = failed = 0
    notice = ['Test samples downloaded by scripts/test-image/fetch_samples.py. Each is redistributed by its',
              'upstream project under the licence shown; they are used only to test DFIP and are not part of it.', '']
    for source in manifest['sources']:
        notice.append(f"{source['name']}: https://github.com/{source['repo']} at {source['commit']} ({source['license']})")
        for item in source['files']:
            dest = OUT / source['name'] / item['name']
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_file() and item.get('sha256') and sha256(dest) == item['sha256']:
                ok += 1
                continue
            url = (f"https://raw.githubusercontent.com/{source['repo']}/{source['commit']}/"
                   f"{source['path']}/{urllib.parse.quote(item['name'])}")
            try:
                with urllib.request.urlopen(url, timeout=300) as r, dest.open('wb') as f:
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
            except Exception as exc:
                print(f"MISSING  {source['name']}/{item['name']}: {exc}")
                dest.unlink(missing_ok=True)
                failed += 1
                continue
            digest = sha256(dest)
            if pin and not item.get('sha256'):
                item['sha256'] = digest
                item['size'] = dest.stat().st_size
            if digest != item.get('sha256'):
                print(f"MISMATCH {source['name']}/{item['name']}: {digest} != {item.get('sha256')}")
                dest.unlink(missing_ok=True)
                failed += 1
                continue
            print(f"OK       {source['name']}/{item['name']} ({dest.stat().st_size:,} bytes)")
            ok += 1
    if pin:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n')
    (OUT / 'NOTICE').write_text('\n'.join(notice) + '\n')
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')  # read by the system tests
    print(f'{ok} samples ready, {failed} unavailable')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
