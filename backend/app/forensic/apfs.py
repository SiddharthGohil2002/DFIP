"""APFS (Apple File System) through the Sleuth Kit's command-line tools.

An APFS container (a pool) holds volumes that share its space. pytsk3 cannot open pools, so APFS volumes are listed with
`pstat`, indexed with `fls`, and read with `ifind`, `istat` and `icat`, each given `-P apfs -B <volume superblock
block>`. A volume's id is `p<container start sector>/apfs<superblock block>`. A file is copied out once (to a temporary
file) the first time it is read, so modules that read in chunks run `icat` once per file. Encrypted volumes (FileVault)
are listed but not opened.
"""
from __future__ import annotations
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

APFS_RE = re.compile(r'^p(\d+)/apfs(\d+)$')
SECTOR = 512


def parse(vid: str | None) -> tuple[int, int] | None:
    m = APFS_RE.match(vid or '')
    return (int(m.group(1)), int(m.group(2))) if m else None


def volume_id(offset: int, apsb: int) -> str:
    return f'p{int(offset)}/apfs{int(apsb)}'


def args(vid: str) -> list[str]:
    """The Sleuth Kit options that select an APFS volume."""
    offset, apsb = parse(vid)
    return (['-o', str(offset)] if offset else []) + ['-P', 'apfs', '-B', str(apsb)]


def is_container(image: Path, offset: int) -> bool:
    """An APFS container superblock (NXSB) at the start of the partition."""
    try:
        with Path(image).open('rb') as f:
            f.seek(offset * SECTOR)
            return f.read(36)[32:36] == b'NXSB'
    except OSError:
        return False


def volumes(image: Path, offset: int) -> list[dict]:
    """The container's volumes: superblock block, name, role, case sensitivity, encryption."""
    tool = shutil.which('pstat')
    if not tool:
        return []
    p = subprocess.run([tool] + (['-o', str(offset)] if offset else []) + [str(image)], capture_output=True, text=True, timeout=120)
    out = []
    for block in re.split(r'\+-> Volume ', p.stdout)[1:]:
        apsb = re.search(r'APSB Block Number:\s*(\d+)', block)
        if not apsb:
            continue
        name = re.search(r'Name \(Role\):\s*(.*?)\s*\((.*?)\)\s*$', block, re.M)
        out.append({'apsb': int(apsb.group(1)), 'uuid': block.split('\n', 1)[0].strip(), 'name': name.group(1) if name else None,
                    'role': name.group(2) if name else None, 'encrypted': bool(re.search(r'Encrypted:\s*Yes', block)),
                    'case_sensitive': bool(re.search(r'Case Sensitive:\s*Yes', block))})
    return out


def find(image: Path, vid: str, path: str) -> str | None:
    tool = shutil.which('ifind')
    if not tool:
        return None
    p = subprocess.run([tool, *args(vid), '-n', path, str(image)], capture_output=True, text=True, timeout=120)
    inode = p.stdout.strip()
    return inode if p.returncode == 0 and inode.isdigit() else None


def size_of(image: Path, vid: str, inode: str) -> int:
    p = subprocess.run(['istat', *args(vid), str(image), str(inode)], capture_output=True, text=True, timeout=120)
    m = re.search(r'^size:\s*(\d+)', p.stdout, re.M | re.I)
    if p.returncode != 0 or not m:
        raise FileNotFoundError(f'No file {inode} on {vid}')
    return int(m.group(1))


class ApfsBlob:
    """A file on an APFS volume: copied out with icat the first time it is read."""

    def __init__(self, image: Path, vid: str, inode: str):
        if not str(inode).isdigit():
            raise ValueError('Invalid inode address')
        self._cmd = ['icat', *args(vid), str(image), str(inode)]
        self.size = size_of(image, vid, inode)
        self._tmp = None

    def read(self, start: int, length: int) -> bytes:
        if length <= 0 or start >= self.size:
            return b''
        if self._tmp is None:
            self._tmp = tempfile.TemporaryFile()
            subprocess.run(self._cmd, stdout=self._tmp, stderr=subprocess.DEVNULL, timeout=3600, check=False)
        self._tmp.seek(start)
        return self._tmp.read(min(length, self.size - start))

    def __del__(self):
        if self._tmp is not None:
            self._tmp.close()
