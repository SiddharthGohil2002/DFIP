"""Hash sets: lists of known file hashes (known good, known bad, notable) that every evidence file is compared with.

Each set lives in its own SQLite file (storage/hashsets/<set id>.sqlite) with one WITHOUT ROWID table per
algorithm, holding raw digests as primary keys, so even the NSRL (tens of millions of hashes) is looked up in
batches without loading it into memory or into MongoDB. Only the set's description is kept in MongoDB.

Import formats, recognised from the content:
  * plain text: one MD5, SHA-1 or SHA-256 per line (the first word; `md5sum`/`sha256sum` output works), # comments
  * CSV with a header naming md5 / sha1 / sha256 columns (sha-1, sha-256 and case variants accepted)
  * NIST NSRL RDS v3 SQLite: the FILE table's md5, sha1 and sha256 columns
"""
from __future__ import annotations
import csv
import re
import sqlite3
from pathlib import Path

from ..core.config import settings

ALGORITHMS = {'md5': 16, 'sha1': 20, 'sha256': 32}
BY_HEX_LENGTH = {32: 'md5', 40: 'sha1', 64: 'sha256'}
KINDS = ('KNOWN_GOOD', 'KNOWN_BAD', 'NOTABLE')
BATCH = 10_000
LOOKUP_BATCH = 500
_HEX = re.compile(r'^[0-9a-fA-F]+$')
_COLUMN = {'md5': 'md5', 'sha1': 'sha1', 'sha-1': 'sha1', 'sha256': 'sha256', 'sha-256': 'sha256'}


def root() -> Path:
    p = Path(settings.storage_path).resolve() / 'hashsets'
    p.mkdir(parents=True, exist_ok=True)
    return p


def store_path(set_id: str) -> Path:
    return root() / f'{set_id}.sqlite'


def _create(path: Path) -> sqlite3.Connection:
    path.unlink(missing_ok=True)
    con = sqlite3.connect(str(path))
    con.execute('PRAGMA journal_mode=OFF')
    con.execute('PRAGMA synchronous=OFF')
    for algo in ALGORITHMS:
        con.execute(f'CREATE TABLE {algo} (h BLOB PRIMARY KEY) WITHOUT ROWID')
    return con


def _digest(value, algo=None):
    """(algorithm, raw bytes) for a hex digest, or None when it is not one."""
    s = (value or '').strip().lower() if isinstance(value, str) else (value.hex() if isinstance(value, bytes) else '')
    if not s or not _HEX.match(s):
        return None
    a = algo or BY_HEX_LENGTH.get(len(s))
    if not a or len(s) != ALGORITHMS[a] * 2:
        return None
    return a, bytes.fromhex(s)


class _Writer:
    def __init__(self, con):
        self.con, self.pending, self.counts, self.invalid = con, {a: [] for a in ALGORITHMS}, {a: 0 for a in ALGORITHMS}, 0

    def add(self, value, algo=None):
        d = _digest(value, algo)
        if d is None:
            self.invalid += 1
            return
        self.pending[d[0]].append((d[1],))
        if len(self.pending[d[0]]) >= BATCH:
            self.flush(d[0])

    def flush(self, algo=None):
        for a in ([algo] if algo else list(ALGORITHMS)):
            if self.pending[a]:
                cur = self.con.executemany(f'INSERT OR IGNORE INTO {a} (h) VALUES (?)', self.pending[a])
                self.counts[a] += cur.rowcount
                self.pending[a] = []
        self.con.commit()


def _import_nsrl(source: Path, writer: _Writer, progress) -> str:
    src = sqlite3.connect(f'file:{source}?mode=ro', uri=True)
    tables = {r[0].lower(): r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
    table = tables.get('file')
    if not table:
        raise ValueError('SQLite file without an NSRL RDS v3 FILE table')
    cols = {r[1].lower(): r[1] for r in src.execute(f'PRAGMA table_info("{table}")')}
    use = [a for a in ALGORITHMS if a in cols]
    if not use:
        raise ValueError('The FILE table has no md5, sha1 or sha256 column')
    total = src.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] or 1
    done = 0
    for row in src.execute(f'SELECT {", ".join(chr(34) + cols[a] + chr(34) for a in use)} FROM "{table}"'):
        for a, v in zip(use, row):
            if v:
                writer.add(v, a)
        done += 1
        if done % 100_000 == 0:
            progress(done / total)
    src.close()
    return 'NSRL RDS v3 (SQLite)'


def _import_text(source: Path, writer: _Writer, progress) -> str:
    size = max(1, source.stat().st_size)
    read = [0]

    def lines(f):
        # Counts what was read, for progress: a text file's position can't be asked for while iterating over it.
        for n, line in enumerate(f, 1):
            read[0] += len(line)
            if n % 100_000 == 0:
                progress(min(0.99, read[0] / size))
            yield line

    with source.open('r', encoding='utf-8', errors='replace', newline='') as f:
        first = f.readline()
        header = [h.strip().strip('"').lower() for h in first.split(',')]
        f.seek(0)
        if len(header) > 1 and any(h in _COLUMN for h in header):
            reader = csv.reader(lines(f))
            cols = [(i, _COLUMN[h]) for i, h in enumerate(h.strip().strip('"').lower() for h in next(reader)) if h in _COLUMN]
            for row in reader:
                for i, algo in cols:
                    if i < len(row) and row[i].strip():
                        writer.add(row[i], algo)
            return 'CSV'
        for line in lines(f):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            writer.add(line.split()[0].lstrip('\\*'))
        return 'text'


def import_set(source: Path, dest: Path, progress=lambda f: None) -> dict:
    """Builds a set's SQLite store from an uploaded file; returns {format, counts per algorithm, invalid lines}."""
    with source.open('rb') as f:
        magic = f.read(16)
    con = _create(dest)
    writer = _Writer(con)
    try:
        fmt = _import_nsrl(source, writer, progress) if magic.startswith(b'SQLite format 3') else _import_text(source, writer, progress)
        writer.flush()
        con.execute('VACUUM')
    finally:
        con.close()
    return {'format': fmt, 'counts': writer.counts, 'invalid': writer.invalid}


def lookup(store: Path, algo: str, digests: list[str]) -> set[str]:
    """The hex digests (lower case) of `digests` that are in the set, for one algorithm."""
    con = sqlite3.connect(f'file:{store}?mode=ro', uri=True)
    found = set()
    try:
        raw = [bytes.fromhex(d) for d in {d.lower() for d in digests if d}]
        for i in range(0, len(raw), LOOKUP_BATCH):
            chunk = raw[i:i + LOOKUP_BATCH]
            q = f'SELECT h FROM {algo} WHERE h IN ({",".join("?" * len(chunk))})'
            found.update(r[0].hex() for r in con.execute(q, chunk))
    finally:
        con.close()
    return found

