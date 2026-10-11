"""The content index: one SQLite FTS5 file per evidence item (storage/analysis/text/<EVID>.sqlite).

The `trigram` tokenizer gives case-insensitive substring search of at least three characters, so "payroll"
finds "PayrollExport" and "DE89370400440532013" finds every IBAN that starts with it. A new index is built in a
temporary file and renamed over the old one, so searches keep working while an analysis runs.

Every match is confirmed in Python and traced back to the file: for decoded text files and strings the exact
byte offset in the file is known (the hex viewer opens there); for text taken out of PDF and Office documents it
is not (the text is not stored in the file as such).

Regular expressions use RE2 (linear time, no backtracking blow-up). When a pattern has a literal of at least
three characters that every match must contain, the index finds the candidate files first; otherwise every file
is scanned. Every search stops at a time limit and says so.
"""
from __future__ import annotations
import bisect
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from ..core.config import settings
from .textextract import Extracted

SNIPPET = 60              # characters of context on each side of a match
MAX_MATCHES_PER_FILE = 20
MAX_CANDIDATES = 20_000
SEARCH_SECONDS = 15.0


def index_dir() -> Path:
    p = Path(settings.storage_path).resolve() / 'analysis' / 'text'
    p.mkdir(parents=True, exist_ok=True)
    return p


def index_path(evidence_id: str) -> Path:
    return index_dir() / f'{evidence_id}.sqlite'


def unallocated_index_path(evidence_id: str) -> Path:
    return index_dir() / f'{evidence_id}.unalloc.sqlite'


class Writer:
    def __init__(self, path: Path):
        self.path = path
        path.unlink(missing_ok=True)
        self.con = sqlite3.connect(str(path))
        self.con.executescript("""
            PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
            CREATE TABLE docs (id INTEGER PRIMARY KEY, path TEXT, inode TEXT, volume_id TEXT, deleted INTEGER,
                               size INTEGER, method TEXT, encoding TEXT, bom INTEGER, spans TEXT, chars INTEGER,
                               truncated INTEGER, member INTEGER);
            CREATE VIRTUAL TABLE body USING fts5(text, tokenize='trigram');
        """)
        self.n = 0

    def add(self, entry: dict, ex: Extracted) -> int:
        self.n += 1
        self.con.execute('INSERT INTO docs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', (
            self.n, entry.get('path'), entry.get('inode'), entry.get('volume_id'), int(bool(entry.get('deleted'))),
            entry.get('size'), ex.method, ex.encoding, ex.bom, json.dumps(ex.spans) if ex.spans else None,
            len(ex.text), int(ex.truncated), int(bool(entry.get('container')))))
        self.con.execute('INSERT INTO body (rowid, text) VALUES (?, ?)', (self.n, ex.text))
        if self.n % 200 == 0:
            self.con.commit()
        return self.n

    def finish(self, final: Path):
        self.con.execute("INSERT INTO body (body) VALUES ('optimize')")
        self.con.commit()
        self.con.close()
        os.replace(self.path, final)

    def abort(self):
        try:
            self.con.close()
        finally:
            self.path.unlink(missing_ok=True)


def open_index(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    return con


# ------------------------------------------------------------------ offsets
class DocMap:
    """Maps character positions in a document's text back to bytes of the file."""

    def __init__(self, doc):
        self.method, self.encoding, self.bom = doc['method'], doc['encoding'], int(doc['bom'] or 0)
        spans = doc['spans']
        self.spans = (json.loads(spans) if isinstance(spans, str) else spans) or []
        self.starts = [x[0] for x in self.spans]

    def _span(self, i: int):
        k = bisect.bisect_right(self.starts, i) - 1
        return self.spans[k] if k >= 0 else None

    def offset(self, text: str, i: int) -> int | None:
        """Where character i starts in the file, or None when the text is not stored in the file as such."""
        if self.method == 'text':
            return self.bom + len(text[:i].encode(self.encoding, errors='replace'))
        if self.method in ('strings', 'unallocated'):  # unallocated: offsets in the volume, not a file
            span = self._span(i)
            return span[1] + (i - span[0]) * span[2] if span else None
        return None

    def length(self, i: int, matched: str) -> int | None:
        if self.method == 'text':
            return len(matched.encode(self.encoding, errors='replace'))
        if self.method in ('strings', 'unallocated') and '\n' not in matched:  # a match across two strings has no single length
            span = self._span(i)
            return len(matched) * span[2] if span else None
        return None


# ------------------------------------------------------------------ query helpers
class QueryError(ValueError):
    pass


def phrase(term: str) -> str:
    """An FTS5 phrase query for a literal substring."""
    return '"' + term.replace('"', '""') + '"'


_SPECIAL_ESCAPES = set('dDwWsSbBAzZpPQECx0123456789')


def required_literal(pattern: str) -> str | None:
    """The longest literal (3+ characters) that every match of the regular expression must contain, if one is
    easy to prove; None otherwise (then every file is scanned)."""
    if '|' in pattern:
        return None
    runs, cur, i, n = [], [], 0, len(pattern)

    def end_run():
        if cur:
            runs.append(''.join(cur))
            cur.clear()

    while i < n:
        c = pattern[i]
        if c == '\\' and i + 1 < n:
            nxt = pattern[i + 1]
            i += 2
            if nxt in _SPECIAL_ESCAPES or nxt.isalpha():
                end_run()
                continue
            lit = nxt
        elif c == '(':
            end_run()
            depth = 0
            while i < n:  # skip the whole group: its content may be optional or repeated
                if pattern[i] == '\\':
                    i += 2
                    continue
                if pattern[i] == '(':
                    depth += 1
                elif pattern[i] == ')':
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            if i < n and pattern[i] in '?*+{':
                i = _skip_quantifier(pattern, i)
            continue
        elif c == '[':
            end_run()
            i += 1
            if i < n and pattern[i] == '^':
                i += 1
            if i < n and pattern[i] == ']':
                i += 1
            while i < n and pattern[i] != ']':
                i += 2 if pattern[i] == '\\' else 1
            i += 1
            if i < n and pattern[i] in '?*+{':
                i = _skip_quantifier(pattern, i)
            continue
        elif c in '.^$':
            end_run()
            i += 1
            if i < n and pattern[i] in '?*+{':
                i = _skip_quantifier(pattern, i)
            continue
        elif c in '?*+{':
            i = _skip_quantifier(pattern, i)
            continue
        else:
            lit = c
            i += 1
        # The literal character is optional or repeated when a quantifier follows it.
        if i < n and pattern[i] in '?*{':
            end_run()
            i = _skip_quantifier(pattern, i)
            continue
        cur.append(lit)
        if i < n and pattern[i] == '+':
            end_run()
            i = _skip_quantifier(pattern, i)
    end_run()
    best = max(runs, key=len, default='')
    return best if len(best) >= 3 else None


def _skip_quantifier(pattern: str, i: int) -> int:
    if pattern[i] == '{':
        j = pattern.find('}', i)
        i = j + 1 if j > 0 else i + 1
    else:
        i += 1
    if i < len(pattern) and pattern[i] in '?+':  # lazy or possessive suffix
        i += 1
    return i


def compile_regex(pattern: str):
    import re2
    if not pattern or len(pattern) > 1000:
        raise QueryError('Give a regular expression of 1 to 1,000 characters')
    try:
        opts = re2.Options()
        opts.max_mem = 64 << 20
        return re2.compile(pattern, opts)
    except Exception as exc:  # re2.error, or an unsupported construct such as a backreference
        raise QueryError(f'Not a valid RE2 regular expression: {exc}')


# ------------------------------------------------------------------ search
def _snip(text: str, s: int, e: int) -> dict:
    before = text[max(0, s - SNIPPET):s]
    after = text[e:e + SNIPPET]
    clean = lambda x: re.sub(r'\s+', ' ', x)
    return {'before': ('…' if s > SNIPPET else '') + clean(before), 'match': clean(text[s:e]),
            'after': clean(after) + ('…' if e + SNIPPET < len(text) else '')}


def search(path: Path, query: str, mode: str, deadline: float, max_files: int = 1000):
    """Files in one index that match, each with its first matches: (hits, complete). `mode` is text or regex."""
    con = open_index(path)
    hits, complete = [], True
    try:
        if mode == 'text':
            rx = re.compile(re.escape(query), re.IGNORECASE)
            finder = rx.finditer
            rows = con.execute('SELECT rowid FROM body WHERE body MATCH ? LIMIT ?', (phrase(query), MAX_CANDIDATES)).fetchall()
            candidates = [r[0] for r in rows]
        else:
            rx = compile_regex(query)
            finder = rx.finditer
            lit = required_literal(query)
            if lit:
                rows = con.execute('SELECT rowid FROM body WHERE body MATCH ? LIMIT ?', (phrase(lit), MAX_CANDIDATES)).fetchall()
                candidates = [r[0] for r in rows]
            else:
                candidates = [r[0] for r in con.execute('SELECT id FROM docs ORDER BY id')]
        if len(candidates) >= MAX_CANDIDATES:
            complete = False
        for rowid in candidates:
            if time.monotonic() > deadline or len(hits) >= max_files:
                complete = False
                break
            doc = con.execute('SELECT * FROM docs WHERE id = ?', (rowid,)).fetchone()
            text = con.execute('SELECT text FROM body WHERE rowid = ?', (rowid,)).fetchone()[0]
            where = DocMap(doc)
            matches, count = [], 0
            for m in finder(text):
                s, e = m.start(), m.end()
                if e == s:
                    continue
                count += 1
                if len(matches) < MAX_MATCHES_PER_FILE:
                    matched = text[s:e]
                    matches.append({'text_offset': s, 'byte_offset': where.offset(text, s),
                                    'byte_length': where.length(s, matched), **_snip(text, s, e)})
                if count >= 10_000:
                    break
            if count:
                hits.append({'path': doc['path'], 'inode': doc['inode'], 'volume_id': doc['volume_id'],
                             'deleted': bool(doc['deleted']), 'size': doc['size'], 'method': doc['method'],
                             'member': bool(doc['member']) if 'member' in doc.keys() else False,
                             'encoding': doc['encoding'], 'truncated': bool(doc['truncated']), 'match_count': count,
                             'matches': matches})
    finally:
        con.close()
    return hits, complete


def iter_documents(path: Path):
    """(doc row, text) for every document in an index."""
    con = open_index(path)
    try:
        for doc in con.execute('SELECT * FROM docs ORDER BY id').fetchall():
            row = con.execute('SELECT text FROM body WHERE rowid = ?', (doc['id'],)).fetchone()
            yield doc, (row[0] if row else '')
    finally:
        con.close()
