"""Unallocated space: the readable strings of every file system's free blocks, searchable with their location.

`blkls` streams the unallocated blocks of a file system and is read as it runs (the raw data is never written to
disk); `blkls -l` lists which blocks those are, so every string is mapped back to its byte offset in the volume
(a string that crosses from one run of free blocks to another is mapped piece by piece). Only the strings are
kept, in a second content index (storage/analysis/text/<EVID>.unalloc.sqlite) that content search and found data
read with the files' index. Data of deleted files whose clusters were not reused is found here even when the
file-system entry is gone.
"""
from __future__ import annotations
import bisect
import re
import shutil

from ..source import TskImageSource
from ..text_index import Writer, unallocated_index_path
from ..textextract import Extracted
from ..tools import TOOLS
from .base import Module

MIN_STRING = 6
DOC_CHARS = 1_000_000            # text per index document
MAX_TOTAL_CHARS = 1_000_000_000  # strings kept per evidence item
CARRY_MAX = 1 << 16              # bytes of a string held back at a chunk boundary
STREAM_TIMEOUT = 24 * 3600
_ASCII = re.compile(rb'[\x20-\x7e\t]{%d,}' % MIN_STRING)
_UTF16 = re.compile(rb'(?:[\x20-\x7e\t]\x00){%d,}' % MIN_STRING)
_TAIL = frozenset(range(0x20, 0x7f)) | {0x09, 0x00}


class Runs:
    """Unallocated blocks in stream order, as runs: (stream offset, volume offset, length) in bytes."""

    def __init__(self, block_size: int):
        self.bs = block_size
        self.stream, self.volume, self.length = [], [], []
        self._last = None
        self._pos = 0
        self._buf = b''

    def feed(self, data: bytes):
        lines = (self._buf + data).split(b'\n')
        self._buf = lines.pop()
        for line in lines:
            addr, _, flag = line.partition(b'|')
            if not addr.isdigit():
                continue  # header lines
            a = int(addr)
            if self._last is not None and a == self._last + 1:
                self.length[-1] += self.bs
            else:
                self.stream.append(self._pos)
                self.volume.append(a * self.bs)
                self.length.append(self.bs)
            self._last = a
            self._pos += self.bs

    def finish(self):
        if self._buf:
            self.feed(b'\n')

    @property
    def total(self) -> int:
        return self._pos

    def locate(self, s: int):
        """(volume offset of stream offset s, bytes left in its run), or None past the end."""
        k = bisect.bisect_right(self.stream, s) - 1
        if k < 0 or s >= self.stream[k] + self.length[k]:
            return None
        return self.volume[k] + (s - self.stream[k]), self.stream[k] + self.length[k] - s


class UnallocatedModule(Module):
    name = 'unallocated'
    label = 'Unallocated space'
    description = ("Readable strings in each file system's free space (where deleted files' data often remains), searchable "
                   'and scanned for found data, each with its byte offset in the volume.')
    requires = ('fs_index',)
    weight = 30
    collections = ()

    def run(self, ctx):
        filesystems = [f for f in (ctx.fact('fs_index', 'filesystems') or []) if f.get('fls_status') == 'COMPLETED']
        src = TskImageSource(ctx.image)
        final = unallocated_index_path(ctx.eid)
        self.writer = Writer(final.with_name(f'{final.stem}.{ctx.run_id}.tmp'))
        self.ctx, self.chars, self.scanned, self.docs = ctx, 0, 0, 0
        try:
            for i, fs in enumerate(filesystems):
                ctx.progress(i / max(1, len(filesystems)), fs['volume_id'])
                if self.chars >= MAX_TOTAL_CHARS:
                    break
                self._scan(src, fs)
            self.writer.finish(final)
        except BaseException:
            self.writer.abort()
            raise
        ctx.count('unallocated_bytes_scanned', self.scanned)
        ctx.count('unallocated_text_blocks', self.docs)
        ctx.set_fact('index', {'path': str(final), 'documents': self.docs, 'characters': self.chars, 'bytes_scanned': self.scanned})

    def _tool(self, name: str) -> str:
        return shutil.which(TOOLS.get(name, name)) or name

    def _scan(self, src, fs: dict):
        ctx, vid, offset = self.ctx, fs['volume_id'], int(fs.get('partition_offset') or 0)
        block_size = src._filesystem(vid).info.block_size
        runs = Runs(block_size)
        where = (['-o', str(offset)] if offset else []) + [str(ctx.image)]
        r = ctx.stream_tool([self._tool('sleuthkit_blkls'), '-l'] + where, runs.feed, timeout=STREAM_TIMEOUT)
        runs.finish()
        if r.get('status') != 'COMPLETED' or not runs.total:
            if r.get('status') != 'COMPLETED':
                ctx.warn(f'Unallocated blocks of {vid} could not be listed: {(r.get("stderr") or r.get("status"))[:200]}')
            return
        self.vid, self.runs, self.pos, self.carry = vid, runs, 0, b''
        self.text, self.spans = [], []
        self.text_len = 0
        r = ctx.stream_tool([self._tool('sleuthkit_blkls')] + where, self._feed, timeout=STREAM_TIMEOUT)
        self._feed(b'', final=True)
        self._flush()
        self.scanned += runs.total
        if r.get('status') != 'COMPLETED':
            ctx.warn(f'Reading the unallocated space of {vid} stopped: {(r.get("stderr") or r.get("status"))[:200]}')

    def _feed(self, chunk: bytes, final: bool = False):
        data = self.carry + chunk
        base = self.pos - len(self.carry)
        cut = len(data)
        if not final:  # hold back a printable tail that may continue in the next chunk
            lim = max(0, len(data) - CARRY_MAX)
            while cut > lim and data[cut - 1] in _TAIL:
                cut -= 1
        found = [(m.start(), m.group().decode('ascii'), 1) for m in _ASCII.finditer(data, 0, cut)]
        found += [(m.start(), m.group().decode('utf-16-le'), 2) for m in _UTF16.finditer(data, 0, cut)]
        found.sort()
        for start, s, width in found:
            self._add(base + start, s, width)
        self.carry = data[cut:]
        self.pos += len(chunk)
        if self.pos // (64 << 20) != (self.pos - len(chunk)) // (64 << 20):
            self.ctx.checkpoint()

    def _add(self, stream_off: int, s: str, width: int):
        if self.chars >= MAX_TOTAL_CHARS:
            return
        if self.text_len:
            self.text.append('\n')
            self.text_len += 1
        i = 0
        while i < len(s):
            loc = self.runs.locate(stream_off + i * width)
            if loc is None:
                break
            vol, left = loc
            n = min(len(s) - i, max(1, left // width))
            self.spans.append([self.text_len, vol, width])
            self.text.append(s[i:i + n])
            self.text_len += n
            i += n
        if self.text_len >= DOC_CHARS:
            self._flush()

    def _flush(self):
        if not self.text_len:
            return
        first = self.spans[0][1] if self.spans else 0
        entry = {'path': f'Unallocated space ({self.vid}) from byte {first:,}', 'inode': None, 'volume_id': self.vid,
                 'deleted': False, 'size': None}
        text = ''.join(self.text)
        self.writer.add(entry, Extracted(text, 'unallocated', spans=self.spans))
        self.chars += len(text)
        self.docs += 1
        if self.chars >= MAX_TOTAL_CHARS:
            self.ctx.warn(f'The unallocated-space index reached its limit of {MAX_TOTAL_CHARS:,} characters; the rest was not kept')
        self.text, self.spans, self.text_len = [], [], 0
