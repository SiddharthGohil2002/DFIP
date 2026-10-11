"""Unallocated space: streaming a tool's output, mapping the blkls stream back to volume offsets, and strings."""
import time

import pytest

from app.forensic.modules.base import Cancelled, stream_tool
from app.forensic.modules.unallocated import Runs, UnallocatedModule
from app.forensic.text_index import DocMap


def test_stream_tool_hands_over_all_output():
    got = []
    r = stream_tool(['sh', '-c', 'seq 1 200000'], got.append, timeout=20, chunk=4096)
    data = b''.join(got)
    assert r['status'] == 'COMPLETED' and len(got) > 1 and data.splitlines()[-1] == b'200000'


def test_stream_tool_timeout_and_cancel():
    t0 = time.monotonic()
    assert stream_tool(['sh', '-c', 'sleep 30'], lambda d: None, timeout=1)['status'] == 'TIMEOUT'
    assert time.monotonic() - t0 < 10
    with pytest.raises(Cancelled):
        stream_tool(['sh', '-c', 'yes'], lambda d: None, timeout=30, should_stop=lambda: True)


def _runs(lines: str, bs=512) -> Runs:
    r = Runs(bs)
    data = ('class|host|image|first_time|unit\nblkls|x||1|Sector\naddr|alloc\n' + lines).encode()
    for i in range(0, len(data), 7):  # in small pieces: lines are split across chunks
        r.feed(data[i:i + 7])
    r.finish()
    return r


def test_runs_map_the_stream_back_to_the_volume():
    r = _runs('10|f\n11|f\n12|f\n40|f\n41|f')
    assert (r.stream, r.volume, r.length, r.total) == ([0, 1536], [5120, 20480], [1536, 1024], 2560)
    assert r.locate(0) == (5120, 1536) and r.locate(1535) == (6655, 1) and r.locate(1536) == (20480, 1024)
    assert r.locate(2560) is None


class _Writer:
    def __init__(self):
        self.docs = []

    def add(self, entry, ex):
        self.docs.append((entry, ex))


class _Ctx:
    def warn(self, m):
        pass

    def checkpoint(self):
        pass


def _scanner(runs: Runs) -> UnallocatedModule:
    m = UnallocatedModule()
    m.ctx, m.writer, m.chars, m.docs = _Ctx(), _Writer(), 0, 0
    m.vid, m.runs, m.pos, m.carry, m.text, m.spans, m.text_len = 'p2048', runs, 0, b'', [], [], 0
    return m


def test_strings_are_found_across_chunks_and_mapped_across_runs():
    # Two runs of free blocks: stream bytes 0-1023 are volume bytes 51200-52223, stream 1024-2047 are 102400-103423.
    runs = _runs('100|f\n101|f\n200|f\n201|f')
    stream = bytearray(b'\x00' * 2048)
    stream[100:119] = b'DE89370400440532013'                            # inside the first run
    word = 'payroll-export.csv'.encode('utf-16-le')
    stream[1010:1010 + len(word)] = word                                 # crosses from the first run into the second
    m = _scanner(runs)
    for i in range(0, len(stream), 300):                                 # chunks that split both strings
        m._feed(bytes(stream[i:i + 300]))
    m._feed(b'', final=True)
    m._flush()
    (entry, ex), = m.writer.docs
    assert entry['volume_id'] == 'p2048' and ex.method == 'unallocated'
    assert ex.text.split('\n') == ['DE89370400440532013', 'payroll-export.csv']
    where = DocMap({'method': 'unallocated', 'encoding': None, 'bom': 0, 'spans': ex.spans})
    assert where.offset(ex.text, 0) == 51200 + 100
    i = ex.text.index('payroll')
    assert where.offset(ex.text, i) == 51200 + 1010                      # first run
    assert ex.spans[-1][1] == 102400                                     # the run boundary is reached 7 characters in
    j = ex.text.index('export')                                          # 8 characters (16 bytes) into the string
    assert where.offset(ex.text, j) == 102400 + (1010 + 16 - 1024)       # second run
