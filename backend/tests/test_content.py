"""File viewer: reading a byte range from a stream, and deciding the type from content."""
import sys
import time

import pytest

from app.forensic.content import decode_text, read_file_range, read_stream_range, sniff

PATTERN = bytes(range(256)) * 4096  # 1 MiB, every offset predictable
GEN = [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(bytes(range(256)) * 4096)']


@pytest.mark.parametrize('start,length', [(0, 16), (100, 50), (65_536, 4096), (1_048_570, 100), (0, 0)])
def test_stream_range_slices(start, length):
    assert read_stream_range(GEN, start, length) == PATTERN[start:start + length]


def test_stream_range_past_the_end_is_empty():
    assert read_stream_range(GEN, 2_000_000, 100) == b''


def test_stream_stops_once_the_range_is_read():
    endless = [sys.executable, '-c', 'import sys\nwhile True: sys.stdout.buffer.write(b"x" * 65536)']
    t0 = time.time()
    assert read_stream_range(endless, 10, 5) == b'xxxxx'
    assert time.time() - t0 < 10


def test_stream_timeout():
    slow = [sys.executable, '-c', 'import time; time.sleep(30)']
    with pytest.raises(TimeoutError):
        read_stream_range(slow, 0, 10, timeout=0.5)


def test_file_range(tmp_path):
    p = tmp_path / 'f.bin'
    p.write_bytes(PATTERN[:10_000])
    assert read_file_range(p, 9_990, 100) == PATTERN[9_990:10_000]


@pytest.mark.parametrize('head,kind,mime', [
    (b'\x89PNG\r\n\x1a\n' + b'\0' * 20, 'image', 'image/png'),
    (b'\xff\xd8\xff\xe0\0\x10JFIF', 'image', 'image/jpeg'),
    (b'GIF89a\x01\x00', 'image', 'image/gif'),
    (b'RIFF\x24\0\0\0WEBPVP8 ', 'image', 'image/webp'),
    (b'%PDF-1.4\n', 'pdf', 'application/pdf'),
    (b'employee,iban,salary\nemp000,DE89\n', 'text', 'text/plain'),
    (b'<html><script>alert(1)</script></html>', 'text', 'text/plain'),          # never rendered as HTML
    (b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>', 'text', 'text/plain'),
    ('﻿hi'.encode('utf-16-le'), 'text', 'text/plain'),
    (b'MZ\x90\x00\x03\x00\x00\x00', 'binary', 'application/octet-stream'),
    (b'SCCA\x1e\0\0\0', 'binary', 'application/octet-stream'),
])
def test_sniff(head, kind, mime):
    assert sniff(head) == (kind, mime)


def test_decode_text():
    assert decode_text('café'.encode()) == ('café', 'UTF-8')
    assert decode_text(b'\xef\xbb\xbfhi') == ('hi', 'UTF-8 (BOM)')
    assert decode_text('hi'.encode('utf-16-le').join([b'\xff\xfe', b''])) == ('hi', 'UTF-16 LE')
    assert decode_text(b'caf\xe9 au lait') == ('café au lait', 'Windows-1252')
    assert decode_text('ab€'.encode()[:-1]) == ('ab', 'UTF-8')  # a character cut at the end of the excerpt
