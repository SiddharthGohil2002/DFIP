"""Reading part of a file for the hex viewer and the preview, without writing a copy of it.

Files inside an image are streamed through `icat` and only the requested byte range is kept; recovered,
carved and extracted files are read directly. The type shown in the preview is decided from the file's
first bytes (magic numbers), never from its name, and HTML or SVG is only ever shown as text.
"""
from __future__ import annotations
import subprocess
import threading
from pathlib import Path

PAGE_MAX = 64 * 1024              # bytes per hex page
STREAM_SKIP_MAX = 256 * 1024 * 1024  # how far into a file icat is read before a recovered copy is needed
TEXT_MAX = 256 * 1024             # text shown in the preview
RAW_MAX = 20 * 1024 * 1024        # images and PDFs rendered in the preview
_streams = threading.BoundedSemaphore(4)  # concurrent icat reads


class Busy(Exception):
    """Too many files are being read at once."""


def read_stream_range(cmd: list[str], start: int, length: int, timeout: float = 30) -> bytes:
    """Bytes [start, start+length) of a command's output; the command is stopped once they are read."""
    if not _streams.acquire(blocking=False):
        raise Busy()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        timed_out = threading.Event()

        def stop():
            timed_out.set()
            proc.kill()
        timer = threading.Timer(timeout, stop)
        timer.start()
        try:
            remaining = start
            while remaining > 0:
                chunk = proc.stdout.read(min(1 << 20, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            out = bytearray()
            while remaining <= 0 and len(out) < length:
                chunk = proc.stdout.read(length - len(out))
                if not chunk:
                    break
                out += chunk
            if timed_out.is_set():
                raise TimeoutError('reading the file took too long')
            return bytes(out)
        finally:
            timer.cancel()
            try:
                proc.kill()
            except OSError:
                pass
            proc.stdout.close()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                pass
    finally:
        _streams.release()


def read_file_range(path: Path, start: int, length: int) -> bytes:
    with open(path, 'rb') as f:
        f.seek(start)
        return f.read(length)


_MAGIC = [
    (b'\x89PNG\r\n\x1a\n', 'image', 'image/png'),
    (b'\xff\xd8\xff', 'image', 'image/jpeg'),
    (b'GIF87a', 'image', 'image/gif'),
    (b'GIF89a', 'image', 'image/gif'),
    (b'%PDF-', 'pdf', 'application/pdf'),
]


def sniff(head: bytes) -> tuple[str, str]:
    """(kind, MIME type) from the first bytes: image, pdf, text or binary."""
    for magic, kind, mime in _MAGIC:
        if head.startswith(magic):
            return kind, mime
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'image', 'image/webp'
    if head[:2] == b'BM' and len(head) >= 26 and int.from_bytes(head[14:18], 'little') in (12, 40, 52, 56, 108, 124):
        return 'image', 'image/bmp'
    if head[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return 'text', 'text/plain'
    sample = head[:8192]
    if not sample:
        return 'text', 'text/plain'
    if b'\0' in sample:
        return 'binary', 'application/octet-stream'
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return ('text', 'text/plain') if printable / len(sample) > 0.95 else ('binary', 'application/octet-stream')


def decode_text(data: bytes) -> tuple[str, str]:
    """Text and the encoding it was read as (BOM, then UTF-8, else Windows-1252)."""
    if data.startswith(b'\xef\xbb\xbf'):
        return data[3:].decode('utf-8', 'replace'), 'UTF-8 (BOM)'
    if data.startswith(b'\xff\xfe'):
        return data[2:].decode('utf-16-le', 'replace'), 'UTF-16 LE'
    if data.startswith(b'\xfe\xff'):
        return data[2:].decode('utf-16-be', 'replace'), 'UTF-16 BE'
    try:
        return data.decode('utf-8'), 'UTF-8'
    except UnicodeDecodeError as e:
        if e.start >= len(data) - 3:  # a character cut off at the end of the excerpt
            return data[:e.start].decode('utf-8', 'replace'), 'UTF-8'
        return data.decode('cp1252', 'replace'), 'Windows-1252'
