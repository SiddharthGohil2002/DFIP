"""Encrypted volumes, recognised from their headers with libyal's libbde (BitLocker, including BitLocker To Go) and
libluksde (Linux LUKS).

A BitLocker To Go drive also carries a small unencrypted FAT "discovery volume", so a readable file system does
not mean the volume is not encrypted: every volume is checked.
"""
from __future__ import annotations
import tempfile
from pathlib import Path

SECTOR = 512
PROBE_BYTES = 1 << 20


def volume_encryption(image: Path, start_sector: int) -> str | None:
    """'BitLocker' or 'LUKS' when the volume starting at `start_sector` is encrypted, else None."""
    with Path(image).open('rb') as f:
        f.seek(start_sector * SECTOR)
        head = f.read(PROBE_BYTES)
    if len(head) < SECTOR:
        return None
    if head[:6] == b'LUKS\xba\xbe':
        return 'LUKS'
    with tempfile.NamedTemporaryFile(suffix='.vol') as t:
        t.write(head)
        t.flush()
        try:
            import pybde
            if pybde.check_volume_signature(t.name):
                return 'BitLocker'
        except Exception:
            pass
        try:
            import pyluksde
            if pyluksde.check_volume_signature(t.name):
                return 'LUKS'
        except Exception:
            pass
    return None
