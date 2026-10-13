"""Pictures attached to findings (screenshots of what a finding rests on): PNG or JPEG by content, kept read-only under
their SHA-256 in storage/findings/<finding>/, listed on the finding and, when a report template asks, shown in reports."""
from __future__ import annotations
from pathlib import Path

from ..core.config import settings

MAX_BYTES = 10 << 20
TYPES = ((b'\x89PNG\r\n\x1a\n', 'image/png', 'png'), (b'\xff\xd8\xff', 'image/jpeg', 'jpg'))


def root() -> Path:
    return Path(settings.storage_path).resolve() / 'findings'


def sniff(data: bytes) -> tuple[str, str] | None:
    return next(((mime, ext) for magic, mime, ext in TYPES if data.startswith(magic)), None)


def attachment_path(finding_id: str, attachment: dict) -> Path:
    return root() / finding_id / attachment['file']
