"""E01 working copies: exact media bytes, verified against the E01's stored MD5, corrupt images refused.

Needs libewf's command-line tools (present in the backend image); skipped elsewhere."""
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app.core.config import settings
from app.forensic import working_image

pytestmark = pytest.mark.skipif(not all(shutil.which(t) for t in ('ewfacquirestream', 'ewfverify', 'ewfexport', 'ewfinfo')),
                                reason='libewf tools not installed')


@pytest.fixture
def media():
    # 3 MiB of non-repeating data whose length is not a multiple of the EWF chunk size.
    return os.urandom(3 * 1024 * 1024 + 4096)


def make_e01(tmp_path: Path, data: bytes) -> Path:
    raw = tmp_path / 'media.raw'
    raw.write_bytes(data)
    with raw.open('rb') as src:
        subprocess.run(['ewfacquirestream', '-q', '-t', str(tmp_path / 'image'), '-C', 'case', '-D', 'test', '-E', '1',
                        '-e', 'tester', '-N', 'none', '-f', 'encase6'], stdin=src, check=True, capture_output=True)
    return tmp_path / 'image.E01'


def evidence(path: Path):
    return {'evidence_id': 'EVID-T01', 'case_id': 'CASE-T', 'format': 'E01', 'storage_path': str(path)}


def test_working_copy_is_the_exact_media(tmp_path, monkeypatch, media):
    monkeypatch.setattr(settings, 'storage_path', str(tmp_path / 'storage'))
    e01 = make_e01(tmp_path, media)
    copy = working_image.analysis_image(evidence(e01), create=True)
    # ewfexport prints a status line on stdout after the data; it must not end up in the copy.
    assert copy.stat().st_size == len(media)
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == hashlib.sha256(media).hexdigest()
    assert working_image.analysis_image(evidence(e01)) == copy  # reused, not exported again


def test_missing_copy_is_not_created_on_demand(tmp_path, monkeypatch, media):
    monkeypatch.setattr(settings, 'storage_path', str(tmp_path / 'storage'))
    with pytest.raises(working_image.WorkingCopyUnavailable):
        working_image.analysis_image(evidence(make_e01(tmp_path, media)))


def test_corrupt_e01_is_refused(tmp_path, monkeypatch, media):
    monkeypatch.setattr(settings, 'storage_path', str(tmp_path / 'storage'))
    e01 = make_e01(tmp_path, media)
    data = bytearray(e01.read_bytes())
    data[len(data) // 2] ^= 0xFF
    e01.write_bytes(bytes(data))
    with pytest.raises(ValueError, match='E01'):
        working_image.analysis_image(evidence(e01), create=True)
    assert not working_image.working_copy_path(evidence(e01)).exists()


def test_raw_images_are_read_directly(tmp_path):
    raw = tmp_path / 'disk.dd'
    raw.write_bytes(b'\0' * 512)
    assert working_image.analysis_image({'evidence_id': 'E', 'case_id': 'C', 'format': 'DD', 'storage_path': str(raw)}) == raw
