"""Writers for Windows artifact formats used to build DFIP's test data.

Each function returns the bytes of one file, laid out as documented in:
  - Recycle Bin $I index files: version 1 (Vista/7) and version 2 (Windows 10+)
  - Shell Link (.lnk), [MS-SHLLINK]
  - Prefetch (.pf) version 30, uncompressed SCCA (libyal "Windows Prefetch File (PF) format")

They are used by scripts/test-image/make_artifacts.py and the unit tests. The parsers DFIP uses
(pyscca, pylnk) and ExifTool read these files independently, which is what the tests rely on.
"""
from __future__ import annotations
import struct
from datetime import datetime

FILETIME_EPOCH_OFFSET = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01


def filetime(dt: datetime | None) -> int:
    """datetime (timezone-aware) -> Windows FILETIME (100 ns intervals since 1601)."""
    return 0 if dt is None else int(round((dt.timestamp() + FILETIME_EPOCH_OFFSET) * 10_000_000))


def utf16z(text: str) -> bytes:
    return text.encode('utf-16-le') + b'\0\0'


# ---------------------------------------------------------------- Recycle Bin
def recycle_bin_index(original_path: str, size: int, deleted: datetime, version: int = 2) -> bytes:
    """A $I file: version, original size, deletion FILETIME, then the original path."""
    head = struct.pack('<qqq', version, size, filetime(deleted))
    if version == 1:
        return head + utf16z(original_path).ljust(520, b'\0')[:520]
    if version == 2:
        path = utf16z(original_path)
        return head + struct.pack('<I', len(path) // 2) + path
    raise ValueError('version must be 1 or 2')


# ---------------------------------------------------------------- Shell Link
LINK_CLSID = bytes.fromhex('0114020000000000c000000000000046')
HAS_LINK_INFO, HAS_WORKING_DIR, HAS_ARGUMENTS, IS_UNICODE = 0x02, 0x10, 0x20, 0x80
DRIVE_REMOVABLE, DRIVE_FIXED = 2, 3


def shell_link(target_path: str, *, size: int, created: datetime, modified: datetime, accessed: datetime,
               drive_type: int = DRIVE_FIXED, drive_serial: int = 0, volume_label: str = '',
               working_dir: str | None = None, arguments: str | None = None, attributes: int = 0x20,
               machine_id: str = '') -> bytes:
    """A .lnk file pointing at a local path: header, LinkInfo (VolumeID + LocalBasePath), StringData,
    a TrackerDataBlock (machine ID) and the terminal block. The header times are the target's times."""
    flags = HAS_LINK_INFO | IS_UNICODE
    strings = b''
    if working_dir is not None:
        flags |= HAS_WORKING_DIR
        strings += struct.pack('<H', len(working_dir)) + working_dir.encode('utf-16-le')
    if arguments is not None:
        flags |= HAS_ARGUMENTS
        strings += struct.pack('<H', len(arguments)) + arguments.encode('utf-16-le')
    header = struct.pack('<I16sIIQQQIiIHHII', 0x4C, LINK_CLSID, flags, attributes,
                         filetime(created), filetime(accessed), filetime(modified), size, 0, 1, 0, 0, 0, 0)
    assert len(header) == 0x4C

    label = volume_label.encode('ascii') + b'\0'
    volume_id = struct.pack('<IIII', 16 + len(label), drive_type, drive_serial, 0x10) + label
    base_path = target_path.encode('ascii') + b'\0'
    suffix = b'\0'
    info_header = 0x1C
    vol_off = info_header
    base_off = vol_off + len(volume_id)
    suffix_off = base_off + len(base_path)
    link_info_size = suffix_off + len(suffix)
    link_info = struct.pack('<IIIIIII', link_info_size, info_header, 0x1, vol_off, base_off, 0, suffix_off) \
        + volume_id + base_path + suffix

    machine = machine_id.encode('ascii')[:15].ljust(16, b'\0')
    tracker = struct.pack('<III', 0x60, 0xA0000003, 0x58) + struct.pack('<I', 0) + machine + b'\0' * 64
    assert len(tracker) == 0x60
    return header + link_info + strings + tracker + struct.pack('<I', 0)


# ---------------------------------------------------------------- Prefetch
def prefetch_hash(device_path: str) -> int:
    """The Vista-style SCCA path hash (used for the file name suffix)."""
    h = 314159
    for b in device_path.upper().encode('utf-16-le'):
        h = (h * 37 + b) & 0xFFFFFFFF
    return h


def prefetch_v30(executable: str, *, run_times: list[datetime], run_count: int, files: list[str],
                 volume_path: str, volume_serial: int, volume_created: datetime) -> bytes:
    """An uncompressed SCCA version 30 file (layout variant with the metrics array at 0x130).

    run_times: newest first, at most 8. files: full device paths of the files the program loaded."""
    if len(run_times) > 8:
        raise ValueError('at most 8 run times')
    exe_path = next((f for f in files if f.upper().endswith('\\' + executable.upper())), files[0])

    header_size, info_size = 84, 220
    metrics_off = header_size + info_size  # 0x130 selects the v26-style file information layout

    names = b''
    metrics = b''
    for i, f in enumerate(files):
        offset = len(names)
        names += utf16z(f)
        metrics += struct.pack('<IIIIIIQ', i * 10, 5, 5, offset, len(f), 0x200, 0)  # 32-byte metrics entry
    names_off = metrics_off + len(metrics)

    vol_entry_size = 96
    device = utf16z(volume_path)
    volume = struct.pack('<IIQIIIIII', vol_entry_size, len(volume_path), filetime(volume_created), volume_serial,
                         0, 0, 0, 0, 0) + b'\0' * (24 + 4 + 24 + 4)
    assert len(volume) == vol_entry_size
    volumes = volume + device + b'\0' * 8  # padding keeps the path strictly inside the section
    volumes_off = names_off + len(names)
    volumes_off += (-volumes_off) % 8
    total = volumes_off + len(volumes)

    run_area = b''.join(struct.pack('<Q', filetime(t)) for t in run_times).ljust(64, b'\0')
    info = struct.pack('<IIIIIIIII', metrics_off, len(files), 0, 0, names_off, len(names),
                       volumes_off, 1, len(volumes)) + b'\0' * 8 + run_area + b'\0' * 16 \
        + struct.pack('<III', run_count, 0, 0) + b'\0' * 84
    assert len(info) == info_size

    name = executable.upper()[:29].encode('utf-16-le').ljust(60, b'\0')
    head = struct.pack('<I4sII', 30, b'SCCA', 0x11, total) + name + struct.pack('<II', prefetch_hash(exe_path), 0)
    assert len(head) == header_size

    body = head + info + metrics + names
    body += b'\0' * (volumes_off - len(body))
    return body + volumes
