"""Windows user-activity artifacts read from copies extracted out of the evidence image.

  Prefetch (C:\\Windows\\Prefetch\\*.pf)        programs that ran: run count, last run times (up to 8 on
                                                Windows 8+), the files the program loaded, the volume
  LNK shortcuts in the Recent folder           files the user opened: target path, the drive it was on
                                                (type, serial number, label) and the target's own times
  Recycle Bin index files ($Recycle.Bin\\<SID>\\$I*)  files moved to the Recycle Bin: original path, size,
                                                deletion time; the matching $R file holds the content

Prefetch and LNK files are parsed with libyal's libscca and liblnk (Windows 10/11 compressed Prefetch
included); the $I format is small enough to read here. Times are Windows FILETIMEs (UTC). Missing or
unreadable values are reported as absent, never estimated.
"""
from __future__ import annotations
import struct
from datetime import datetime, timedelta, timezone

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
MAX_REFERENCED_FILES = 1000
KNOWN_PREFETCH_VERSIONS = {17, 23, 26, 30, 31}
DRIVE_TYPES = {0: 'Unknown', 1: 'No root directory', 2: 'Removable', 3: 'Fixed', 4: 'Network', 5: 'CD-ROM', 6: 'RAM disk'}


def filetime_iso(value) -> str | None:
    """Integer FILETIME -> ISO 8601 UTC string, or None for 0 / out-of-range values."""
    if not isinstance(value, int) or value <= 0:
        return None
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat()
    except OverflowError:
        return None


def volume_serial(value) -> str | None:
    return f'{value >> 16:04X}-{value & 0xFFFF:04X}' if isinstance(value, int) and value else None


def _failed(error) -> dict:
    return {'status': 'FAILED', 'error': str(error)[:300]}


def _get(obj, name):
    """Reads a pyscca/pylnk property; libyal raises IOError for values a file does not carry."""
    try:
        value = getattr(obj, name)
        return value() if callable(value) else value
    except (IOError, OSError, ValueError, TypeError):
        return None


# ---------------------------------------------------------------- Recycle Bin $I
def parse_recycle_index(data: bytes) -> dict:
    """Parses a $I record: version 1 (Vista/7, fixed 520-byte path) or version 2 (Windows 10+)."""
    if len(data) < 24:
        raise ValueError('too short for a Recycle Bin $I record')
    version, size, deleted = struct.unpack_from('<qqq', data)
    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2:
        if len(data) < 28:
            raise ValueError('version 2 record without a path length')
        chars = struct.unpack_from('<I', data, 24)[0]
        if not chars or 28 + chars * 2 > len(data):
            raise ValueError('path length outside the record')
        raw = data[28:28 + chars * 2]
    else:
        raise ValueError(f'unknown $I version {version}')
    path = raw.decode('utf-16-le', 'replace').split('\0', 1)[0]
    if not path:
        raise ValueError('empty original path')
    return {'format_version': version, 'original_path': path,
            'original_size': size if size >= 0 else None, 'deleted_time': filetime_iso(deleted)}


def parse_recycle_index_file(path) -> dict:
    try:
        with open(path, 'rb') as f:
            data = f.read(70_000)  # a v2 path is at most 32,767 UTF-16 characters
        return {'status': 'COMPLETED', **parse_recycle_index(data)}
    except (OSError, ValueError, struct.error) as e:
        return _failed(e)


# ---------------------------------------------------------------- LNK
def parse_lnk(path) -> dict:
    """Shell link: target, drive, and the target file's created/modified/accessed times from the header."""
    import pylnk
    f = pylnk.file()
    try:
        f.open(str(path))
    except (IOError, OSError) as e:
        return _failed(e)
    try:
        drive_type = _get(f, 'drive_type')
        local, network = _get(f, 'local_path'), _get(f, 'network_path')
        return {
            'status': 'COMPLETED',
            'target_path': local or network or _get(f, 'relative_path'),
            'local_path': local, 'network_path': network,
            'target_size': _get(f, 'file_size'),
            'target_created': filetime_iso(_get(f, 'get_file_creation_time_as_integer')),
            'target_modified': filetime_iso(_get(f, 'get_file_modification_time_as_integer')),
            'target_accessed': filetime_iso(_get(f, 'get_file_access_time_as_integer')),
            'file_attributes': _get(f, 'file_attribute_flags'),
            'drive_type': DRIVE_TYPES.get(drive_type) if drive_type is not None else None,
            'drive_serial': volume_serial(_get(f, 'drive_serial_number')),
            'volume_label': _get(f, 'volume_label') or None,
            'relative_path': _get(f, 'relative_path'),
            'working_directory': _get(f, 'working_directory'),
            'arguments': _get(f, 'command_line_arguments'),
            'description': _get(f, 'description'),
            'machine_id': _get(f, 'machine_identifier') or None,
        }
    finally:
        f.close()


# ---------------------------------------------------------------- Prefetch
def parse_prefetch(path) -> dict:
    """Prefetch file: executable, run count, last run times (newest first), volumes and loaded files."""
    import pyscca
    try:
        with open(path, 'rb') as fh:
            compressed = fh.read(4) == b'MAM\x04'
    except OSError as e:
        return _failed(e)
    f = pyscca.file()
    try:
        f.open(str(path))
    except (IOError, OSError) as e:
        return _failed(e)
    try:
        version = _get(f, 'format_version')
        slots = 8 if version and version >= 26 else 1
        runs = []
        for i in range(slots):
            try:
                t = filetime_iso(f.get_last_run_time_as_integer(i))
            except (IOError, OSError):
                t = None
            if t:
                runs.append(t)
        runs.sort(reverse=True)
        files = []
        try:
            files = [str(name) for name in f.filenames]
        except (IOError, OSError):
            pass
        exe = _get(f, 'executable_filename')
        exe_path = next((p for p in files if exe and p.upper().endswith('\\' + exe.upper())), None)
        volumes = []
        for i in range(_get(f, 'number_of_volumes') or 0):
            try:
                v = f.get_volume_information(i)
            except (IOError, OSError):
                continue
            volumes.append({'device_path': _get(v, 'device_path'), 'serial': volume_serial(_get(v, 'serial_number')),
                            'created': filetime_iso(_get(v, 'get_creation_time_as_integer'))})
        hash_value = _get(f, 'prefetch_hash')
        out = {
            'status': 'COMPLETED', 'format_version': version, 'compressed': compressed,
            'executable': exe, 'executable_path': exe_path,
            'prefetch_hash': f'{hash_value:08X}' if isinstance(hash_value, int) else None,
            'run_count': _get(f, 'run_count'), 'last_run_times': runs, 'last_run': runs[0] if runs else None,
            'volumes': volumes, 'referenced_files': files[:MAX_REFERENCED_FILES], 'referenced_files_total': len(files),
        }
        if version not in KNOWN_PREFETCH_VERSIONS:
            out['warning'] = f'Prefetch format version {version} has not been verified with DFIP'
        return out
    finally:
        f.close()
