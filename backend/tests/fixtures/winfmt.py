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


# ---------------------------------------------------------------- OLE compound files ([MS-CFB] version 3)
ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def compound_file(streams: dict[str, bytes]) -> bytes:
    """A compound file (512-byte sectors) holding `streams` ({'Storage/Stream': bytes}); streams under 4096 bytes
    go to the mini stream, as the format requires. Siblings are chained as a right-leaning tree in [MS-CFB] name
    order (a valid binary search tree; colouring every node black is accepted by readers)."""
    ss, mss, cutoff = 512, 64, 4096
    nodes = [{'name': 'Root Entry', 'type': 5, 'children': [], 'data': b''}]
    index = {'': 0}
    for path, data in streams.items():
        parent, prefix = 0, ''
        parts = path.split('/')
        for i, part in enumerate(parts):
            prefix = f'{prefix}/{part}' if prefix else part
            if prefix not in index:
                stream = i == len(parts) - 1
                nodes.append({'name': part, 'type': 2 if stream else 1, 'children': [], 'data': data if stream else b''})
                index[prefix] = len(nodes) - 1
                nodes[parent]['children'].append(index[prefix])
            parent = index[prefix]
    sectors, fat = [], []

    def chain(data: bytes) -> int:
        if not data:
            return ENDOFCHAIN
        n, start = -(-len(data) // ss), len(sectors)
        for i in range(n):
            sectors.append(data[i * ss:(i + 1) * ss].ljust(ss, b'\0'))
            fat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        return start

    mini, minifat = b'', []
    for nd in nodes[1:]:
        d = nd['data']
        nd['size'] = len(d)
        if nd['type'] != 2:
            nd['start'] = 0
        elif len(d) >= cutoff:
            nd['start'] = chain(d)
        elif d:
            n, start = -(-len(d) // mss), len(minifat)
            mini += d.ljust(n * mss, b'\0')
            minifat += [start + i + 1 if i < n - 1 else ENDOFCHAIN for i in range(n)]
            nd['start'] = start
        else:
            nd['start'] = ENDOFCHAIN
    nodes[0]['start'], nodes[0]['size'] = chain(mini), len(mini)
    minifat_bytes = b''.join(struct.pack('<I', x) for x in minifat)
    minifat_bytes += b'\xff' * (-len(minifat_bytes) % ss)
    first_minifat = chain(minifat_bytes) if minifat else ENDOFCHAIN
    n_minifat = len(minifat_bytes) // ss
    for nd in nodes:
        kids = sorted(nd['children'], key=lambda k: (len(nodes[k]['name']), nodes[k]['name'].upper()))
        nd['child'] = kids[0] if kids else NOSTREAM
        for a, b in zip(kids, kids[1:]):
            nodes[a]['right'] = b

    def entry(nd) -> bytes:
        name = nd['name'].encode('utf-16-le') + b'\0\0'
        return struct.pack('<64sHBBIII16sIQQIQ', name, len(name), nd['type'], 1, NOSTREAM, nd.get('right', NOSTREAM),
                           nd['child'], b'\0' * 16, 0, 0, 0, nd['start'], nd['size'])

    empty = struct.pack('<64sHBBIII16sIQQIQ', b'', 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM, b'\0' * 16, 0, 0, 0, 0, 0)
    directory = b''.join(entry(nd) for nd in nodes)
    directory += empty * (-len(nodes) % 4)
    first_dir = chain(directory)
    n_fat = 1
    while n_fat * 128 < len(sectors) + n_fat:
        n_fat += 1
    fat_start = len(sectors)
    fat += [FATSECT] * n_fat
    fat += [FREESECT] * (n_fat * 128 - len(fat))
    fat_bytes = b''.join(struct.pack('<I', x) for x in fat)
    sectors += [fat_bytes[i * ss:(i + 1) * ss] for i in range(n_fat)]
    if n_fat > 109:
        raise ValueError('compound_file supports files up to about 7 MB')
    header = struct.pack('<8s16sHHHHH6sIIIIIIIII', b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', b'\0' * 16, 0x3E, 3, 0xFFFE, 9, 6,
                         b'\0' * 6, 0, n_fat, first_dir, 0, cutoff, first_minifat, n_minifat, ENDOFCHAIN, 0)
    header += struct.pack('<109I', *([fat_start + i for i in range(n_fat)] + [FREESECT] * (109 - n_fat)))
    return header + b''.join(sectors)


def ole10native(filename: str, data: bytes) -> bytes:
    """The '\x01Ole10Native' stream of an embedded package (an 'Insert > Object > Create from file' attachment)."""
    src = f'C:\\Users\\alice\\Documents\\{filename}'.encode('latin-1') + b'\0'
    tmp = f'C:\\Users\\alice\\AppData\\Local\\Temp\\{filename}'.encode('latin-1') + b'\0'
    body = (struct.pack('<H', 2) + filename.encode('latin-1') + b'\0' + src + struct.pack('<II', 0x00030000, len(tmp)) + tmp
            + struct.pack('<I', len(data)) + data)
    return struct.pack('<I', len(body)) + body


# ---------------------------------------------------------------- shell items ([MS-SHLLINK] IDList items, libfwsi notes)
def fat_datetime(dt: datetime) -> bytes:
    """FAT date then FAT time (2 seconds resolution), as shell items store them."""
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return struct.pack('<HH', date, time)


def _item(body: bytes) -> bytes:
    return struct.pack('<H', len(body) + 2) + body


def shell_item_root(guid: str = '20D04FE0-3AEA-1069-A2D8-08002B30309D', sort_index: int = 0x50) -> bytes:
    """A root folder item (class 0x1F) for a shell folder; the default is My Computer ("This PC")."""
    import uuid
    return _item(struct.pack('<BB', 0x1F, sort_index) + uuid.UUID(guid).bytes_le)


def shell_item_volume(path: str = 'E:\\') -> bytes:
    """A volume item (class 0x2F) naming a drive, for example E:\\."""
    return _item(struct.pack('<B', 0x2F) + path.encode('ascii').ljust(22, b'\0'))


def shell_item_directory(name: str, short_name: str, modified: datetime, created: datetime, accessed: datetime,
                         mft_entry: int = 0, mft_sequence: int = 0) -> bytes:
    """A directory file-entry item (class 0x31) with its 0xBEEF0004 extension block (version 9, Windows 8 and later):
    the 8.3 name and modification time, then the creation and access times, NTFS reference and long name."""
    primary = short_name.encode('ascii') + b'\0'
    primary += b'\0' * (len(primary) % 2)
    head = struct.pack('<BBI', 0x31, 0, 0) + fat_datetime(modified) + struct.pack('<H', 0x10) + primary
    ext = (struct.pack('<HI', 9, 0xBEEF0004) + fat_datetime(created) + fat_datetime(accessed) + struct.pack('<H', 0x2E)
           + struct.pack('<HQQ', 0, mft_entry | (mft_sequence << 48), 0) + struct.pack('<HII', 0, 0, 0)
           + name.encode('utf-16-le') + b'\0\0')
    first_ext = 2 + len(head)  # where this extension block starts within the item
    ext_block = struct.pack('<H', 2 + len(ext) + 2) + ext + struct.pack('<H', first_ext)
    return _item(head + ext_block)


def id_list(*items: bytes) -> bytes:
    """Shell items followed by the 2-byte terminator, as stored in ShellBags (BagMRU) values."""
    return b''.join(items) + b'\0\0'
