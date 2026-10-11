"""An empty Windows registry hive (regf): a base block and one hive bin holding only the root key.

hivex can add keys and values to a hive but cannot create one from nothing, so the generator starts every
synthetic hive from this. Layout per the regf format: 4 KiB base block (signature, sequence numbers, version 1.5,
root cell offset, XOR checksum), then a 4 KiB hbin with the root nk cell, its security descriptor (sk cell) and
one free cell.
"""
import struct

HBIN = 4096
ROOT_OFF = 0x20      # cell offsets are relative to the first hive bin
SK_OFF = 0x78


def _sid(authority: int, *subs: int) -> bytes:
    return struct.pack('<BB', 1, len(subs)) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


def _security_descriptor() -> bytes:
    """Self-relative descriptor: owner Administrators, group SYSTEM, a DACL granting Everyone full access."""
    owner, group, everyone = _sid(5, 32, 544), _sid(5, 18), _sid(1, 0)
    ace = struct.pack('<BBHI', 0, 0x02, 8 + len(everyone), 0x000F003F) + everyone   # ACCESS_ALLOWED, CONTAINER_INHERIT
    acl = struct.pack('<BBHHH', 2, 0, 8 + len(ace), 1, 0) + ace
    dacl_off = 20
    owner_off = dacl_off + len(acl)
    group_off = owner_off + len(owner)
    header = struct.pack('<BBHIIII', 1, 0, 0x8004, owner_off, group_off, 0, dacl_off)  # SELF_RELATIVE | DACL_PRESENT
    return header + acl + owner + group


def _cell(body: bytes) -> bytes:
    size = (len(body) + 4 + 7) & ~7
    return struct.pack('<i', -size) + body + b'\0' * (size - 4 - len(body))


def empty_hive(root_name: str = 'ROOT') -> bytes:
    name = root_name.encode('ascii')
    nk = struct.pack('<2sHQIIIIIIIIIIIIIIIHH', b'nk', 0x2C, 0, 0, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF,
                     SK_OFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, len(name), 0) + name
    sd = _security_descriptor()
    sk = struct.pack('<2sHIIII', b'sk', 0, SK_OFF, SK_OFF, 1, len(sd)) + sd
    cells = _cell(nk)
    assert len(cells) + ROOT_OFF == SK_OFF, 'root nk cell must end where the sk cell starts'
    cells += _cell(sk)
    free = HBIN - 0x20 - len(cells)
    hbin = struct.pack('<4sIIQQI', b'hbin', 0, HBIN, 0, 0, 0) + cells + struct.pack('<i', free) + b'\0' * (free - 4)
    base = bytearray(4096)
    struct.pack_into('<4sIIQIIIIIII', base, 0, b'regf', 1, 1, 0, 1, 5, 0, 1, ROOT_OFF, HBIN, 1)
    checksum = 0
    for (word,) in struct.iter_unpack('<I', bytes(base[:508])):
        checksum ^= word
    struct.pack_into('<I', base, 508, 1 if checksum == 0 else (0xFFFFFFFE if checksum == 0xFFFFFFFF else checksum))
    return bytes(base) + hbin
