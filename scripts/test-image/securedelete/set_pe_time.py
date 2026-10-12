"""Sets a PE file's compile time (the COFF header's TimeDateStamp) to a Unix time: python3 set_pe_time.py <file> <seconds>"""
import struct
import sys

path, when = sys.argv[1], int(sys.argv[2])
with open(path, 'r+b') as f:
    data = f.read(0x400)
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        sys.exit(f'{path}: not a PE file')
    f.seek(pe + 8)
    f.write(struct.pack('<I', when))
