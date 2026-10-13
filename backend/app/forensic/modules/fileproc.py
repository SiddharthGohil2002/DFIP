"""Every file's hashes and real type, read once, in-process.

For each file in the index (allocated and deleted; a deleted file's hash is of its content as it is on the disk
now) one read pass feeds MD5, SHA-1 and SHA-256, the type check on the first bytes (libmagic), a byte histogram
for entropy, and the encryption markers. Results are stored on the file-index entries, so the Files page can
filter on them and hash sets can be matched without reading the evidence again.
"""
from __future__ import annotations
import hashlib

from pymongo import UpdateOne

from ..filetypes import ENTROPY_BYTES, HEAD_BYTES, ZIP_LOCAL, category, encryption, entropy, histogram, mismatch, refine_zip
from ..source import BlobRef
from .base import Module

CHUNK = 1 << 20
WRITE_BATCH = 500
FIELDS = ('md5', 'sha1', 'sha256', 'mime', 'magic', 'file_category', 'ext_mismatch', 'expected_type', 'entropy', 'encryption',
          'hash_basis', 'hash_error')


def _inode_order(entry):
    head = (entry.get('inode') or '').split('-')[0]
    return entry.get('volume_id') or '', int(head) if head.isdigit() else 0


class FileProcModule(Module):
    name = 'fileproc'
    label = 'File hashes and types'
    description = ('MD5, SHA-1 and SHA-256 of every file (deleted ones as they are on the disk now), its real type from its '
                   'content, files whose name does not match their content, entropy and encryption.')
    requires = ('fs_index',)
    weight = 25
    collections = ()
    fields = {'fs_entries': FIELDS}

    def run(self, ctx):
        import magic
        mime_of = magic.Magic(mime=True)
        describe = magic.Magic()
        src = ctx.source()
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'is_virtual': False, 'container': {'$exists': False}},
            {'path': 1, 'name': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'deleted': 1}))
        entries.sort(key=_inode_order)  # roughly the order of the data on the disk
        total = sum(max(0, e.get('size') or 0) for e in entries) or 1
        done = 0
        ops = []
        counts = {'files_hashed': 0, 'files_unreadable': 0, 'renamed_files': 0, 'encrypted_files': 0}
        categories: dict[str, int] = {}
        for e in entries:
            fields = self._process(src, ctx, e, mime_of, describe)
            done += max(0, e.get('size') or 0)
            if fields.get('hash_error'):
                counts['files_unreadable'] += 1
            else:
                counts['files_hashed'] += 1
                counts['renamed_files'] += bool(fields.get('ext_mismatch'))
                counts['encrypted_files'] += bool(fields.get('encryption'))
                categories[fields['file_category']] = categories.get(fields['file_category'], 0) + 1
            ops.append(UpdateOne({'_id': e['_id']}, {'$set': fields}))
            if len(ops) >= WRITE_BATCH:
                ctx.db['fs_entries'].bulk_write(ops, ordered=False)
                ops = []
                ctx.progress(done / total)
        if ops:
            ctx.db['fs_entries'].bulk_write(ops, ordered=False)
        for k, v in counts.items():
            ctx.count(k, v)
        ctx.set_fact('categories', categories)
        if counts['files_unreadable']:
            ctx.warn(f'{counts["files_unreadable"]} file(s) could not be read for hashing (see hash_error on the file)')

    def _process(self, src, ctx, e, mime_of, describe) -> dict:
        basis = 'deleted: content as currently on the disk' if e.get('deleted') else 'allocated'
        try:
            blob = src.open(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e.get('inode')))
        except Exception as exc:
            return {'hash_basis': basis, 'hash_error': str(exc)[:300]}
        return process_blob(blob, e.get('name') or e.get('path', '').rsplit('/', 1)[-1], basis, mime_of, describe,
                            checkpoint=ctx.checkpoint, warn=lambda m: ctx.warn(f'{e.get("path")}: {m}'))


def process_blob(blob, name: str, basis: str, mime_of, describe, checkpoint=lambda: None, warn=lambda m: None) -> dict:
    """Hashes, type, entropy and encryption of one piece of content (a file on the evidence or a member taken out
    of a container), from a single read."""
    try:
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        head = b''
        hist = None
        for start in range(0, blob.size, CHUNK):
            data = blob.read(start, min(CHUNK, blob.size - start))
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
            if start == 0:
                head = data[:HEAD_BYTES]
            if start < ENTROPY_BYTES:
                h = histogram(data[:ENTROPY_BYTES - start])
                hist = h if hist is None else hist + h
            if start // CHUNK % 64 == 63:
                checkpoint()
    except Exception as exc:
        return {'hash_basis': basis, 'hash_error': str(exc)[:300]}
    mime = mime_of.from_buffer(head) if head else 'inode/x-empty'
    desc = describe.from_buffer(head) if head else 'empty'
    if head[:4] == ZIP_LOCAL and mime in ('application/octet-stream', 'application/zip'):
        mime, desc = refine_zip(blob, mime, desc)
    ent = round(entropy(hist), 4) if hist is not None else 0.0
    expected = mismatch(name, mime)
    try:
        enc = encryption(blob, head, mime, ent) if head else None
    except Exception as exc:
        enc = None
        warn(f'encryption check failed: {exc}')
    return {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256': sha256.hexdigest(), 'mime': mime, 'magic': desc[:200],
            'file_category': category(mime, name, desc), 'ext_mismatch': bool(expected), 'expected_type': expected,
            'entropy': ent, 'encryption': enc, 'hash_basis': basis, 'hash_error': None}
