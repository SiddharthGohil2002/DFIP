"""File contents: the text of every file that has any, in a per-evidence full-text index (SQLite FTS5).

Which files and how their text is read is decided by their real type from file processing (see
app/forensic/textextract.py). Deleted files are indexed as their content is on the disk now. The index is
built into a temporary file and renamed over the previous one when complete.
"""
from __future__ import annotations

from ..source import open_entry
from ..text_index import Writer, index_path
from ..textextract import MAX_READ, Extracted, extract, method_for
from .base import Module
from .fileproc import _inode_order

MAX_TOTAL_CHARS = 1_500_000_000  # text kept per evidence item


class ContentModule(Module):
    name = 'content'
    label = 'File contents'
    version = '4'  # 2: archive members, and a member flag in the index; 3: SQLite write-ahead logs by value; 4: OCR text
    description = ('Text of documents, PDFs, text files and the readable strings of other files, in a full-text index for '
                   'content search (deleted files included).')
    requires = ('fileproc',)
    follows = ('containers', 'email', 'ocr')  # archive members, email attachments, and text read from pictures and scans
    weight = 30
    collections = ()

    def run(self, ctx):
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'is_virtual': False, 'size': {'$gt': 0}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'deleted': 1, 'mime': 1, 'file_category': 1,
             'encryption': 1, 'hash_error': 1, 'container': 1, 'magic': 1, 'ocr.text': 1}))
        entries.sort(key=_inode_order)
        final = index_path(ctx.eid)
        writer = Writer(final.with_name(f'{final.stem}.{ctx.run_id}.tmp'))
        src = ctx.source()
        counts = {'files_text_indexed': 0, 'files_text_failed': 0, 'files_text_truncated': 0}
        methods: dict[str, int] = {}
        chars = 0
        try:
            for n, e in enumerate(entries):
                if n % 50 == 0:
                    ctx.progress(n / max(1, len(entries)))
                method = method_for(e)
                if not method:
                    continue
                try:
                    if method == 'ocr':  # text the OCR module read from a picture or a scanned PDF
                        ex = Extracted(e['ocr']['text'], 'ocr')
                    else:
                        blob = open_entry(src, ctx.eid, e)
                        data = blob.read(0, min(blob.size, MAX_READ))
                        ex = extract(method, data, run_tool=ctx.run_tool, work=ctx.work)
                except Exception as exc:
                    counts['files_text_failed'] += 1
                    ctx.warn(f'{e["path"]}: text could not be read ({method}): {str(exc)[:200]}')
                    continue
                if not ex.text.strip():
                    continue
                if chars + len(ex.text) > MAX_TOTAL_CHARS:
                    ctx.warn(f'The content index reached its limit of {MAX_TOTAL_CHARS:,} characters; '
                             f'{len(entries) - n:,} later file(s) were not indexed')
                    break
                writer.add(e, ex)
                chars += len(ex.text)
                counts['files_text_indexed'] += 1
                counts['files_text_truncated'] += int(ex.truncated or (e.get('size') or 0) > MAX_READ)
                methods[ex.method] = methods.get(ex.method, 0) + 1
            writer.finish(final)
        except BaseException:
            writer.abort()
            raise
        for k, v in counts.items():
            ctx.count(k, v)
        ctx.set_fact('index', {'path': str(final), 'documents': counts['files_text_indexed'], 'characters': chars,
                               'methods': methods})
