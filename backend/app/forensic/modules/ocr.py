"""Text in pictures and scans: tesseract reads every picture big enough to hold text, and every PDF whose pages carry no
text (rendered by pdftoppm first). The text goes on the file-index entry (`ocr`); the content index and found data use it,
so a word or an account number written on a whiteboard photo or a scanned page is found by content search."""
from __future__ import annotations
import shutil

from pymongo import UpdateOne

from .. import media as md
from .base import Module
from .fileproc import _inode_order
from .media import _ext, copy_out

MAX_FILES = 2_000
MAX_BYTES = 100 << 20


class OcrModule(Module):
    name = 'ocr'
    label = 'Text in pictures and scans (OCR)'
    description = ('Text read by OCR (tesseract, English) from pictures and from PDFs that are scans, for content search and found '
                   'data.')
    requires = ('fileproc',)
    follows = ('containers', 'email', 'media')  # members; picture sizes (too small to hold text)
    weight = 25
    collections = ()
    fields = {'fs_entries': ('ocr',)}

    def run(self, ctx):
        counts = {'ocr_files_read': 0, 'ocr_files_with_text': 0, 'ocr_characters': 0, 'ocr_failed': 0}
        entries = [e for e in ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'size': {'$gt': 0}, 'hash_error': None, 'encryption': None,
             '$or': [{'file_category': 'image'}, {'mime': 'application/pdf'}]},
            {'path': 1, 'name': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'deleted': 1, 'file_category': 1, 'mime': 1, 'container': 1,
             'media.width': 1, 'media.height': 1})]
        small = lambda e: (e.get('media') or {}).get('width') and ((e['media']['width'] < md.OCR_MIN_SIZE[0])
                                                                   or (e['media'].get('height') or 0) < md.OCR_MIN_SIZE[1])
        entries = [e for e in entries if not small(e)]
        entries.sort(key=lambda e: (bool(e.get('container')), _inode_order(e)))
        if len(entries) > MAX_FILES:
            ctx.warn(f'Only the first {MAX_FILES:,} of {len(entries):,} pictures and PDFs were read by OCR')
            entries = entries[:MAX_FILES]
        src = ctx.source()
        work = ctx.work / 'ocr'
        ops = []
        for n, e in enumerate(entries):
            ctx.progress(n / max(1, len(entries)), e['path'][-60:])
            ctx.checkpoint()
            local = work / f'input{_ext(e.get("name") or e["path"])}'
            try:
                if not copy_out(src, ctx.eid, e, local, MAX_BYTES):
                    continue
                if e.get('mime') == 'application/pdf':
                    if not md.pdf_needs_ocr(local, ctx.run_tool):
                        continue
                    text, pages = md.ocr_pdf(local, work / 'pages', ctx.run_tool)
                else:
                    text, pages = md.ocr_image(local, work, ctx.run_tool), 1
                counts['ocr_files_read'] += 1
            except Exception as exc:
                counts['ocr_failed'] += 1
                ctx.warn(f'{e["path"]}: OCR failed: {str(exc)[:200]}')
                continue
            finally:
                shutil.rmtree(work, ignore_errors=True)
            if sum(c.isalnum() for c in text) < 3:
                continue
            counts['ocr_files_with_text'] += 1
            counts['ocr_characters'] += len(text)
            ops.append(UpdateOne({'_id': e['_id']}, {'$set': {'ocr': {'text': text, 'chars': len(text), 'pages': pages,
                                                                       'engine': 'tesseract', 'language': 'eng'}}}))
            if len(ops) >= 200:
                ctx.db['fs_entries'].bulk_write(ops, ordered=False)
                ops = []
        if ops:
            ctx.db['fs_entries'].bulk_write(ops, ordered=False)
        for k, v in counts.items():
            ctx.count(k, v)
