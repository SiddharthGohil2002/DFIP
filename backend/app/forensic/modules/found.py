"""Found data: email addresses, web and IP addresses, phone, card, IBAN, cryptocurrency and Aadhaar numbers
recognised (and validated) in the content index, each with where it occurs (file and byte offset)."""
from __future__ import annotations
from pathlib import Path

from ..found_data import KINDS, SENSITIVE, find_all, key_of
from ..text_index import DocMap, index_path, iter_documents, unallocated_index_path
from .base import Module

MAX_OCCURRENCES = 100     # stored per value (all are counted)
MAX_VALUES_PER_KIND = 50_000
COUNT_KEYS = {'email': 'found_emails', 'url': 'found_urls', 'ip': 'found_ip_addresses', 'phone': 'found_phone_numbers',
              'card': 'found_card_numbers', 'iban': 'found_ibans', 'crypto': 'found_crypto_addresses', 'aadhaar': 'found_aadhaar_numbers'}


class FoundDataModule(Module):
    name = 'found_data'
    label = 'Found data'
    description = ('Email addresses, web and IP addresses, phone numbers, card numbers (Luhn), IBANs (mod-97), Bitcoin and '
                   'Ethereum addresses (checksums) and Aadhaar numbers (Verhoeff) in the file contents.')
    requires = ('content',)
    kinds = ('disk', 'logical', 'capture')  # files carried in a capture too
    follows = ('unallocated',)  # unallocated space is scanned too when it was read
    weight = 8
    collections = ('entities',)

    def run(self, ctx):
        for key in COUNT_KEYS.values():
            ctx.count(key, 0)
        path = index_path(ctx.eid)
        if not Path(path).is_file():
            ctx.warn('No content index for this evidence; run File contents first')
            return
        sources = [path] + ([unallocated_index_path(ctx.eid)] if ctx.fact('unallocated', 'index') else [])
        found: dict[tuple[str, str], dict] = {}
        per_kind = {k: 0 for k in KINDS}
        capped = set()
        documents = (d for p in sources if Path(p).is_file() for d in iter_documents(p))
        for n, (doc, text) in enumerate(documents):
            if n % 100 == 0:
                ctx.progress(min(0.95, n / max(1, (ctx.fact('content', 'index') or {}).get('documents') or 1)))
            where = None
            for kind, value, display, details, start, end in find_all(text):
                item = found.get((kind, value))
                if item is None:
                    if per_kind[kind] >= MAX_VALUES_PER_KIND:
                        capped.add(kind)
                        continue
                    per_kind[kind] += 1
                    item = found[(kind, value)] = {
                        'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'kind': kind, 'value': value, 'key': key_of(kind, value),
                        'display': display, 'sensitive': kind in SENSITIVE, 'details': details, 'count': 0, 'files': set(),
                        'occurrences': []}
                item['count'] += 1
                item['files'].add((doc['volume_id'], doc['path']))  # ids repeat across the two indexes
                if len(item['occurrences']) < MAX_OCCURRENCES:
                    where = where or DocMap(doc)
                    item['occurrences'].append({
                        'path': doc['path'], 'inode': doc['inode'], 'volume_id': doc['volume_id'], 'deleted': bool(doc['deleted']),
                        'method': doc['method'], 'member': bool(doc['member']) if 'member' in doc.keys() else False, 'text_offset': start,
                        'byte_offset': where.offset(text, start),
                        'byte_length': where.length(start, text[start:end]), 'as_found': text[start:end] if kind not in SENSITIVE else None})
        for kind in capped:
            ctx.warn(f'More than {MAX_VALUES_PER_KIND:,} different {kind} values: the rest were not recorded')
        docs = []
        for item in found.values():
            item['file_count'] = len(item.pop('files'))
            docs.append(item)
            ctx.count(COUNT_KEYS[item['kind']])
        docs.sort(key=lambda d: (d['kind'], -d['count'], d['value']))
        for i in range(0, len(docs), 1000):
            ctx.insert('entities', docs[i:i + 1000])
