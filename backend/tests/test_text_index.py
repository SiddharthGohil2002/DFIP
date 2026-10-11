"""The content index: trigram substring search, RE2 regular expressions, byte offsets and time limits."""
import time

import pytest

from app.forensic.text_index import QueryError, Writer, compile_regex, iter_documents, phrase, required_literal, search
from app.forensic.textextract import decode_text, strings

PAYROLL = ('employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))).encode()


def _entry(path, inode='10', deleted=False):
    return {'path': path, 'inode': inode, 'volume_id': 'p2048', 'deleted': deleted, 'size': 1}


@pytest.fixture
def index(tmp_path):
    final = tmp_path / 'EVID-1.sqlite'
    w = Writer(tmp_path / 'EVID-1.tmp')
    w.add(_entry('/Users/alice/Pictures/holiday.jpg', '11'), decode_text(PAYROLL))
    w.add(_entry('/Users/alice/Documents/payroll-export.csv', '12', deleted=True), decode_text(PAYROLL))
    w.add(_entry('/Users/alice/Documents/notes-utf16.txt', '13'),
          decode_text(b'\xff\xfe' + 'Reminder: wipe the SanDisk drive after copying PAYROLL-export.csv'.encode('utf-16-le')))
    blob = b'\x00' * 7 + 'E:\\payroll-export.csv'.encode('utf-16-le') + b'\x00' * 3
    w.add(_entry('/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk', '14'), strings(blob))
    w.finish(final)
    assert not (tmp_path / 'EVID-1.tmp').exists()
    return final, blob


def _by_path(hits):
    return {h['path'].rsplit('/', 1)[-1]: h for h in hits}


def test_substring_search_is_case_insensitive_with_exact_byte_offsets(index):
    path, blob = index
    hits, complete = search(path, 'payroll-export', 'text', time.monotonic() + 10)
    found = _by_path(hits)
    assert complete and set(found) == {'notes-utf16.txt', 'payroll-export.csv.lnk'}
    utf16 = 'Reminder: wipe the SanDisk drive after copying PAYROLL-export.csv'
    m = found['notes-utf16.txt']['matches'][0]
    assert m['byte_offset'] == 2 + utf16.index('PAYROLL') * 2 and m['byte_length'] == 28 and m['match'] == 'PAYROLL-export'
    lnk = found['payroll-export.csv.lnk']['matches'][0]
    assert lnk['byte_offset'] == blob.index('payroll'.encode('utf-16-le')) and lnk['byte_length'] == 28


def test_every_occurrence_is_counted_and_located(index):
    path, _ = index
    hits, _ = search(path, 'DE89370400440532013', 'text', time.monotonic() + 10)
    found = _by_path(hits)
    assert set(found) == {'holiday.jpg', 'payroll-export.csv'}
    h = found['holiday.jpg']
    assert h['match_count'] == 60 and len(h['matches']) == 20 and found['payroll-export.csv']['deleted'] is True
    starts = [i for i in range(len(PAYROLL)) if PAYROLL.startswith(b'DE89370400440532013', i)]
    assert [m['byte_offset'] for m in h['matches']] == starts[:20]
    assert h['matches'][0]['before'].endswith('emp000,') and h['matches'][0]['after'].startswith('000,50000')


def test_quotes_in_a_search_term(index):
    path, _ = index
    assert phrase('say "hi"') == '"say ""hi"""'
    assert search(path, 'emp"000', 'text', time.monotonic() + 10)[0] == []


def test_regex_search_with_and_without_a_required_literal(index):
    path, _ = index
    hits, complete = search(path, r'emp05\d,DE\d{20}', 'regex', time.monotonic() + 10)
    assert complete and {h['path'].rsplit('/', 1)[-1] for h in hits} == {'holiday.jpg', 'payroll-export.csv'}
    assert all(h['match_count'] == 10 for h in hits)
    hits, _ = search(path, r'[A-Z]:\\[a-z-]+\.csv', 'regex', time.monotonic() + 10)  # no literal: every file scanned
    assert {h['path'].rsplit('/', 1)[-1] for h in hits} == {'payroll-export.csv.lnk'}
    hits, _ = search(path, r'(?i)sandisk', 'regex', time.monotonic() + 10)
    assert [h['path'].rsplit('/', 1)[-1] for h in hits] == ['notes-utf16.txt']


@pytest.mark.parametrize('pattern', ['(unclosed', r'(a)\1', '', 'x' * 1001])
def test_invalid_or_unsupported_patterns_are_refused(pattern):
    with pytest.raises(QueryError):
        compile_regex(pattern)


def test_a_search_stops_at_its_deadline(index):
    path, _ = index
    hits, complete = search(path, 'payroll', 'text', time.monotonic() - 1)
    assert hits == [] and complete is False


@pytest.mark.parametrize('pattern,literal', [
    (r'payroll-export\.csv', 'payroll-export.csv'),
    (r'emp05\d,DE\d{20}', 'emp05'),
    (r'abc?def', 'def'),          # c is optional
    (r'abcd+ef', 'abcd'),         # d repeats: "abcd" is certain, "ef" follows some number of d
    (r'(?i)sandisk', 'sandisk'),
    (r'foo|barbaz', None),        # alternation: no single required literal
    (r'[A-Z]:\\x', ':\\x'),       # an escaped backslash is a literal character
    (r'ab(cdef)?gh', None),       # the group is optional; ab and gh are too short
    (r'\d{4}-\d{4}', None),
])
def test_required_literal(pattern, literal):
    assert required_literal(pattern) == literal


def test_documents_can_be_read_back(index):
    path, _ = index
    docs = list(iter_documents(path))
    assert [d['method'] for d, _ in docs] == ['text', 'text', 'text', 'strings'] and docs[0][1] == PAYROLL.decode()
