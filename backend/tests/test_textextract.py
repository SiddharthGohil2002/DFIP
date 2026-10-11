"""Text extraction for the content index: decoding with traceable offsets, strings, Office/OpenDocument, RTF, PDF."""
import io
import zipfile

import pytest

from app.forensic.modules.base import run_tool
from app.forensic.textextract import (MAX_XML_PART, decode_text, extract, method_for, odf_text, ooxml_text, rtf_text,
                                      strings)
from app.forensic.text_index import DocMap


def _offset(ex, text_index):
    doc = {'method': ex.method, 'encoding': ex.encoding, 'bom': ex.bom, 'spans': ex.spans}
    return DocMap(doc).offset(ex.text, text_index)


def _zip(parts: dict, first_stored: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        if first_stored:
            z.writestr(zipfile.ZipInfo(first_stored), parts.pop(first_stored))
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


# ------------------------------------------------------------------ which method
@pytest.mark.parametrize('entry,expected', [
    ({'size': 10, 'file_category': 'text', 'mime': 'text/csv'}, 'text'),
    ({'size': 10, 'file_category': 'script', 'mime': 'text/plain'}, 'text'),
    ({'size': 10, 'file_category': 'document', 'mime': 'application/pdf'}, 'pdf'),
    ({'size': 10, 'file_category': 'document', 'mime': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}, 'ooxml'),
    ({'size': 10, 'file_category': 'document', 'mime': 'application/vnd.oasis.opendocument.text'}, 'odf'),
    ({'size': 10, 'file_category': 'document', 'mime': 'text/rtf'}, 'rtf'),
    ({'size': 10, 'file_category': 'document', 'mime': 'application/msword'}, 'strings'),
    ({'size': 10, 'file_category': 'registry', 'mime': 'application/octet-stream'}, 'strings'),
    ({'size': 10, 'file_category': 'database', 'mime': 'application/vnd.sqlite3'}, 'sqlite'),
    ({'size': 10, 'file_category': 'image', 'mime': 'image/png'}, None),
    ({'size': 10, 'file_category': 'archive', 'mime': 'application/zip'}, None),
    ({'size': 0, 'file_category': 'text', 'mime': 'text/plain'}, None),
    ({'size': 10, 'file_category': 'document', 'mime': 'application/encrypted', 'encryption': {'kind': 'OFFICE'}}, None),
    ({'size': 10, 'file_category': 'text', 'mime': 'text/plain', 'hash_error': 'unreadable'}, None),
])
def test_method_for(entry, expected):
    assert method_for(entry) == expected


# ------------------------------------------------------------------ plain text
def test_utf8_offsets_count_bytes_not_characters():
    data = 'Zoë Martin <zoe.martin@example.org>'.encode()
    ex = decode_text(data)
    i = ex.text.index('<')
    assert (ex.encoding, ex.bom) == ('utf-8', 0) and _offset(ex, i) == data.index(b'<') == 12


def test_byte_order_marks():
    ex = decode_text(b'\xef\xbb\xbfhello')
    assert (ex.text, ex.encoding, ex.bom) == ('hello', 'utf-8', 3) and _offset(ex, 1) == 4
    data = b'\xff\xfe' + 'wipe the SanDisk'.encode('utf-16-le')
    ex = decode_text(data)
    assert (ex.text, ex.encoding, ex.bom) == ('wipe the SanDisk', 'utf-16-le', 2)
    assert _offset(ex, ex.text.index('SanDisk')) == data.index('SanDisk'.encode('utf-16-le'))
    ex = decode_text(b'\xfe\xff' + 'big'.encode('utf-16-be'))
    assert (ex.text, ex.encoding) == ('big', 'utf-16-be')


def test_utf16_without_a_byte_order_mark():
    data = 'Reminder: copy payroll-export.csv'.encode('utf-16-le')
    ex = decode_text(data)
    assert ex.encoding == 'utf-16-le' and ex.text.startswith('Reminder') and _offset(ex, 10) == 20


def test_windows_1252_fallback_keeps_one_byte_per_character():
    data = b'caf\xe9 \x81 r\xe9sum\xe9 payroll'
    ex = decode_text(data)
    assert ex.encoding == 'cp1252' and ex.text.startswith('café') and _offset(ex, ex.text.index('payroll')) == data.index(b'payroll')


def test_a_character_cut_at_the_end_is_dropped_not_misread():
    ex = decode_text('naïve text €'.encode()[:-1])
    assert ex.encoding == 'utf-8' and ex.text == 'naïve text '


def test_nul_bytes_keep_their_place():
    ex = decode_text(b'ab\x00cd payroll')
    assert '\x00' not in ex.text and _offset(ex, ex.text.index('payroll')) == 6


# ------------------------------------------------------------------ strings
def test_strings_ascii_and_utf16_with_offsets():
    blob = b'\x00\x01' + b'short' + b'\xff' * 3 + b'C:\\Users\\alice' + b'\x00' * 4 + 'E:\\payroll-export.csv'.encode('utf-16-le') + b'\x90'
    ex = strings(blob)
    assert ex.text.split('\n') == ['C:\\Users\\alice', 'E:\\payroll-export.csv']  # "short" is under 6 characters
    i = ex.text.index('payroll')
    assert _offset(ex, i) == blob.index('payroll'.encode('utf-16-le'))
    assert _offset(ex, ex.text.index('alice')) == blob.index(b'alice')
    assert DocMap({'method': 'strings', 'encoding': None, 'bom': 0, 'spans': ex.spans}).length(i, 'payroll') == 14


# ------------------------------------------------------------------ documents
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def test_word_document_text():
    doc = (f'<w:document {W}><w:body><w:p><w:r><w:t>Send the payroll </w:t></w:r><w:r><w:t>export</w:t></w:r></w:p>'
           f'<w:p><w:r><w:t>to alice.personal@example.net</w:t></w:r></w:p></w:body></w:document>')
    data = _zip({'[Content_Types].xml': '<Types/>', 'word/document.xml': doc,
                 'word/footer1.xml': f'<w:ftr {W}><w:p><w:r><w:t>Confidential</w:t></w:r></w:p></w:ftr>'})
    assert ooxml_text(data).split('\n') == ['Send the payroll export', 'to alice.personal@example.net', 'Confidential']


def test_spreadsheet_and_presentation_text():
    S = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    xlsx = _zip({'[Content_Types].xml': '<Types/>', 'xl/workbook.xml': f'<workbook {S}/>',
                 'xl/sharedStrings.xml': f'<sst {S}><si><t>employee</t></si><si><t>iban</t></si></sst>',
                 'xl/worksheets/sheet1.xml': f'<worksheet {S}><sheetData><row><c t="s"><v>0</v></c><c t="s"><v>1</v></c></row>'
                                             f'<row><c t="inlineStr"><is><t>emp000</t></is></c><c><v>50000</v></c></row></sheetData></worksheet>'})
    assert ooxml_text(xlsx) == 'employee\tiban\nemp000\t50000'
    A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
    pptx = _zip({'[Content_Types].xml': '<Types/>', 'ppt/presentation.xml': '<p/>',
                 'ppt/slides/slide2.xml': f'<s {A}><a:p><a:r><a:t>Second</a:t></a:r></a:p></s>',
                 'ppt/slides/slide1.xml': f'<s {A}><a:p><a:r><a:t>First</a:t></a:r></a:p></s>'})
    assert ooxml_text(pptx) == 'First\nSecond'


def test_extract_returns_each_method_with_its_text():
    docx = _zip({'[Content_Types].xml': '<Types/>', 'word/document.xml': f'<w:document {W}><w:body><w:p><w:r><w:t>hello docx</w:t></w:r></w:p></w:body></w:document>'})
    for method, data, text in (('ooxml', docx, 'hello docx'), ('rtf', rb'{\rtf1 hello rtf\par}', 'hello rtf\n'),
                               ('text', b'hello text', 'hello text'), ('strings', b'\x00hello strings\x00', 'hello strings')):
        ex = extract(method, data)
        assert (ex.method, ex.text, ex.truncated) == (method, text, False)
    with pytest.raises(ValueError):
        extract('nope', b'')


def test_opendocument_text():
    content = ('<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
               'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text>'
               '<text:h>Budget</text:h><text:p>Q3 total <text:span>12,400</text:span></text:p></office:text></office:body></office:document-content>')
    data = _zip({'mimetype': 'application/vnd.oasis.opendocument.text', 'content.xml': content}, first_stored='mimetype')
    assert odf_text(data) == 'Budget\nQ3 total 12,400'


def test_xml_entities_are_refused():
    bomb = ('<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>'
            f'<w:document {W}><w:body><w:p><w:r><w:t>&b;</w:t></w:r></w:p></w:body></w:document>')
    with pytest.raises(Exception):
        ooxml_text(_zip({'[Content_Types].xml': '<Types/>', 'word/document.xml': bomb}))


def test_oversized_xml_parts_are_not_expanded():
    huge = f'<w:document {W}><w:body>' + ' ' * (MAX_XML_PART + 10) + '</w:body></w:document>'
    with pytest.raises(ValueError, match='too large'):
        ooxml_text(_zip({'[Content_Types].xml': '<Types/>', 'word/document.xml': huge}))


def test_rtf_text():
    rtf = (r"{\rtf1\ansi\deff0{\fonttbl{\f0 Calibri;}}{\colortbl;\red0\green0\blue0;}{\*\generator Riched20;}"
           r"\pard Meeting notes: the USB drive CRUZER holds the export.\par Caf\'e9 at 10:00\tab done\par" "\r\n"
           r"Euro \u8364? sign\par}")
    assert rtf_text(rtf) == 'Meeting notes: the USB drive CRUZER holds the export.\nCafé at 10:00\tdone\nEuro € sign\n'


def _pdf(text: str) -> bytes:
    stream = f'BT /F1 18 Tf 72 720 Td ({text}) Tj ET'.encode()
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
               b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'\nendstream',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    out, offsets = b'%PDF-1.4\n', []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % i + body + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1) + b''.join(b'%010d 00000 n \n' % o for o in offsets)
    return out + b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, xref)


def test_pdf_text_with_pdftotext(tmp_path):
    ex = extract('pdf', _pdf('Offer letter - Alice Example'), run_tool=lambda argv, timeout: run_tool(argv, timeout=timeout), work=tmp_path)
    assert ex.method == 'pdf' and 'Offer letter - Alice Example' in ex.text
    assert not list(tmp_path.iterdir())  # the temporary copies are removed


def _tool(argv, timeout):
    return run_tool(argv, timeout=timeout)


def test_sqlite_values_are_kept_apart(tmp_path):
    import sqlite3
    db = tmp_path / 'History'
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visits INTEGER)')
    con.execute("INSERT INTO urls VALUES (1, 'https://mail.example.com/inbox', 'Inbox - Mail', 12)")
    con.execute("CREATE TABLE notes (body BLOB)")
    con.execute("INSERT INTO notes VALUES (?)", ('stored as utf-8 bytes'.encode(),))
    con.commit()
    con.close()
    work = tmp_path / 'work'
    ex = extract('sqlite', db.read_bytes(), run_tool=_tool, work=work)
    assert ex.method == 'sqlite' and ex.text.split('\n')[:3] == ['https://mail.example.com/inbox', 'Inbox - Mail', 'stored as utf-8 bytes']
    assert not list(work.iterdir())
    # A damaged database falls back to its strings.
    broken = extract('sqlite', b'SQLite format 3\x00' + b'\xff' * 100 + b'https://example.org/page' + b'\x00' * 50, run_tool=_tool, work=work)
    assert broken.method == 'strings' and 'https://example.org/page' in broken.text


def test_a_broken_pdf_is_reported():
    with pytest.raises(ValueError, match='pdftotext'):
        extract('pdf', b'%PDF-1.4 not really', run_tool=lambda argv, timeout: run_tool(argv, timeout=timeout), work=__import__('pathlib').Path('/tmp/dfip-pdf-test'))
