"""Text from evidence files, for the content index and found data.

How a file's text is obtained depends on its real type (from file processing), never its name:
  * text (plain text, CSV, JSON, XML, HTML, scripts, email): decoded (byte-order mark, UTF-8, UTF-16 without a
    mark, else Windows-1252), so a match can be traced back to its exact byte offset in the file
  * PDF: pdftotext (poppler), run as an external tool with a timeout
  * Office Open XML (docx, xlsx, pptx) and OpenDocument: the text of their XML parts, parsed with defusedxml
  * RTF: control words removed, escaped characters decoded
  * SQLite databases: the text values of their tables, one per line, read by a separate process (raw strings would
    run one field into the next); a database that can't be opened falls back to strings
  * everything else that may hold text (programs, databases, registry hives, shortcuts, legacy Office, unknown
    binary data): printable ASCII and UTF-16LE strings of at least 6 characters, each with its byte offset

Pictures, video, audio, archives (their members are a later addition), empty files and encrypted files have no
text here. Every file is read at most MAX_READ bytes deep and gives at most MAX_CHARS characters.
"""
from __future__ import annotations
import io
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_READ = 64 << 20          # bytes of a file read for text
MAX_CHARS = 8_000_000        # characters of text kept per file
MIN_STRING = 6               # shortest printable run kept by the strings fallback
MAX_XML_PART = 32 << 20      # largest uncompressed XML part read from an Office/OpenDocument file
MAX_XML_TOTAL = 96 << 20     # all parts of one document together
PDF_TIMEOUT = 120

TEXT_CATEGORIES = ('text', 'script', 'email')
STRINGS_CATEGORIES = ('executable', 'database', 'registry', 'shortcut', 'document', 'other')
OOXML_MIMES = {'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
               'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
               'application/vnd.openxmlformats-officedocument.presentationml.presentation'}
RTF_MIMES = {'text/rtf', 'application/rtf'}
SQLITE_MIMES = {'application/vnd.sqlite3', 'application/x-sqlite3'}
SQLITE_TIMEOUT = 120


@dataclass
class Extracted:
    text: str
    method: str                      # text | strings | pdf | ooxml | odf | rtf | sqlite
    encoding: str | None = None      # text: the encoding the bytes were decoded with
    bom: int = 0                     # text: bytes of byte-order mark before the text
    spans: list = field(default_factory=list)  # strings: [text_start, byte_start, bytes per character]
    truncated: bool = False


def method_for(entry: dict) -> str | None:
    """How to get text out of a file-index entry processed by fileproc, or None when it has none to give."""
    if entry.get('encryption') or entry.get('hash_error') or not entry.get('size'):
        return None
    mime, cat = entry.get('mime') or '', entry.get('file_category') or ''
    if mime in RTF_MIMES:
        return 'rtf'
    if cat in TEXT_CATEGORIES:
        return 'text'
    if mime == 'application/pdf':
        return 'pdf'
    if mime in OOXML_MIMES:
        return 'ooxml'
    if mime.startswith('application/vnd.oasis.opendocument'):
        return 'odf'
    if mime in SQLITE_MIMES:
        return 'sqlite'
    if cat in STRINGS_CATEGORIES:
        return 'strings'
    return None


def extract(method: str, data: bytes, *, run_tool=None, work: Path | None = None) -> Extracted:
    """The text of one file's bytes (at most MAX_READ of them) by `method` (see method_for)."""
    if method == 'text':
        return decode_text(data)
    if method == 'strings':
        return strings(data)
    if method == 'pdf':
        return pdf_text(data, run_tool, work)
    if method == 'ooxml':
        return _document(ooxml_text(data), 'ooxml')
    if method == 'odf':
        return _document(odf_text(data), 'odf')
    if method == 'rtf':
        return _document(rtf_text(data.decode('latin-1')), 'rtf')
    if method == 'sqlite':
        return sqlite_text(data, run_tool, work)
    raise ValueError(f'Unknown text method {method}')


def _cap(text: str) -> tuple[str, bool]:
    return (text[:MAX_CHARS], True) if len(text) > MAX_CHARS else (text, False)


def _document(text: str, method: str) -> Extracted:
    text, truncated = _cap(text.replace('\x00', ' '))
    return Extracted(text, method, truncated=truncated)


# ------------------------------------------------------------------ plain text
def _looks_utf16le(data: bytes) -> bool:
    sample = data[:4096]
    if len(sample) < 8:
        return False
    odd_zero = sample[1::2].count(0) / (len(sample) // 2)
    even_zero = sample[0::2].count(0) / ((len(sample) + 1) // 2)
    return odd_zero > 0.6 and even_zero < 0.1


def decode_text(data: bytes) -> Extracted:
    """Decodes a text file. Offsets stay traceable: byte offset = bom + len(text[:i].encode(encoding))."""
    if data.startswith(b'\xef\xbb\xbf'):
        enc, bom = 'utf-8', 3
    elif data.startswith(b'\xff\xfe'):
        enc, bom = 'utf-16-le', 2
    elif data.startswith(b'\xfe\xff'):
        enc, bom = 'utf-16-be', 2
    elif _looks_utf16le(data):
        enc, bom = 'utf-16-le', 0
    else:
        enc, bom = 'utf-8', 0
    body = data[bom:]
    if enc.startswith('utf-16') and len(body) % 2:
        body = body[:-1]
    if enc == 'utf-8':
        try:
            text = body.decode('utf-8')
        except UnicodeDecodeError as exc:
            if exc.start >= len(body) - 3:  # a character cut in two where the read stopped
                text = body[:exc.start].decode('utf-8')
            else:
                enc = 'cp1252'
                text = body.decode(enc, errors='replace')
    else:
        text = body.decode(enc, errors='replace')
    text, truncated = _cap(text)
    # NUL is kept as a space of the same width, so offsets do not move (SQLite text stops at NUL in places).
    return Extracted(text.replace('\x00', ' '), 'text', encoding=enc, bom=bom, truncated=truncated)


# ------------------------------------------------------------------ strings
_ASCII_RUN = re.compile(rb'[\x20-\x7e\t]{%d,}' % MIN_STRING)
_UTF16_RUN = re.compile(rb'(?:[\x20-\x7e\t]\x00){%d,}' % MIN_STRING)


def strings(data: bytes) -> Extracted:
    """Printable ASCII and UTF-16LE runs, in file order, one per line; spans map text back to bytes."""
    runs = [(m.start(), m.group().decode('ascii'), 1) for m in _ASCII_RUN.finditer(data)]
    runs += [(m.start(), m.group().decode('utf-16-le'), 2) for m in _UTF16_RUN.finditer(data)]
    runs.sort()
    parts, spans, pos, truncated = [], [], 0, False
    for start, s, width in runs:
        if pos + len(s) > MAX_CHARS:
            truncated = True
            break
        spans.append([pos, start, width])
        parts.append(s)
        pos += len(s) + 1
    return Extracted('\n'.join(parts), 'strings', spans=spans, truncated=truncated)


# ------------------------------------------------------------------ PDF
def pdf_text(data: bytes, run_tool, work: Path | None) -> Extracted:
    if run_tool is None or work is None:
        raise ValueError('PDF text needs the tool runner and a work folder')
    work.mkdir(parents=True, exist_ok=True)
    src, out = work / 'pdftext-input.pdf', work / 'pdftext-output.txt'
    try:
        src.write_bytes(data)
        r = run_tool(['pdftotext', '-enc', 'UTF-8', '-q', str(src), str(out)], timeout=PDF_TIMEOUT)
        if r.get('status') != 'COMPLETED' or not out.exists():
            raise ValueError(f'pdftotext: {r.get("status")} {(r.get("stderr") or "").strip()[:200]}')
        with out.open('rb') as f:
            raw = f.read(MAX_CHARS * 4)
        text, truncated = _cap(raw.decode('utf-8', errors='replace').replace('\x0c', '\n').replace('\x00', ' '))
        return Extracted(text, 'pdf', truncated=truncated)
    finally:
        src.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


# ------------------------------------------------------------------ SQLite
_BACKEND = str(Path(__file__).resolve().parents[2])
_SQLITE_CMD = 'import sys; sys.path.insert(0, sys.argv[1]); from app.forensic.sqlite_text import dump; dump(sys.argv[2], sys.argv[3])'


def sqlite_text(data: bytes, run_tool, work: Path | None) -> Extracted:
    """The database's text values; its strings when it can't be opened (damaged, truncated or not really SQLite)."""
    if run_tool is None or work is None:
        return strings(data)
    work.mkdir(parents=True, exist_ok=True)
    src, out = work / 'sqlite-input.db', work / 'sqlite-output.txt'
    try:
        src.write_bytes(data)
        r = run_tool([sys.executable, '-c', _SQLITE_CMD, _BACKEND, str(src), str(out)], timeout=SQLITE_TIMEOUT)
        if r.get('status') != 'COMPLETED' or not out.exists():
            return strings(data)
        with out.open('rb') as f:
            text = f.read(MAX_CHARS * 4).decode('utf-8', errors='replace')
        return _document(text, 'sqlite')
    finally:
        src.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


# ------------------------------------------------------------------ Office Open XML and OpenDocument
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
A = '{http://schemas.openxmlformats.org/drawingml/2006/main}'
S = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
TEXT_NS = '{urn:oasis:names:tc:opendocument:xmlns:text:1.0}'


class _Parts:
    """XML parts of a ZIP-based document, read with size limits (a ZIP bomb is not expanded)."""

    def __init__(self, data: bytes):
        self.z = zipfile.ZipFile(io.BytesIO(data))
        self.total = 0

    def names(self, pattern: str) -> list[str]:
        rx = re.compile(pattern)
        return sorted((n for n in self.z.namelist() if rx.fullmatch(n)), key=_natural)

    def xml(self, name: str):
        from defusedxml.ElementTree import fromstring
        info = self.z.getinfo(name)
        if info.file_size > MAX_XML_PART or self.total + info.file_size > MAX_XML_TOTAL:
            raise ValueError(f'{name} is too large to read ({info.file_size:,} bytes uncompressed)')
        self.total += info.file_size
        return fromstring(self.z.read(name))


def _natural(name: str):
    return [int(p) if p.isdigit() else p for p in re.split(r'(\d+)', name)]


def _paragraphs(root, para: str, run_text: str) -> list[str]:
    out = []
    for p in root.iter(para):
        out.append(''.join(t.text or '' for t in p.iter(run_text)))
    return out


def ooxml_text(data: bytes) -> str:
    parts = _Parts(data)
    names = set(parts.z.namelist())
    out: list[str] = []
    if 'word/document.xml' in names:
        for n in ['word/document.xml'] + parts.names(r'word/(header|footer)\d*\.xml') + \
                 [x for x in ('word/footnotes.xml', 'word/endnotes.xml', 'word/comments.xml') if x in names]:
            out += _paragraphs(parts.xml(n), W + 'p', W + 't')
    if 'xl/workbook.xml' in names:
        shared = []
        if 'xl/sharedStrings.xml' in names:
            shared = [''.join(t.text or '' for t in si.iter(S + 't')) for si in parts.xml('xl/sharedStrings.xml').iter(S + 'si')]
        for n in parts.names(r'xl/worksheets/sheet\d+\.xml'):
            for row in parts.xml(n).iter(S + 'row'):
                cells = []
                for c in row.iter(S + 'c'):
                    v = c.find(S + 'v')
                    if c.get('t') == 's' and v is not None and (v.text or '').isdigit() and int(v.text) < len(shared):
                        cells.append(shared[int(v.text)])
                    elif c.get('t') == 'inlineStr':
                        cells.append(''.join(t.text or '' for t in c.iter(S + 't')))
                    elif v is not None and v.text:
                        cells.append(v.text)
                if cells:
                    out.append('\t'.join(cells))
    if 'ppt/presentation.xml' in names:
        for n in parts.names(r'ppt/slides/slide\d+\.xml') + parts.names(r'ppt/notesSlides/notesSlide\d+\.xml'):
            out += _paragraphs(parts.xml(n), A + 'p', A + 't')
    return '\n'.join(out)


def odf_text(data: bytes) -> str:
    parts = _Parts(data)
    root = parts.xml('content.xml')
    return '\n'.join(''.join(el.itertext()) for el in root.iter() if el.tag in (TEXT_NS + 'p', TEXT_NS + 'h'))


# ------------------------------------------------------------------ RTF
# Groups whose content is not document text (fonts, colours, styles, metadata, pictures, embedded objects).
_RTF_SKIP = {'fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'header', 'footer', 'headerl', 'headerr',
             'footerl', 'footerr', 'listtable', 'listoverridetable', 'rsidtbl', 'generator', 'xmlnstbl', 'themedata',
             'colorschememapping', 'datastore', 'latentstyles', 'filetbl', 'revtbl', 'pgdsctbl'}
_RTF_TOKEN = re.compile(r"\\([a-z]{1,32})(-?\d{1,10})? ?|\\'([0-9a-f]{2})|\\([^a-z])|([{}])|[\r\n]+|([^\\{}\r\n]+)", re.I)
_RTF_BREAKS = {'par': '\n', 'line': '\n', 'sect': '\n', 'page': '\n', 'row': '\n', 'tab': '\t', 'cell': '\t',
               'emdash': '\u2014', 'endash': '\u2013', 'bullet': '\u2022', 'lquote': '\u2018', 'rquote': '\u2019',
               'ldblquote': '\u201c', 'rdblquote': '\u201d'}


def rtf_text(rtf: str) -> str:
    """Document text of an RTF file (decoded as latin-1 so every byte maps to one character)."""
    out: list[str] = []
    stack: list[tuple[bool, int]] = []
    skip, uc, pending_skip = False, 1, 0
    star = False
    for m in _RTF_TOKEN.finditer(rtf):
        word, arg, hexc, sym, brace, text = m.groups()
        if brace == '{':
            stack.append((skip, uc))
            star = False
            continue
        if brace == '}':
            skip, uc = stack.pop() if stack else (False, 1)
            continue
        if pending_skip and (text or hexc):
            # Characters after \uN that stand in for it in readers without Unicode support.
            if text:
                n = min(pending_skip, len(text))
                text, pending_skip = text[n:], pending_skip - n
            else:
                pending_skip -= 1
                continue
        if word:
            w = word.lower()
            if star or w in _RTF_SKIP:
                skip, star = True, False
            elif w == 'uc' and arg:
                uc = int(arg)
            elif w == 'u' and arg is not None:
                if not skip:
                    code = int(arg)
                    out.append(chr(code + 65536 if code < 0 else code))
                pending_skip = uc
            elif w in _RTF_BREAKS and not skip:
                out.append(_RTF_BREAKS[w])
        elif sym:
            if sym == '*':
                star = True
            elif not skip and sym in '\\{}':
                out.append(sym)
            elif not skip and sym == '~':
                out.append('\u00a0')
            elif not skip and sym in '\r\n':
                out.append('\n')
        elif hexc and not skip:
            out.append(bytes([int(hexc, 16)]).decode('cp1252', errors='replace'))
        elif text and not skip:
            out.append(text)
    return ''.join(out)
