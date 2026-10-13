"""Exports: any table view as CSV or XLSX, and a case as CASE/UCO JSON-LD or its indicators as STIX 2.1 or a MISP event.

A table export names the view by its API path and query (`resource=/api/forensics/executables?case_id=…&flagged=true`).
The view is read with the user's own credentials, page by page, so an export holds exactly what the user can see there.
Cells that a spreadsheet would run as a formula (starting with = + - @, a tab or a carriage return) are prefixed with
an apostrophe. Every export is audited with its SHA-256, which the response also carries."""
import csv
import hashlib
import io
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from ..repositories.cases import get_case
from ..security import require_permission
from ..services.audit import log

r = APIRouter(prefix='/exports', tags=['exports'])
MAX_ROWS = 100_000
PAGE = 1000
MAX_CELL = 32_000  # XLSX holds at most 32,767 characters in a cell
FORMULA_START = ('=', '+', '-', '@', '\t', '\r', '\n', '＝', '＋', '－', '＠')
INTERNAL = {'nk', 'pipeline', 'pipeline_module', 'module_run_id'}
_ILLEGAL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


def safe_cell(v):
    """A value a spreadsheet shows as it is: text that would start a formula gets a leading apostrophe."""
    if isinstance(v, str):
        v = v[:MAX_CELL]
        first = v.lstrip(' ')[:1]
        return "'" + v if first and first in FORMULA_START else v
    if isinstance(v, bool) or v is None or isinstance(v, float):
        return v
    if isinstance(v, int):
        return v if abs(v) < 2 ** 53 else str(v)  # spreadsheets keep 15 significant digits
    return safe_cell(str(v))


def flatten(row: dict) -> dict:
    """Nested records as columns: `pe.version_info.CompanyName`; lists of values joined with '; ', lists of records as JSON."""
    out = {}

    def walk(v, key, depth):
        if isinstance(v, dict) and depth < 3:
            for k, x in v.items():
                if k not in INTERNAL:
                    walk(x, f'{key}.{k}' if key else k, depth + 1)
        elif isinstance(v, list):
            out[key] = '; '.join('' if x is None else str(x) for x in v) if all(not isinstance(x, (dict, list)) for x in v) \
                else json.dumps(v, default=str, ensure_ascii=False)[:MAX_CELL]
        elif isinstance(v, dict):
            out[key] = json.dumps(v, default=str, ensure_ascii=False)[:MAX_CELL]
        else:
            out[key] = v
    walk(row, '', 0)
    return out


def _resource(resource: str) -> tuple[str, list[tuple[str, str]]]:
    if len(resource) > 4000:
        raise HTTPException(400, 'The view address is too long')
    parts = urlsplit(resource)
    path = parts.path
    if parts.scheme or parts.netloc or not path.startswith('/api/') or '..' in path or '//' in path or path.startswith('/api/exports'):
        raise HTTPException(400, 'resource must be a table view of this API, such as /api/forensics/executables?case_id=…')
    params = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=False) if k not in ('skip', 'limit')]
    return path, params


def _filename(path: str, params: list, ext: str) -> str:
    stem = re.sub(r'[^A-Za-z0-9]+', '-', path.removeprefix('/api/')).strip('-')[:60] or 'export'
    case = dict(params).get('case_id')
    when = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    return f'{stem}{"-" + re.sub(r"[^A-Za-z0-9-]", "", case) if case else ""}-{when}.{ext}'


async def _fetch_rows(request: Request, path: str, params: list, spool) -> tuple[list[str], int, bool]:
    """The view's rows, read page by page with the caller's credentials, flattened and spooled as JSON lines. Returns the
    columns (in order of first appearance), the row count and whether MAX_ROWS cut it short."""
    import httpx
    headers = {k: v for k, v in request.headers.items() if k.lower() in ('authorization', 'x-dfip-device-token')}
    columns: dict[str, None] = {}
    n, skip, truncated = 0, 0, False
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=request.app), base_url='http://dfip.internal', timeout=600) as client:
        while True:
            res = await client.get(path, params=params + [('skip', str(skip)), ('limit', str(PAGE))], headers=headers)
            if res.status_code >= 400:
                try:
                    detail = res.json().get('detail')
                except ValueError:
                    detail = res.text[:300]
                raise HTTPException(res.status_code, detail if isinstance(detail, str) else 'The view could not be read')
            if 'application/json' not in res.headers.get('content-type', ''):
                raise HTTPException(400, 'This view is not a table')
            body = res.json()
            rows = body if isinstance(body, list) else body.get('data') if isinstance(body, dict) else None
            if not isinstance(rows, list):
                raise HTTPException(400, 'This view is not a table')
            for row in rows:
                if n >= MAX_ROWS:
                    truncated = True
                    break
                flat = flatten(row if isinstance(row, dict) else {'value': row})
                for k in flat:
                    columns.setdefault(k, None)
                spool.write(json.dumps(flat, default=str, ensure_ascii=False) + '\n')
                n += 1
            total = body.get('total') if isinstance(body, dict) else None
            skip += len(rows)
            if truncated or not rows or not isinstance(total, int) or skip >= total:
                truncated = truncated or (isinstance(total, int) and n < total and n >= MAX_ROWS)
                break
    return list(columns), n, truncated


def _write_csv(spool_path: str, columns: list[str], out_path: str):
    with open(spool_path, encoding='utf-8') as src, open(out_path, 'w', encoding='utf-8-sig', newline='') as out:
        w = csv.writer(out)
        w.writerow([safe_cell(c) for c in columns])
        for line in src:
            row = json.loads(line)
            w.writerow(['' if row.get(c) is None else safe_cell(row.get(c)) for c in columns])


def _write_xlsx(spool_path: str, columns: list[str], out_path: str, title: str):
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font
    wb = Workbook(write_only=True)
    ws = wb.create_sheet(re.sub(r'[\[\]:*?/\\]', '-', title)[:31] or 'Export')
    ws.freeze_panes = 'A2'

    def cell(v, bold=False):
        v = safe_cell(v)
        c = WriteOnlyCell(ws, value=_ILLEGAL.sub('', v) if isinstance(v, str) else v)
        if isinstance(v, str):
            c.data_type = 's'  # text, never a formula
        if bold:
            c.font = Font(bold=True)
        return c
    ws.append([cell(c, bold=True) for c in columns])
    with open(spool_path, encoding='utf-8') as src:
        for line in src:
            row = json.loads(line)
            ws.append([cell(row.get(c)) for c in columns])
    wb.save(out_path)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _stream(path: str):
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            yield chunk


@r.get('/table')
async def export_table(request: Request, resource: str, format: str = 'csv', u=Depends(require_permission('REPORT_EXPORT'))):
    """A table view as CSV (UTF-8, Excel-ready) or XLSX: every row the view lists for the user (up to 100,000), every field
    as a column, formulas defused. The response carries the SHA-256 and row count; the export is audited."""
    if format not in ('csv', 'xlsx'):
        raise HTTPException(400, 'format must be csv or xlsx')
    path, params = _resource(resource)
    fd, spool_path = tempfile.mkstemp(prefix='dfip-export-', suffix='.jsonl')
    out_fd, out_path = tempfile.mkstemp(prefix='dfip-export-', suffix=f'.{format}')
    os.close(out_fd)

    def cleanup():
        for p in (spool_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as spool:
            columns, n, truncated = await _fetch_rows(request, path, params, spool)
        if format == 'csv':
            await run_in_threadpool(_write_csv, spool_path, columns, out_path)
        else:
            await run_in_threadpool(_write_xlsx, spool_path, columns, out_path, path.removeprefix('/api/'))
        sha = await run_in_threadpool(_sha256, out_path)
    except BaseException:
        cleanup()
        raise
    name = _filename(path, params, format)
    case_id = dict(params).get('case_id')
    await run_in_threadpool(log, u, 'EXPORT_DOWNLOADED', 'case' if case_id else 'export', case_id or path,
                            {'resource': path, 'params': dict(params), 'format': format, 'rows': n, 'columns': len(columns),
                             'truncated': truncated, 'sha256': sha, 'filename': name})
    media = 'text/csv; charset=utf-8' if format == 'csv' else 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return StreamingResponse(_stream(out_path), media_type=media, background=BackgroundTask(cleanup), headers={
        'Content-Disposition': f'attachment; filename="{name}"', 'X-DFIP-Export-SHA256': sha, 'X-DFIP-Export-Rows': str(n),
        'X-DFIP-Export-Truncated': 'true' if truncated else 'false', 'X-Content-Type-Options': 'nosniff'})


def _case(case_id: str, u) -> dict:
    case = get_case(case_id, u)
    if not case:
        raise HTTPException(404, 'Case not found or access denied')
    return case


def _download(data: bytes, media: str, name: str, u, action: str, case_id: str, details: dict) -> Response:
    sha = hashlib.sha256(data).hexdigest()
    log(u, action, 'case', case_id, {**details, 'sha256': sha, 'filename': name})
    return Response(content=data, media_type=media, headers={'Content-Disposition': f'attachment; filename="{name}"',
                                                             'X-DFIP-Export-SHA256': sha, 'X-Content-Type-Options': 'nosniff'})


@r.get('/cases/{case_id}/case-uco')
def export_case_uco(case_id: str, u=Depends(require_permission('REPORT_EXPORT'))):
    """The case as CASE/UCO JSON-LD (ontology 1.4): evidence with hashes and exhibit numbers, the investigative actions on
    it from the chain of custody and the analyses, recovered files, and approved findings."""
    from ..services.case_uco import export
    _case(case_id, u)
    doc = export(case_id, u)
    data = json.dumps(doc, indent=1, ensure_ascii=False).encode('utf-8')
    return _download(data, 'application/ld+json', f'{case_id}-case-uco.jsonld', u, 'CASE_EXPORTED', case_id,
                     {'format': 'case-uco', 'nodes': len(doc['@graph'])})


def _tlp(tlp: str) -> str:
    from ..services.ioc_export import TLP
    if tlp not in TLP:
        raise HTTPException(400, f'tlp must be one of {", ".join(TLP)}')
    return tlp


@r.get('/cases/{case_id}/iocs')
def case_iocs(case_id: str, u=Depends(require_permission('REPORT_EXPORT'))):
    """The indicators the STIX and MISP exports would hold, with why each is included and the records behind it."""
    from ..services.ioc_export import collect
    _case(case_id, u)
    return {'data': collect(case_id)}


@r.get('/cases/{case_id}/stix')
def export_stix(case_id: str, tlp: str = 'amber', u=Depends(require_permission('REPORT_EXPORT'))):
    """The case's indicators as a STIX 2.1 bundle: the exporting system's identity, one indicator per file hash, URL,
    domain or address (malicious-activity or anomalous-activity, with the reasons), and a report that lists them."""
    from ..services.ioc_export import collect, stix_bundle
    case = _case(case_id, u)
    items = collect(case_id)
    data = stix_bundle(case, items, _tlp(tlp), u).encode('utf-8')
    return _download(data, 'application/stix+json;version=2.1', f'{case_id}-indicators.stix.json', u, 'IOC_EXPORTED', case_id,
                     {'format': 'stix-2.1', 'tlp': tlp, 'indicators': len(items)})


@r.get('/cases/{case_id}/misp')
def export_misp(case_id: str, tlp: str = 'amber', u=Depends(require_permission('REPORT_EXPORT'))):
    """The case's indicators as a MISP event (JSON for MISP's event import): file hashes as Payload delivery attributes,
    URLs, domains and addresses as Network activity; malicious ones marked for IDS."""
    from ..services.ioc_export import collect, misp_event
    case = _case(case_id, u)
    items = collect(case_id)
    data = json.dumps(misp_event(case, items, _tlp(tlp), u), indent=1, ensure_ascii=False).encode('utf-8')
    return _download(data, 'application/json', f'{case_id}-indicators.misp.json', u, 'IOC_EXPORTED', case_id,
                     {'format': 'misp', 'tlp': tlp, 'indicators': len(items)})
