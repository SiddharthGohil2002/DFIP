"""Memory images of a case (module `memory`, Volatility 3): the Windows version and capture time, processes and their
tree, network connections, injected code, services and DLLs; and the symbol packs Volatility reads (administrators)."""
import re
import shutil
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from ..core.config import settings
from ..database import get_db
from ..forensic import volatility as vol
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from .malware import _receive

r = APIRouter(prefix='/forensics/memory', tags=['memory images'])
TYPES = {  # type: (sort, fields searched)
    'MEMORY_INFO': ([('evidence_id', 1)], ('windows', 'version', 'product_type')),
    'MEMORY_PROCESS': ([('score', -1), ('created', 1), ('pid', 1)], ('name', 'path', 'cmdline', 'parent_name', 'flags.label')),
    'MEMORY_CONNECTION': ([('score', -1), ('created', 1)], ('local_addr', 'foreign_addr', 'owner', 'state', 'proto')),
    'MEMORY_INJECTION': ([('score', -1), ('pid', 1), ('start', 1)], ('process', 'protection', 'tag')),
    'MEMORY_SERVICE': ([('score', -1), ('name', 1)], ('name', 'display', 'binary', 'binary_registry', 'dll', 'state')),
    'MEMORY_DLL': ([('score', -1), ('pid', 1), ('name', 1)], ('name', 'path', 'process')),
}


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


@r.get('')
def records(case_id: str, type: str, evidence_id: str | None = None, search: str | None = None, notable: bool = False, pid: int | None = None,
            external: bool = False, skip: int = 0, limit: int = 200, u=Depends(current_user)):
    """Records of one type; `notable=true` only those that stand out, `pid` one process's, `external=true` connections to
    internet addresses."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    sort, fields = TYPES[type]
    q: dict = {'case_id': case_id, 'type': type, **({'evidence_id': evidence_id} if evidence_id else {})}
    if notable:
        q['notable'] = True
    if pid is not None:
        q['pid'] = pid
    if external:
        q['external'] = True
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q['$or'] = [{f: rx} for f in fields] + ([{'pid': int(search.strip())}] if search.strip().isdigit() else [])
    col = get_db()['forensic_artifacts']
    rows = [dict(_plain(x), _id=str(x['_id'])) for x in col.find(q).sort(sort).skip(max(0, skip)).limit(max(1, min(limit, 1000)))]
    return {'data': rows, 'total': col.count_documents(q)}


@r.get('/tree')
def tree(case_id: str, evidence_id: str, u=Depends(current_user)):
    """One memory image's processes as a tree (children under the process that started them; a process whose parent is
    gone is at the top), with their flags."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    procs = [dict(_plain(x), _id=str(x['_id'])) for x in get_db()['forensic_artifacts'].find(
        {'case_id': case_id, 'evidence_id': evidence_id, 'type': 'MEMORY_PROCESS'}, {'nk': 0}).sort([('created', 1), ('pid', 1)])]
    by_pid = {p['pid']: dict(p, children=[]) for p in procs}
    roots = []
    for p in by_pid.values():
        parent = by_pid.get(p.get('ppid'))
        (parent['children'] if parent and parent is not p else roots).append(p)
    return {'data': roots, 'total': len(procs)}


@r.get('/status')
def status(u=Depends(current_user)):
    """What memory analysis reads with: the Volatility version, the symbol packs, and whether symbols may be downloaded from
    Microsoft's symbol server."""
    db = get_db()
    job = db['jobs'].find_one({'type': 'MEMORY_SYMBOLS'}, sort=[('created_at', -1)])
    return {'volatility': vol.version(), 'packs': vol.packs(), 'symbol_server': settings.memory_symbol_server,
            'pack_url': settings.memory_symbol_pack_url,
            'download': {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in (job or {}).items()
                         if k in ('job_id', 'status', 'progress', 'stage', 'error', 'created_at', 'finished_at')} or None}


@r.post('/symbols')
async def add_pack(file: UploadFile = File(...), u=Depends(require_write('SYSTEM_MANAGE'))):
    """Adds a symbol pack (a ZIP of ISF files in windows/, linux/ or mac/ folders, such as the Volatility Foundation's
    windows.zip). Anything else in it is refused. A pack of the same name is replaced."""
    name = (file.filename or '').rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
    if not vol.PACK_NAME.match(name) or name == 'packs.json':
        raise HTTPException(400, 'Give a ZIP file with a plain name, such as windows.zip')
    incoming = vol.symbols_dir() / '.incoming'
    incoming.mkdir(exist_ok=True)
    tmp = incoming / name
    size, sha = await _receive(file, tmp, vol.MAX_PACK_BYTES)
    try:
        vol.check_pack(tmp)
    except ValueError as exc:
        tmp.unlink(missing_ok=True)
        raise HTTPException(400, str(exc))
    replaced = (vol.symbols_dir() / name).exists()
    tmp.replace(vol.symbols_dir() / name)
    shutil.rmtree(vol.cache_dir() / 'volatility3', ignore_errors=True)  # Volatility lists the symbol tables again
    info = vol.record_pack(name, vol.symbols_dir() / name, 'upload', u.get('name'))
    log(u, 'MEMORY_SYMBOLS_ADDED', 'symbol_pack', name, {'sha256': sha, 'size': size, 'symbols': info['symbols'], 'replaced': replaced})
    return {'name': name, **info, 'replaced': replaced}


@r.post('/symbols/download')
def download_pack(u=Depends(require_write('SYSTEM_MANAGE'))):
    """Downloads the Windows symbol pack (MEMORY_SYMBOL_PACK_URL) as a job; the server needs internet access."""
    from ..services.jobs import queue
    if not settings.memory_symbol_pack_url:
        raise HTTPException(409, 'No symbol pack address is configured (MEMORY_SYMBOL_PACK_URL)')
    if get_db()['jobs'].find_one({'type': 'MEMORY_SYMBOLS', 'status': {'$in': ['QUEUED', 'RUNNING']}}):
        raise HTTPException(409, 'A symbol pack is already being downloaded')
    job_id = queue.enqueue('MEMORY_SYMBOLS', {'url': settings.memory_symbol_pack_url}, u['_id'])
    log(u, 'MEMORY_SYMBOLS_DOWNLOAD_STARTED', 'symbol_pack', settings.memory_symbol_pack_url, {'job_id': job_id})
    return {'job_id': job_id}


@r.delete('/symbols/{name}')
def delete_pack(name: str, u=Depends(require_write('SYSTEM_MANAGE'))):
    p = vol.symbols_dir() / name
    if not vol.PACK_NAME.match(name) or not p.is_file():
        raise HTTPException(404, 'Symbol pack not found')
    p.unlink()
    vol.forget_pack(name)
    shutil.rmtree(vol.cache_dir() / 'volatility3', ignore_errors=True)  # Volatility's list of symbol tables included the pack
    log(u, 'MEMORY_SYMBOLS_DELETED', 'symbol_pack', name, {})
    return {'deleted': True, 'name': name, 'at': datetime.now(timezone.utc).isoformat()}
