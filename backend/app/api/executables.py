"""Programs (PE files) of a case: what the analysis found in each, why it stands out, and capa on request."""
import re
import shutil
import tempfile
from pathlib import Path

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic import pe
from ..forensic.modules.base import run_tool
from ..forensic.source import TskImageSource, open_entry
from ..forensic.working_image import WorkingCopyUnavailable, analysis_image
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log

r = APIRouter(prefix='/forensics/executables', tags=['executables'])
SIGNATURES = ('valid', 'untrusted', 'expired', 'invalid', 'unsigned', 'error')


def _plain(doc):
    def conv(v):
        if hasattr(v, 'isoformat'):
            return v.isoformat()
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [conv(x) for x in v]
        return v
    out = conv({k: v for k, v in doc.items() if k != '_id'})
    out['_id'] = str(doc['_id'])
    return out


@r.get('')
def programs(case_id: str, evidence_id: str | None = None, flagged: bool | None = None, signature: str | None = None,
             search: str | None = None, skip: int = 0, limit: int = 100, u=Depends(current_user)):
    """Programs, those that stand out most first. flagged=true: at least one serious reason; signature: valid, untrusted,
    expired, invalid, unsigned or error; search: the path, version information or signer."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q: dict = {'case_id': case_id, 'type': 'EXECUTABLE', **({'evidence_id': evidence_id} if evidence_id else {})}
    if flagged is not None:
        q['score'] = {'$gte': 3} if flagged else {'$lt': 3}
    if signature:
        if signature not in SIGNATURES:
            raise HTTPException(400, f'signature must be one of {", ".join(SIGNATURES)}')
        q['signature.status'] = signature
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q['$or'] = [{f: rx} for f in ('path', 'pe.version_info.CompanyName', 'pe.version_info.FileDescription', 'pe.version_info.OriginalFilename',
                                      'pe.version_info.ProductName', 'signature.signers.signer', 'sha256', 'pe.pdb_path')]
    col = get_db()['forensic_artifacts']
    data = [_plain(x) for x in col.find(q, {'pe.imports': 0, 'pe.sections': 0}).sort([('score', -1), ('path', 1)])
            .skip(max(0, skip)).limit(max(1, min(limit, 500)))]
    return {'data': data, 'total': col.count_documents(q)}


def _program(artifact_id, u):
    doc = get_db()['forensic_artifacts'].find_one({'artifact_id': artifact_id, 'type': 'EXECUTABLE'})
    if not doc or not get_case(doc['case_id'], u):
        raise HTTPException(404, 'Program not found or access denied')
    return doc


@r.get('/{artifact_id}')
def program(artifact_id: str, u=Depends(current_user)):
    """One program with its sections, imports, version information, signature chain and capa capabilities."""
    return _plain(_program(artifact_id, u))


@r.post('/{artifact_id}/capa')
def capa(artifact_id: str, u=Depends(require_write('ANALYSIS_RUN'))):
    """Runs capa on the program now (it takes up to a few minutes) and keeps the result with it."""
    doc = _program(artifact_id, u)
    db = get_db()
    entry = db['fs_entries'].find_one({'_id': ObjectId(doc['entry_id'])}) if ObjectId.is_valid(doc.get('entry_id') or '') else None
    evidence = db['evidence'].find_one({'evidence_id': doc['evidence_id']})
    if not entry or not evidence:
        raise HTTPException(409, 'The program is no longer in the file index; analyse the evidence again')
    try:
        image = analysis_image(evidence)
    except WorkingCopyUnavailable as exc:
        raise HTTPException(409, str(exc))
    work = Path(tempfile.mkdtemp(prefix='dfip_capa_'))
    try:
        blob = open_entry(TskImageSource(Path(image)), doc['evidence_id'], entry)
        (work / 'program.bin').write_bytes(blob.read(0, blob.size))
        result = pe.run_capa(work / 'program.bin', run_tool)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    result['ran'] = f'on request by {u.get("name")}'
    db['forensic_artifacts'].update_one({'_id': doc['_id']}, {'$set': {'capa': result}})
    log(u, 'CAPA_RUN', 'evidence', doc['evidence_id'], {'path': doc['path'], 'sha256': doc.get('sha256'), 'status': result.get('status'),
                                                        'capabilities': len(result.get('capabilities') or [])})
    return _plain({**doc, 'capa': result})
