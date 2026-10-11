from fastapi import APIRouter,Depends,HTTPException
from fastapi.responses import Response
from fastapi.responses import FileResponse
from datetime import datetime,timezone
from pathlib import Path
import base64,re,uuid
from ..forensic import content
from ..forensic.filesystem import INODE_RE
from ..forensic.source import offset_of
from ..forensic.hashing import sha256_file
from ..forensic.working_image import analysis_image,WorkingCopyUnavailable
from ..repositories.cases import allowed_case_query
from ..security import current_user, require_permission, require_write
from ..database import get_db
from ..repositories.evidence import get_evidence
from ..repositories.cases import get_case
from ..forensic.engine import ForensicEngine,extract_demo_artifacts
from ..analysis.services import compute_patterns,compute_anomalies
from ..ai.services import AIService
from ..services.audit import log
from ..forensic.tools import inventory,parse_mmls,parse_filesystem,filesystem_stats,inode_stat,recover_file,inspect_file,scan_yara,extract_strings,inspect_pcap,inspect_memory
from ..core.config import settings
from ..websocket.manager import manager
r=APIRouter(prefix='/forensics',tags=['forensics'])

def auth_evidence(eid,u):
    e=get_evidence(eid)
    if not e or not get_case(e['case_id'],u): raise HTTPException(404,'Evidence not found or access denied')
    return e

def tsk_image(e,create=False):
    """The image the Sleuth Kit reads: the original, or for E01 its verified raw working copy (see forensic/working_image.py)."""
    if not Path(e['storage_path']).exists(): raise HTTPException(409,'Original evidence object is unavailable')
    try:
        return analysis_image(e,create=create,db=get_db(),actor='DFIP')
    except WorkingCopyUnavailable as exc:
        raise HTTPException(409,str(exc))

def _volume_offset(offset:int,volume_id:str|None)->int:
    """The partition start sector from a volume id ('p2048'); the older `offset=` parameter still works."""
    if volume_id is None: return offset
    try: return offset_of(volume_id)
    except ValueError: raise HTTPException(400,'Invalid volume id')

def serial(v):
    if hasattr(v,'isoformat'): return v.isoformat()
    if isinstance(v,dict): return {k:serial(x) for k,x in v.items()}
    if isinstance(v,list): return [serial(x) for x in v]
    return v

@r.get('/tooling')
def tooling(u=Depends(current_user)):
    from ..forensic.carving import engine_availability
    return {'data':{**inventory(),**{f'carving_{k}':v for k,v in engine_availability().items()}}}

@r.post('/evidence/{eid}/analyze')
def analyze(eid,u=Depends(require_write('ANALYSIS_RUN'))):
    e=auth_evidence(eid,u)
    if e.get('demo'): return {'status':'DEMO','evidence_id':e['evidence_id'],'case_id':e['case_id'],'engine':'DFIP Demo Engine','limitations':['Synthetic demo evidence cannot be parsed as a real image.']}
    path=tsk_image(e)
    manager.emit_sync('ANALYSIS_STARTED', {'evidence_id': e['evidence_id'], 'case_id': e['case_id']})
    result=ForensicEngine().analyze(path,e['format'])
    get_db()['forensic_artifacts'].insert_one({'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':'ANALYSIS_RUN','timestamp':datetime.now(timezone.utc),'data':result,'source':'DFIP_ENGINE'})
    log(u,'ANALYSIS_COMPLETED','evidence',e['_id'],{'engine':result['engine']})
    manager.emit_sync('ANALYSIS_COMPLETED', {'evidence_id': e['evidence_id'], 'case_id': e['case_id'], 'engine': result['engine']})
    return serial(dict(result,evidence_id=e['evidence_id'],case_id=e['case_id']))

@r.post('/evidence/{eid}/examine')
def examine(eid:str,offset:int=0,u=Depends(require_write('ANALYSIS_RUN'))):
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be examined as a real image')
    path=tsk_image(e)
    parts=parse_mmls(path); fs=parse_filesystem(path,e['format'],offset); stats=filesystem_stats(path,offset)
    now=datetime.now(timezone.utc)
    docs=[]
    for p in parts.get('partitions',[]): docs.append({'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':'PARTITION','timestamp':now,'data':p,'source':'SLEUTH_KIT'})
    for a in fs.get('artifacts',[]): docs.append({'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':'FILESYSTEM_ENTRY','timestamp':now,'data':a,'source':'SLEUTH_KIT'})
    if docs: get_db()['forensic_artifacts'].insert_many(docs)
    log(u,'FORENSIC_EXAMINATION','evidence',e['_id'],{'offset':offset,'partitions':len(parts.get('partitions',[])),'filesystem_entries':len(fs.get('artifacts',[]))})
    manager.emit_sync('ARTIFACT_BATCH_CREATED', {'case_id': e['case_id'], 'evidence_id': e['evidence_id'], 'count': len(docs)})
    return serial({'evidence_id':e['evidence_id'],'offset':offset,'partitions':parts,'filesystem':fs,'filesystem_stats':stats,'persisted_artifacts':len(docs)})

@r.get('/evidence/{eid}/partitions')
def partitions(eid,u=Depends(current_user)):
    e=auth_evidence(eid,u)
    if e.get('demo'): return {'data':[],'warning':'Synthetic demo evidence'}
    return serial(parse_mmls(tsk_image(e)))

@r.post('/evidence/{eid}/istat')
def istat(eid:str,inode:str,offset:int=0,u=Depends(require_write('ANALYSIS_RUN'))):
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be examined')
    if not INODE_RE.match(inode): raise HTTPException(400,'Invalid inode address')
    return serial(inode_stat(tsk_image(e),inode,offset))

@r.get('/evidence/{eid}/files')
def files(eid:str,deleted:bool|None=None,q:str|None=None,offset:int|None=None,volume_id:str|None=None,category:str|None=None,
          renamed:bool|None=None,encrypted:bool|None=None,hash_status:str|None=None,hide_known:bool=False,sha256:str|None=None,
          members:bool=False,skip:int=0,limit:int=200,u=Depends(current_user)):
    """Filesystem index built by the analysis pipeline (Sleuth Kit fls), with each file's hashes, type and flags."""
    e=auth_evidence(eid,u)
    # Files of the file systems, or (members=true) files taken out of archives and documents on them.
    query={'evidence_id':e['evidence_id'],'is_virtual':False,'container':{'$exists':members}}
    if deleted is not None: query['deleted']=deleted
    if category: query['file_category']=category
    if renamed is not None: query['ext_mismatch']=True if renamed else {'$ne':True}
    if encrypted is not None: query['encryption']={'$ne':None,'$exists':True} if encrypted else {'$in':[None]}
    if hash_status: query['hash_status']=hash_status
    if hide_known: query['hash_status']={'$ne':'KNOWN_GOOD'} if not hash_status else hash_status
    if sha256: query['sha256']=sha256.strip().lower()
    if volume_id is not None: offset=_volume_offset(0,volume_id)
    if offset is not None: query['partition_offset']=offset
    if q: query['path']={'$regex':re.escape(q),'$options':'i'}
    limit=max(1,min(limit,1000))
    col=get_db()['fs_entries']
    rows=[serial(dict(x,_id=str(x['_id']))) for x in col.find(query).sort([('deleted',-1),('path',1)]).skip(max(0,skip)).limit(limit)]
    return {'data':rows,'total':col.count_documents(query),'skip':skip,'limit':limit,
            'analysis_status':e.get('analysis_status'),'summary':e.get('analysis_summary')}

_HASH_FIELD={32:'md5',40:'sha1',64:'sha256'}


def _hash_query(term:str):
    """{field: digest} when the term is an MD5, SHA-1 or SHA-256 in hex, else None."""
    t=term.strip().lower()
    return {_HASH_FIELD[len(t)]:t} if len(t) in _HASH_FIELD and re.fullmatch(r'[0-9a-f]+',t) else None


@r.get('/hash')
def hash_occurrences(case_id:str,digest:str,u=Depends(current_user)):
    """Every file in the case with this content (MD5, SHA-1 or SHA-256), in the file index and among recovered and carved files."""
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    hq=_hash_query(digest)
    if not hq: raise HTTPException(400,'Give an MD5, SHA-1 or SHA-256 in hexadecimal')
    db=get_db()
    eids=[x['evidence_id'] for x in db['evidence'].find({'case_id':case_id},{'evidence_id':1})]
    files=[serial(dict(x,_id=str(x['_id']))) for x in db['fs_entries'].find({'evidence_id':{'$in':eids},**hq},
           {'path':1,'evidence_id':1,'inode':1,'volume_id':1,'partition_offset':1,'deleted':1,'size':1,'md5':1,'sha1':1,'sha256':1}).limit(500)]
    arts=[] if 'sha256' not in hq else [serial(dict(x,_id=str(x['_id']))) for x in db['forensic_artifacts'].find(
           {'case_id':case_id,'sha256':hq['sha256'],'type':{'$in':['RECOVERED_FILE','CARVED_FILE','EXTRACTED_FILE']}},
           {'artifact_id':1,'type':1,'filename':1,'original_path':1,'evidence_id':1,'size':1}).limit(500)]
    return {'digest':digest.lower(),'algorithm':next(iter(hq)),'files':files,'artifacts':arts}


FLAG_QUERIES={'renamed':{'ext_mismatch':True},'encrypted':{'encryption':{'$ne':None,'$exists':True}},
              'known_bad':{'hash_status':'KNOWN_BAD'},'notable':{'hash_status':'NOTABLE'}}


@r.get('/flagged')
def flagged(case_id:str,kind:str,limit:int=500,u=Depends(current_user)):
    """Files of the case flagged as renamed (content does not match the name), encrypted, known-bad or notable."""
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    if kind not in FLAG_QUERIES: raise HTTPException(400,f'kind must be one of {", ".join(FLAG_QUERIES)}')
    db=get_db()
    eids=[x['evidence_id'] for x in db['evidence'].find({'case_id':case_id},{'evidence_id':1})]
    q={'evidence_id':{'$in':eids},'is_virtual':False,**FLAG_QUERIES[kind]}
    rows=[serial(dict(x,_id=str(x['_id']))) for x in db['fs_entries'].find(q).sort('path',1).limit(max(1,min(limit,2000)))]
    return {'data':rows,'total':db['fs_entries'].count_documents(q)}


@r.post('/evidence/{eid}/recover')
def recover(eid:str,inode:str,offset:int=0,volume_id:str|None=None,u=Depends(require_write('ANALYSIS_RUN'))):
    offset=_volume_offset(offset,volume_id)
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be recovered')
    if not INODE_RE.match(inode): raise HTTPException(400,'Invalid inode address')
    entry=get_db()['fs_entries'].find_one({'evidence_id':e['evidence_id'],'inode':inode,'partition_offset':offset,'container':{'$exists':False}})
    image=tsk_image(e); aid=str(uuid.uuid4())
    original=entry['path'] if entry else None
    # Keep the original file name (in a per-recovery folder) so viewers and parsers can use it.
    name=Path(original).name if original else f'inode-{inode}.bin'
    dest=Path(settings.storage_path).resolve()/'analysis'/'recovered'/e['evidence_id']/aid/name
    result=recover_file(image,inode,dest,offset)
    if result.get('status')!='COMPLETED': return result
    digest=sha256_file(dest); size=dest.stat().st_size
    dest.chmod(0o440)
    now=datetime.now(timezone.utc)
    doc={'artifact_id':aid,'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':'RECOVERED_FILE','timestamp':now,'path':str(dest),'filename':name,
         'original_path':original,'was_deleted':bool(entry and entry.get('deleted')),'inode':inode,'offset':offset,'size':size,'sha256':digest,'source':'SLEUTH_KIT_ICAT'}
    get_db()['forensic_artifacts'].insert_one(doc); log(u,'FILE_RECOVERED','evidence',e['_id'],{'artifact_id':aid,'inode':inode,'original_path':original,'sha256':digest})
    get_db()['chain_of_custody'].insert_one({'evidence_id':e['evidence_id'],'case_id':e['case_id'],'timestamp':now,'user_id':str(u['_id']),'user_name':u.get('name'),
                                             'action':'FILE_RECOVERED','artifact_id':aid,'original_path':original,'inode':inode,'sha256':digest})
    manager.emit_sync('ARTIFACT_CREATED', {'artifact_id': aid, 'case_id': e['case_id'], 'type': 'RECOVERED_FILE', 'filename': name})
    return serial({'status':'COMPLETED','artifact_id':aid,'size':size,'sha256':digest,'filename':name,'original_path':original,'was_deleted':doc['was_deleted']})

@r.get('/artifacts/{artifact_id}/download')
def download_artifact(artifact_id:str,u=Depends(require_permission('EVIDENCE_READ'))):
    """Downloads a recovered/extracted file; the SHA-256 recorded at recovery is sent as a header."""
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u) or not a.get('path'): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a['path']); root=Path(settings.storage_path).resolve()/'analysis'
    if not p.is_file() or root not in p.resolve().parents: raise HTTPException(410,'Artifact file unavailable')
    log(u,'ARTIFACT_DOWNLOADED','artifact',artifact_id,{'sha256':a.get('sha256')})
    return FileResponse(str(p),filename=a.get('filename') or p.name,media_type='application/octet-stream',headers={'X-DFIP-SHA256':a.get('sha256','')})

# ---------------------------------------------------------------- file content: hex viewer and preview
def _image_file(eid, inode, offset, u):
    """An indexed file inside an evidence image, and the command that streams its content."""
    e = auth_evidence(eid, u)
    if e.get('demo'): raise HTTPException(400, 'Demo evidence has no file content')
    if not INODE_RE.match(inode or ''): raise HTTPException(400, 'Invalid inode address')
    entry = get_db()['fs_entries'].find_one({'evidence_id': e['evidence_id'], 'inode': inode, 'partition_offset': offset,
                                             'container': {'$exists': False}})
    if not entry: raise HTTPException(404, 'File not found in the file index')
    if entry.get('is_dir') or entry.get('is_virtual'): raise HTTPException(400, 'Folders and filesystem metadata entries cannot be viewed')
    image = tsk_image(e)
    cmd = ['icat', '-o', str(offset), str(image), inode]

    def read(start, length):
        if start > content.STREAM_SKIP_MAX:
            raise HTTPException(416, 'Recover the file to view it beyond 256 MiB')
        try:
            return content.read_stream_range(cmd, start, length)
        except content.Busy:
            raise HTTPException(503, 'Too many files are being read at once; try again in a moment')
        except TimeoutError:
            raise HTTPException(504, 'Reading the file from the image took too long')
    return e, entry.get('path'), entry.get('size') or 0, read, {'evidence_id': e['evidence_id'], 'inode': inode, 'offset': offset, 'path': entry.get('path')}


def _artifact_file(artifact_id, u):
    """A recovered, carved or extracted file stored by DFIP."""
    a = get_db()['forensic_artifacts'].find_one({'artifact_id': artifact_id})
    if not a or not get_case(a['case_id'], u) or not a.get('path'): raise HTTPException(404, 'Artifact not found or access denied')
    p = Path(a['path']); root = Path(settings.storage_path).resolve() / 'analysis'
    if not p.is_file() or root not in p.resolve().parents: raise HTTPException(410, 'Artifact file unavailable')
    return a, a.get('original_path') or a.get('filename') or p.name, p.stat().st_size, \
        (lambda start, length: content.read_file_range(p, start, length)), {'artifact_id': artifact_id, 'path': a.get('original_path')}


def _page(target, start, length, u, resource):
    e, path, size, read, meta = target
    if start < 0 or length < 1: raise HTTPException(400, 'start must be 0 or more and length at least 1')
    data = read(start, min(length, content.PAGE_MAX))
    if start == 0:
        log(u, 'FILE_CONTENT_VIEWED', resource, meta.get('artifact_id') or e['_id'], {**meta, 'view': 'hex'})
    return {'path': path, 'start': start, 'length': len(data), 'size': size, 'eof': start + len(data) >= size,
            'data_b64': base64.b64encode(data).decode()}


def _preview(target, u, resource):
    e, path, size, read, meta = target
    head = read(0, content.TEXT_MAX + 1)
    kind, mime = content.sniff(head)
    out = {'path': path, 'size': size, 'kind': kind, 'mime': mime}
    if kind == 'text':
        out['text'], out['encoding'] = content.decode_text(head[:content.TEXT_MAX])
        out['truncated'] = size > content.TEXT_MAX
    elif kind in ('image', 'pdf'):
        out['renderable'] = size <= content.RAW_MAX
    log(u, 'FILE_CONTENT_VIEWED', resource, meta.get('artifact_id') or e['_id'], {**meta, 'view': 'preview', 'kind': kind})
    return out


def _raw(target, u, resource):
    e, path, size, read, meta = target
    if size > content.RAW_MAX: raise HTTPException(413, 'File is too large to preview; download it instead')
    data = read(0, size)
    kind, mime = content.sniff(data[:8192])
    if kind not in ('image', 'pdf'): raise HTTPException(415, 'Only images and PDF files are rendered; other files are shown as text or hex')
    log(u, 'FILE_CONTENT_VIEWED', resource, meta.get('artifact_id') or e['_id'], {**meta, 'view': 'render', 'kind': kind})
    return Response(content=data, media_type=mime, headers={
        'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment',
        'Content-Security-Policy': "sandbox; default-src 'none'", 'Cache-Control': 'no-store'})


@r.get('/evidence/{eid}/content')
def evidence_content(eid: str, inode: str, offset: int = 0, volume_id: str | None = None, start: int = 0, length: int = 4096,
                     u=Depends(require_permission('EVIDENCE_READ'))):
    """One page of a file inside the image (base64), for the hex viewer."""
    return _page(_image_file(eid, inode, _volume_offset(offset, volume_id), u), start, length, u, 'evidence')


@r.get('/evidence/{eid}/preview')
def evidence_preview(eid: str, inode: str, offset: int = 0, volume_id: str | None = None, u=Depends(require_permission('EVIDENCE_READ'))):
    """What the file is (from its first bytes) and, for text, its content."""
    return _preview(_image_file(eid, inode, _volume_offset(offset, volume_id), u), u, 'evidence')


@r.get('/evidence/{eid}/raw')
def evidence_raw(eid: str, inode: str, offset: int = 0, volume_id: str | None = None, u=Depends(require_permission('EVIDENCE_READ'))):
    """An image or PDF inside the image, for rendering in the preview."""
    return _raw(_image_file(eid, inode, _volume_offset(offset, volume_id), u), u, 'evidence')


@r.get('/artifacts/{artifact_id}/content')
def artifact_content(artifact_id: str, start: int = 0, length: int = 4096, u=Depends(require_permission('EVIDENCE_READ'))):
    return _page(_artifact_file(artifact_id, u), start, length, u, 'artifact')


@r.get('/artifacts/{artifact_id}/preview')
def artifact_preview(artifact_id: str, u=Depends(require_permission('EVIDENCE_READ'))):
    return _preview(_artifact_file(artifact_id, u), u, 'artifact')


@r.get('/artifacts/{artifact_id}/raw')
def artifact_raw(artifact_id: str, u=Depends(require_permission('EVIDENCE_READ'))):
    return _raw(_artifact_file(artifact_id, u), u, 'artifact')


# ---------------------------------------------------------------- files taken out of archives and documents
def _member_doc(entry_id: str, u) -> tuple[dict, dict]:
    from bson import ObjectId
    doc = get_db()['fs_entries'].find_one({'_id': ObjectId(entry_id), 'container': {'$exists': True}}) if ObjectId.is_valid(entry_id) else None
    if not doc: raise HTTPException(404, 'Archive member not found')
    return auth_evidence(doc['evidence_id'], u), doc


def _member_file(entry_id: str, u):
    """A member taken out of an archive or document on the evidence (stored under a generated name)."""
    from ..forensic.source import member_path
    e, doc = _member_doc(entry_id, u)
    c = doc['container']
    if not c.get('store'): raise HTTPException(409, f"This member was not extracted: {c.get('note') or 'encrypted'}")
    p = member_path(doc)
    if not p.is_file(): raise HTTPException(410, 'The member content is no longer stored; run Archives and embedded files again')
    return e, doc['path'], p.stat().st_size, (lambda start, length: content.read_file_range(p, start, length)), \
        {'evidence_id': e['evidence_id'], 'member': entry_id, 'path': doc['path']}


@r.get('/members/{entry_id}/content')
def member_content(entry_id: str, start: int = 0, length: int = 4096, u=Depends(require_permission('EVIDENCE_READ'))):
    return _page(_member_file(entry_id, u), start, length, u, 'member')


@r.get('/members/{entry_id}/preview')
def member_preview(entry_id: str, u=Depends(require_permission('EVIDENCE_READ'))):
    return _preview(_member_file(entry_id, u), u, 'member')


@r.get('/members/{entry_id}/raw')
def member_raw(entry_id: str, u=Depends(require_permission('EVIDENCE_READ'))):
    return _raw(_member_file(entry_id, u), u, 'member')


@r.post('/members/{entry_id}/recover')
def recover_member(entry_id: str, u=Depends(require_write('ANALYSIS_RUN'))):
    """Copies an archive member out as a recovered file: hashed, recorded in the chain of custody, downloadable."""
    import shutil
    e, path, size, _, _ = _member_file(entry_id, u)
    _, doc = _member_doc(entry_id, u)
    from ..forensic.source import member_path
    aid = str(uuid.uuid4())
    name = doc.get('name') or 'member.bin'
    dest = Path(settings.storage_path).resolve() / 'analysis' / 'recovered' / e['evidence_id'] / aid / Path(name).name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(member_path(doc), dest)
    digest = sha256_file(dest)
    dest.chmod(0o440)
    if doc.get('sha256') and digest != doc['sha256']:
        raise HTTPException(409, 'The stored member no longer matches its recorded SHA-256')
    now = datetime.now(timezone.utc)
    art = {'artifact_id': aid, 'case_id': e['case_id'], 'evidence_id': e['evidence_id'], 'type': 'RECOVERED_FILE', 'timestamp': now,
           'path': str(dest), 'filename': dest.name, 'original_path': doc['path'], 'was_deleted': bool(doc.get('deleted')),
           'inode': doc.get('inode'), 'offset': doc.get('partition_offset'), 'size': size, 'sha256': digest, 'source': 'CONTAINER_MEMBER',
           'container': {'parent': doc['container'].get('parent'), 'member': doc['container'].get('member'), 'kind': doc['container'].get('kind')}}
    get_db()['forensic_artifacts'].insert_one(art)
    log(u, 'FILE_RECOVERED', 'evidence', e['_id'], {'artifact_id': aid, 'original_path': doc['path'], 'sha256': digest, 'member': True})
    get_db()['chain_of_custody'].insert_one({'evidence_id': e['evidence_id'], 'case_id': e['case_id'], 'timestamp': now, 'user_id': str(u['_id']),
                                             'user_name': u.get('name'), 'action': 'FILE_RECOVERED', 'artifact_id': aid,
                                             'original_path': doc['path'], 'inode': doc.get('inode'), 'sha256': digest})
    manager.emit_sync('ARTIFACT_CREATED', {'artifact_id': aid, 'case_id': e['case_id'], 'type': 'RECOVERED_FILE', 'filename': dest.name})
    return serial({'status': 'COMPLETED', 'artifact_id': aid, 'size': size, 'sha256': digest, 'filename': dest.name,
                   'original_path': doc['path'], 'was_deleted': art['was_deleted']})


# ---------------------------------------------------------------- raw bytes of a volume (unallocated-space hits)
@r.get('/evidence/{eid}/volume')
def volume_content(eid: str, volume_id: str, start: int = 0, length: int = 4096, u=Depends(require_permission('EVIDENCE_READ'))):
    """One page of a volume's raw bytes (base64) at a byte offset within the volume, for the hex viewer. Every
    page read is recorded in the audit log."""
    e = auth_evidence(eid, u)
    if e.get('demo'): raise HTTPException(400, 'Demo evidence has no content')
    try:
        sector = offset_of(volume_id)
    except ValueError:
        raise HTTPException(400, 'Unknown volume')
    if start < 0 or length < 1: raise HTTPException(400, 'start must be 0 or more and length at least 1')
    image = Path(tsk_image(e))
    facts = get_db()['analysis_facts'].find_one({'evidence_id': e['evidence_id']}) or {}
    part = next((p for p in (facts.get('fs_index') or {}).get('partitions', []) if p.get('start') == sector), None)
    size = int(part['length']) * 512 if part and part.get('length') else image.stat().st_size - sector * 512
    with image.open('rb') as f:
        f.seek(sector * 512 + min(start, size))
        data = f.read(max(0, min(length, content.PAGE_MAX, size - start)))
    log(u, 'FILE_CONTENT_VIEWED', 'volume', e['_id'], {'evidence_id': e['evidence_id'], 'volume_id': volume_id, 'start': start, 'view': 'hex'})
    return {'path': f'Volume {volume_id}', 'start': start, 'length': len(data), 'size': size, 'eof': start + len(data) >= size,
            'data_b64': base64.b64encode(data).decode()}


@r.get('/usb')
def usb_devices(case_id:str,evidence_id:str|None=None,u=Depends(current_user)):
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    q={'case_id':case_id}
    if evidence_id: q['evidence_id']=evidence_id
    return {'data':[serial(dict(x,_id=str(x['_id']))) for x in get_db()['usb_artifacts'].find(q).sort('first_install',1)]}

# Windows activity records (forensic_artifacts types) and the time each list is sorted by, newest first.
ACTIVITY_SORT={'PROGRAM_RUN':'last_run','RECENT_FILE':'lnk_modified','RECYCLE_BIN_ITEM':'deleted_time'}

def _activity_text(rx):
    return [{'executable':rx},{'executable_path':rx},{'target_path':rx},{'original_path':rx},{'volume_label':rx},{'referenced_files':rx}]

@r.get('/activity')
def activity(case_id:str,kind:str='PROGRAM_RUN',evidence_id:str|None=None,search:str|None=None,skip:int=0,limit:int=500,u=Depends(current_user)):
    """Windows activity: programs run (Prefetch), recently opened files (Recent shortcuts), Recycle Bin items."""
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    if kind not in ACTIVITY_SORT: raise HTTPException(400,f'Invalid kind; use one of {", ".join(ACTIVITY_SORT)}')
    q={'case_id':case_id,'type':kind}
    if evidence_id: q['evidence_id']=evidence_id
    if search: q['$or']=_activity_text({'$regex':re.escape(search),'$options':'i'})
    col=get_db()['forensic_artifacts']
    rows=[serial(dict(x,_id=str(x['_id']))) for x in col.find(q).sort(ACTIVITY_SORT[kind],-1).skip(max(0,skip)).limit(max(1,min(limit,1000)))]
    names=account_names(get_db(),{r['evidence_id'] for r in rows})
    for row in rows:
        if row.get('sid'): row['user_name']=names.get((row['evidence_id'],row['sid']))
    return {'data':rows,'total':col.count_documents(q)}


def account_names(db,evidence_ids)->dict:
    """User names of the accounts found on these evidence items, by (evidence_id, SID)."""
    out={}
    for a in db['forensic_artifacts'].find({'evidence_id':{'$in':list(evidence_ids)},'type':'USER_ACCOUNT','sid':{'$ne':None}},
                                           {'evidence_id':1,'sid':1,'username':1}):
        out[(a['evidence_id'],a['sid'])]=a.get('username')
    return out


@r.get('/computer')
def computer(case_id:str,evidence_id:str|None=None,u=Depends(current_user)):
    """Per evidence item: the computer (name, Windows version, network, last shutdown, time zone) and its user accounts."""
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    db=get_db(); out=[]
    q={'case_id':case_id}
    if evidence_id: q['evidence_id']=evidence_id
    for e in db['evidence'].find(q,{'evidence_id':1,'filename':1}).sort('created_at',1):
        eid=e['evidence_id']
        info=db['forensic_artifacts'].find_one({'evidence_id':eid,'type':'COMPUTER_INFO'})
        users=list(db['forensic_artifacts'].find({'evidence_id':eid,'type':'USER_ACCOUNT'}).sort([('source',-1),('rid',1),('username',1)]))
        facts=(db['analysis_facts'].find_one({'evidence_id':eid},{'tz_probe':1}) or {}).get('tz_probe') or {}
        if not info and not users and not facts: continue
        out.append(serial({'evidence_id':eid,'filename':e.get('filename'),
                           'computer':info and dict(info,_id=str(info['_id'])),
                           'accounts':[dict(x,_id=str(x['_id'])) for x in users],
                           'time_zone':{k:facts.get(k) for k in ('zone','source','detected','override')} if facts else None}))
    return {'data':out}

@r.get('/search')
def search(case_id:str,q:str,limit:int=50,u=Depends(current_user)):
    """Keyword search across a case: file paths, timeline events, browser
    records, USB devices, Windows activity, findings and user accounts (case-insensitive substring match)."""
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    term=q.strip()
    if len(term)<2: raise HTTPException(400,'Search term must be at least 2 characters')
    db=get_db(); rx={'$regex':re.escape(term),'$options':'i'}; limit=max(1,min(limit,200))
    eids=[e['evidence_id'] for e in db['evidence'].find({'case_id':case_id},{'evidence_id':1})]
    queries={
        'files':('fs_entries',{'evidence_id':{'$in':eids},'is_virtual':False,**({'$or':[{'path':rx},_hash_query(term)]} if _hash_query(term) else {'path':rx})},
                 [('deleted',-1),('path',1)]),
        'timeline':('timeline_events',{'case_id':case_id,'description':rx},[('timestamp',1)]),
        'browser':('forensic_artifacts',{'case_id':case_id,'type':{'$in':['BROWSER_HISTORY','BROWSER_DOWNLOAD']},
                   '$or':[{'url':rx},{'title':rx},{'target_path':rx},{'tab_url':rx}]},[('timestamp',-1)]),
        'usb':('usb_artifacts',{'case_id':case_id,'$or':[{'friendly_name':rx},{'vendor':rx},{'product':rx},{'serial':rx}]},[('serial',1)]),
        'activity':('forensic_artifacts',{'case_id':case_id,'type':{'$in':list(ACTIVITY_SORT)},'$or':_activity_text(rx)},[('timestamp',-1)]),
        'findings':('findings',{'case_id':case_id,'$or':[{'title':rx},{'description':rx}]},[('created_at',-1)]),
        'accounts':('forensic_artifacts',{'case_id':case_id,'type':'USER_ACCOUNT','$or':[{'username':rx},{'full_name':rx},{'sid':rx},
                    {'profile_path':rx}]},[('rid',1)]),
        'registry':('forensic_artifacts',{'case_id':case_id,'source':'REGISTRY','$or':[{f:rx} for f in ('program','path','value','command','name','server','remote_path','publisher')]},
                    [('type',1),('key_last_write',-1)]),
        # Found data by what is shown: masked card and Aadhaar numbers only by their visible digits.
        'found':('entities',{'evidence_id':{'$in':eids},'$or':[{'display':rx},{'value':rx,'sensitive':False}]},[('kind',1),('count',-1)]),
    }
    results,totals={},{}
    for key,(col,query,sort) in queries.items():
        totals[key]=db[col].count_documents(query)
        results[key]=[serial(dict(x,_id=str(x['_id']))) for x in db[col].find(query,{'occurrences':0}).sort(sort).limit(limit)]
    for x in results['found']:
        if x.get('sensitive'): x.pop('value',None)
    return {'query':term,'results':results,'totals':totals}

@r.get('/browser')
def browser(case_id:str,evidence_id:str|None=None,kind:str='BROWSER_HISTORY',browser:str|None=None,search:str|None=None,skip:int=0,limit:int=500,u=Depends(current_user)):
    if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
    if kind not in {'BROWSER_HISTORY','BROWSER_DOWNLOAD','BROWSER_COOKIE'}: raise HTTPException(400,'Invalid kind')
    q={'case_id':case_id,'type':kind}
    if evidence_id: q['evidence_id']=evidence_id
    if browser: q['browser']=browser
    if search:
        rx={'$regex':re.escape(search),'$options':'i'}; q['$or']=[{'url':rx},{'title':rx},{'target_path':rx},{'tab_url':rx}]
    sort='start_time' if kind=='BROWSER_DOWNLOAD' else 'last_visit_time' if kind=='BROWSER_HISTORY' else 'created'
    col=get_db()['forensic_artifacts']
    rows=[serial(dict(x,_id=str(x['_id']))) for x in col.find(q).sort(sort,-1).skip(max(0,skip)).limit(max(1,min(limit,1000)))]
    return {'data':rows,'total':col.count_documents(q)}

@r.post('/artifacts/{artifact_id}/metadata')
def metadata(artifact_id,u=Depends(require_permission('ANALYSIS_RUN'))):
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path',''))
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    result=inspect_file(p)
    get_db()['forensic_artifacts'].insert_one({'case_id':a['case_id'],'evidence_id':a['evidence_id'],'type':'METADATA','timestamp':datetime.now(timezone.utc),'data':result,'source':'EXIFTOOL','parent_artifact_id':artifact_id})
    return serial(result)

@r.post('/artifacts/{artifact_id}/strings')
def strings(artifact_id,u=Depends(require_permission('ANALYSIS_RUN'))):
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path',''))
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    result=extract_strings(p); get_db()['forensic_artifacts'].insert_one({'case_id':a['case_id'],'evidence_id':a['evidence_id'],'type':'STRINGS','timestamp':datetime.now(timezone.utc),'data':result,'source':'STRINGS','parent_artifact_id':artifact_id})
    return serial(result)

@r.post('/artifacts/{artifact_id}/yara')
def yara(artifact_id,u=Depends(require_permission('ANALYSIS_RUN'))):
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path','')); rules=Path(__file__).resolve().parents[2]/'rules'/'default.yar'
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    result=scan_yara(rules,p); get_db()['forensic_artifacts'].insert_one({'case_id':a['case_id'],'evidence_id':a['evidence_id'],'type':'YARA_SCAN','timestamp':datetime.now(timezone.utc),'data':result,'source':'YARA','parent_artifact_id':artifact_id})
    return serial(result)

@r.post('/artifacts/{artifact_id}/pcap')
def pcap(artifact_id,u=Depends(require_permission('ANALYSIS_RUN'))):
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path',''))
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    result=inspect_pcap(p); return serial(result)

@r.post('/artifacts/{artifact_id}/memory')
def memory(artifact_id,u=Depends(require_permission('ANALYSIS_RUN'))):
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path',''))
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    return serial(inspect_memory(p))

@r.get('/artifacts')
def artifacts(case_id:str|None=None,evidence_id:str|None=None,artifact_type:str|None=None,u=Depends(current_user)):
    q=_case_scope(u,case_id)
    if evidence_id:q['evidence_id']=evidence_id
    if artifact_type:q['type']=artifact_type
    out=[]
    for x in get_db()['forensic_artifacts'].find(q).sort('timestamp',-1).limit(1000):
        x['_id']=str(x['_id']);out.append(serial(x))
    return {'data':out}

@r.post('/demo/seed/{case_id}')
def seed_demo(case_id,u=Depends(require_permission('ANALYSIS_RUN'))):
    if not settings.demo_mode:
        raise HTTPException(403,'Demo seeding is disabled outside DFIP_DEMO_MODE')
    c=get_case(case_id,u)
    if not c:raise HTTPException(404,'Case not found')
    if not c.get('demo'):
        raise HTTPException(403,'Synthetic artifacts can only be seeded into cases explicitly flagged as demo cases')
    evid=get_db()['evidence'].find_one({'case_id':case_id})
    if not evid:raise HTTPException(400,'Add evidence before seeding demo artifacts')
    if not evid.get('demo'):
        raise HTTPException(403,'Synthetic artifacts can only be attached to demo evidence records')
    events=extract_demo_artifacts(case_id,evid['evidence_id']);get_db()['timeline_events'].insert_many(events)
    get_db()['forensic_artifacts'].insert_many([{'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':e['type'],'timestamp':e['timestamp'],'description':e['description'],'source':'DEMO_DATA'} for e in events])
    log(u,'DEMO_ARTIFACTS_SEEDED','case',c['_id'],{'count':len(events)});return {'created':len(events),'warning':'DEMO DATA — NOT REAL FORENSIC EVIDENCE'}

@r.post('/artifacts/{artifact_id}/browser-parse')
def browser_parse(artifact_id, kind: str | None = None, u=Depends(require_permission('ANALYSIS_RUN'))):
    """Parses a recovered/carved file as a browser artifact database. The parser
    is chosen from the filename, or explicitly with `kind` for renamed/carved
    files (e.g. PhotoRec output). Real parsing only — see
    forensic/browser_artifacts.py for the no-fabrication rules this follows."""
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path',''))
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    from ..forensic.browser_artifacts import identify_browser_file, PARSERS
    if kind and kind not in PARSERS:
        raise HTTPException(400, f'Unknown browser artifact kind; expected one of {sorted(PARSERS)}')
    kind = kind or identify_browser_file(a.get('filename', p.name))
    if not kind:
        raise HTTPException(400, f'File {p.name} does not match a known browser artifact filename (History, Cookies, places.sqlite, cookies.sqlite); pass kind= to choose a parser')
    result = PARSERS[kind](p, a['case_id'], a['evidence_id'])
    now=datetime.now(timezone.utc)
    to_insert=[]
    for key in ('history','downloads','cookies'):
        for row in result.get(key, []):
            to_insert.append({**row,'timestamp':now,'parent_artifact_id':artifact_id})
    if to_insert: get_db()['forensic_artifacts'].insert_many(to_insert)
    log(u,'BROWSER_ARTIFACT_PARSED','evidence',a.get('evidence_id',''),{'artifact_id':artifact_id,'kind':kind,'status':result.get('status'),'rows_persisted':len(to_insert)})
    return serial({'kind':kind,'status':result.get('status'),'errors':result.get('errors',[]),'note':result.get('note'),'rows_persisted':len(to_insert)})


@r.post('/evidence/{eid}/carve')
def carve_evidence(eid:str,engine:str='photorec',u=Depends(require_write('ANALYSIS_RUN'))):
    """Runs file carving (PhotoRec by default) against the original evidence
    image and registers each recovered file as a chain-of-custody-tracked
    forensic artifact with a real SHA-256 hash."""
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be carved')
    if engine not in ('photorec','scalpel'): raise HTTPException(400,'Unknown carving engine; use photorec or scalpel')
    image=tsk_image(e,create=True)
    from ..forensic.carving import carve
    # A fresh directory per run so earlier carving output is never re-registered.
    run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+f'-{engine}'
    output_dir=Path(settings.storage_path).resolve()/'analysis'/'carved'/e['evidence_id']/run_id
    scalpel_conf=Path(__file__).resolve().parents[2]/'rules'/'scalpel.conf'
    result=carve(engine,image,output_dir,scalpel_config=scalpel_conf)
    if result.get('status')=='TOOL_UNAVAILABLE':
        return serial(result)
    now=datetime.now(timezone.utc)
    docs=[]
    for f in result.get('recovered_files', []):
        if 'sha256' not in f: continue
        aid=str(uuid.uuid4())
        docs.append({'artifact_id':aid,'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':'CARVED_FILE',
                     'timestamp':now,'path':f['path'],'filename':f['filename'],'size':f['size'],
                     'sha256':f['sha256'],'source':f'FILE_CARVING_{engine.upper()}'})
    if docs: get_db()['forensic_artifacts'].insert_many(docs)
    log(u,'FILE_CARVING_COMPLETED','evidence',e['_id'],{'engine':engine,'status':result.get('status'),'files_recovered':len(docs)})
    manager.emit_sync('ARTIFACT_BATCH_CREATED', {'case_id': e['case_id'], 'evidence_id': e['evidence_id'], 'type': 'CARVED_FILE', 'count': len(docs)})
    return serial({'status':result.get('status'),'engine':engine,'files_recovered':len(docs),
                   'stderr':result.get('stderr','')[-2000:] if result.get('stderr') else ''})


def _case_scope(u,case_id=None):
    """Mongo filter restricting case_id to cases the user may access."""
    if case_id:
        if not get_case(case_id,u): raise HTTPException(404,'Case not found or access denied')
        return {'case_id':case_id}
    if u['role']=='ADMIN': return {}
    return {'case_id':{'$in':[x['case_id'] for x in get_db()['cases'].find(allowed_case_query(u),{'case_id':1})]}}

def _parse_when(v,name):
    if not v: return None
    try:
        dt=datetime.fromisoformat(v.replace('Z','+00:00'))
    except ValueError:
        raise HTTPException(400,f'Invalid {name} timestamp')
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def _timeline_query(u,case_id,evidence_id,type,start,end,q):
    query=_case_scope(u,case_id)
    if evidence_id: query['evidence_id']=evidence_id
    if type: query['type']={'$in':[t for t in type.split(',') if t]}
    s,e=_parse_when(start,'start'),_parse_when(end,'end')
    if s or e: query['timestamp']={k:v for k,v in (('$gte',s),('$lte',e)) if v}
    if q: query['description']={'$regex':re.escape(q),'$options':'i'}
    return query

@r.get('/timeline/histogram')
def timeline_histogram(case_id:str,evidence_id:str|None=None,type:str|None=None,start:str|None=None,end:str|None=None,
                       q:str|None=None,u=Depends(current_user)):
    """Event counts per time bucket (hour, day or month, chosen from the span) and type."""
    query=_timeline_query(u,case_id,evidence_id,type,start,end,q); col=get_db()['timeline_events']
    first=col.find_one(query,{'timestamp':1},sort=[('timestamp',1)])
    last=col.find_one(query,{'timestamp':1},sort=[('timestamp',-1)])
    if not first: return {'unit':None,'buckets':[]}
    span=(last['timestamp']-first['timestamp']).total_seconds()
    unit='hour' if span<=3*86400 else 'day' if span<=180*86400 else 'month'
    rows=col.aggregate([{'$match':query},
                        {'$group':{'_id':{'t':{'$dateTrunc':{'date':'$timestamp','unit':unit}},'type':'$type'},'n':{'$sum':1}}},
                        {'$sort':{'_id.t':1}}])
    buckets={}
    for r_ in rows:
        t=r_['_id']['t']; b=buckets.setdefault(t,{'t':t.isoformat(),'total':0,'by_type':{}})
        b['total']+=r_['n']; b['by_type'][r_['_id']['type']]=r_['n']
    return {'unit':unit,'first':first['timestamp'].isoformat(),'last':last['timestamp'].isoformat(),'buckets':list(buckets.values())}

@r.get('/timeline')
def timeline(case_id:str|None=None,evidence_id:str|None=None,type:str|None=None,start:str|None=None,end:str|None=None,
             q:str|None=None,order:str='desc',skip:int=0,limit:int=500,u=Depends(current_user)):
    query=_timeline_query(u,case_id,evidence_id,type,start,end,q)
    limit=max(1,min(limit,2000)); col=get_db()['timeline_events']
    out=[serial(dict(x,_id=str(x['_id']))) for x in col.find(query).sort('timestamp',1 if order=='asc' else -1).skip(max(0,skip)).limit(limit)]
    return {'data':out,'total':col.count_documents(query),'skip':skip,'limit':limit}

@r.post('/patterns')
def patterns(case_id:str,u=Depends(require_write('ANALYSIS_RUN'))):
    if not get_case(case_id,u):raise HTTPException(404,'Case not found or access denied')
    docs=compute_patterns(get_db(),case_id)
    log(u,'PATTERN_ANALYSIS','case',case_id,{'count':len(docs)})
    manager.emit_sync('TIMELINE_UPDATED', {'case_id': case_id, 'patterns_count': len(docs)})
    return {'data':serial([{k:v for k,v in d.items() if k!='_id'} for d in docs])}

@r.get('/patterns')
def get_patterns(case_id:str|None=None,u=Depends(current_user)):
    out=[]
    for x in get_db()['patterns'].find(_case_scope(u,case_id)).sort('created_at',-1):x['_id']=str(x['_id']);out.append(serial(x))
    return {'data':out}

@r.post('/anomalies')
def anomalies(case_id:str,u=Depends(require_write('ANALYSIS_RUN'))):
    if not get_case(case_id,u):raise HTTPException(404,'Case not found or access denied')
    docs,method,extra=compute_anomalies(get_db(),case_id)
    log(u,'ANOMALY_ANALYSIS','case',case_id,{'count':len(docs),'method':method})
    manager.emit_sync('TIMELINE_UPDATED', {'case_id': case_id, 'anomalies_count': len(docs)})
    return {'data':serial([{k:v for k,v in d.items() if k!='_id'} for d in docs]),**extra}

@r.get('/anomalies')
def get_anomalies(case_id:str|None=None,u=Depends(current_user)):
    out=[]
    for x in get_db()['anomalies'].find(_case_scope(u,case_id)).sort('created_at',-1):x['_id']=str(x['_id']);out.append(serial(x))
    return {'data':out}

@r.post('/ai')
async def ai(question:str,case_id:str,u=Depends(current_user)):
    if not get_case(case_id,u):raise HTTPException(404,'Case not found or access denied')
    from ..ai.services import VectorSearchService
    context=await VectorSearchService().search(question,case_id,limit=10)
    if not context:
        # Fall back to most recent artifacts if nothing is lexically relevant,
        # so the assistant can still say "nothing matches" grounded in real data
        # rather than returning an empty, unexplained answer.
        context=list(get_db()['forensic_artifacts'].find({'case_id':case_id}).sort('timestamp',-1).limit(10))
    result=await AIService().answer(question,case_id,context);log(u,'AI_QUERY','case',case_id,{'question':question});return result
