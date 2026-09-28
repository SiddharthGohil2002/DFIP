from fastapi import APIRouter,Depends,HTTPException
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,uuid
from ..security import current_user, require_permission, require_desktop_workstation
from ..database import get_db
from ..repositories.evidence import get_evidence
from ..repositories.cases import get_case
from ..forensic.engine import ForensicEngine,extract_demo_artifacts
from ..analysis.services import PatternService,AnomalyService
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

def serial(v):
    if hasattr(v,'isoformat'): return v.isoformat()
    if isinstance(v,dict): return {k:serial(x) for k,x in v.items()}
    if isinstance(v,list): return [serial(x) for x in v]
    return v

@r.get('/tooling')
def tooling(u=Depends(current_user)): return {'data':inventory()}

@r.post('/evidence/{eid}/analyze')
def analyze(eid,u=Depends(require_desktop_workstation)):
    e=auth_evidence(eid,u)
    if e.get('demo'): return {'status':'DEMO','evidence_id':e['evidence_id'],'case_id':e['case_id'],'engine':'DFIP Demo Engine','limitations':['Synthetic demo evidence cannot be parsed as a real image.']}
    path=Path(e['storage_path'])
    if not path.exists(): raise HTTPException(409,'Original evidence object is unavailable')
    manager.emit_sync('ANALYSIS_STARTED', {'evidence_id': e['evidence_id'], 'case_id': e['case_id']})
    result=ForensicEngine().analyze(path,e['format'])
    get_db()['forensic_artifacts'].insert_one({'case_id':e['case_id'],'evidence_id':e['evidence_id'],'type':'ANALYSIS_RUN','timestamp':datetime.now(timezone.utc),'data':result,'source':'DFIP_ENGINE'})
    log(u,'ANALYSIS_COMPLETED','evidence',e['_id'],{'engine':result['engine']})
    manager.emit_sync('ANALYSIS_COMPLETED', {'evidence_id': e['evidence_id'], 'case_id': e['case_id'], 'engine': result['engine']})
    return serial(dict(result,evidence_id=e['evidence_id'],case_id=e['case_id']))

@r.post('/evidence/{eid}/examine')
def examine(eid:str,offset:int=0,u=Depends(require_desktop_workstation)):
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be examined as a real image')
    path=Path(e['storage_path'])
    if not path.exists(): raise HTTPException(409,'Original evidence object is unavailable')
    parts=parse_mmls(path); fs=parse_filesystem(path,e['format'],offset); stats=filesystem_stats(path,offset)
    now=datetime.now(timezone.utc)
    docs=[]
    for p in parts.get('partitions',[]): docs.append({'case_id':e['case_id'],'evidence_id':eid,'type':'PARTITION','timestamp':now,'data':p,'source':'SLEUTH_KIT'})
    for a in fs.get('artifacts',[]): docs.append({'case_id':e['case_id'],'evidence_id':eid,'type':'FILESYSTEM_ENTRY','timestamp':now,'data':a,'source':'SLEUTH_KIT'})
    if docs: get_db()['forensic_artifacts'].insert_many(docs)
    log(u,'FORENSIC_EXAMINATION','evidence',e['_id'],{'offset':offset,'partitions':len(parts.get('partitions',[])),'filesystem_entries':len(fs.get('artifacts',[]))})
    manager.emit_sync('ARTIFACT_BATCH_CREATED', {'case_id': e['case_id'], 'evidence_id': eid, 'count': len(docs)})
    return serial({'evidence_id':eid,'offset':offset,'partitions':parts,'filesystem':fs,'filesystem_stats':stats,'persisted_artifacts':len(docs)})

@r.get('/evidence/{eid}/partitions')
def partitions(eid,u=Depends(current_user)):
    e=auth_evidence(eid,u)
    if e.get('demo'): return {'data':[],'warning':'Synthetic demo evidence'}
    p=Path(e['storage_path']);
    if not p.exists(): raise HTTPException(409,'Original evidence object is unavailable')
    return serial(parse_mmls(p))

@r.post('/evidence/{eid}/istat')
def istat(eid:str,inode:int,offset:int=0,u=Depends(require_desktop_workstation)):
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be examined')
    return serial(inode_stat(Path(e['storage_path']),inode,offset))

@r.post('/evidence/{eid}/recover')
def recover(eid:str,inode:int,offset:int=0,u=Depends(require_desktop_workstation)):
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be recovered')
    image=Path(e['storage_path']); root=Path(settings.storage_path).resolve()/'analysis'/'recovered'/eid
    name=f'{inode}_{uuid.uuid4().hex}.bin'; dest=root/name
    result=recover_file(image,inode,dest,offset)
    if result.get('status')!='COMPLETED': return result
    digest=hashlib.sha256(dest.read_bytes()).hexdigest(); size=dest.stat().st_size
    dest.chmod(0o440)
    now=datetime.now(timezone.utc); aid=str(uuid.uuid4())
    doc={'artifact_id':aid,'case_id':e['case_id'],'evidence_id':eid,'type':'RECOVERED_FILE','timestamp':now,'path':str(dest),'filename':name,'inode':inode,'offset':offset,'size':size,'sha256':digest,'source':'SLEUTH_KIT_ICAT'}
    get_db()['forensic_artifacts'].insert_one(doc); log(u,'FILE_RECOVERED','evidence',e['_id'],{'artifact_id':aid,'inode':inode,'sha256':digest})
    manager.emit_sync('ARTIFACT_CREATED', {'artifact_id': aid, 'case_id': e['case_id'], 'type': 'RECOVERED_FILE', 'filename': name})
    return serial({'status':'COMPLETED','artifact_id':aid,'size':size,'sha256':digest,'filename':name})

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
    q={}
    if case_id:q['case_id']=case_id
    if evidence_id:q['evidence_id']=evidence_id
    if artifact_type:q['type']=artifact_type
    if u['role']!='ADMIN':
        allowed=[x['case_id'] for x in get_db()['cases'].find({'$or':[{'investigator_id':str(u['_id'])},{'created_by':str(u['_id'])}]},{'case_id':1})]
        q['case_id']={'$in':allowed}
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
def browser_parse(artifact_id, u=Depends(require_permission('ANALYSIS_RUN'))):
    """Parses a recovered/carved file as a browser artifact database, if its
    filename matches a known browser artifact file. Real parsing only — see
    forensic/browser_artifacts.py for the no-fabrication rules this follows."""
    a=get_db()['forensic_artifacts'].find_one({'artifact_id':artifact_id})
    if not a or not get_case(a['case_id'],u): raise HTTPException(404,'Artifact not found or access denied')
    p=Path(a.get('path',''))
    if not p.is_file(): raise HTTPException(409,'Artifact file is unavailable')
    from ..forensic.browser_artifacts import identify_browser_file, PARSERS
    kind = identify_browser_file(a.get('filename', p.name))
    if not kind:
        raise HTTPException(400, f'File {p.name} does not match a known browser artifact filename (History, Cookies, places.sqlite, cookies.sqlite)')
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
def carve_evidence(eid:str,engine:str='photorec',u=Depends(require_desktop_workstation)):
    """Runs file carving (PhotoRec by default) against the original evidence
    image and registers each recovered file as a chain-of-custody-tracked
    forensic artifact with a real SHA-256 hash."""
    e=auth_evidence(eid,u)
    if e.get('demo'): raise HTTPException(400,'Demo evidence cannot be carved')
    image=Path(e['storage_path'])
    if not image.exists(): raise HTTPException(409,'Original evidence object is unavailable')
    from ..forensic.carving import carve
    output_dir=Path(settings.storage_path).resolve()/'analysis'/'carved'/eid
    result=carve(engine,image,output_dir)
    if result.get('status')=='TOOL_UNAVAILABLE':
        return serial(result)
    now=datetime.now(timezone.utc)
    docs=[]
    for f in result.get('recovered_files', []):
        if 'sha256' not in f: continue
        aid=str(uuid.uuid4())
        docs.append({'artifact_id':aid,'case_id':e['case_id'],'evidence_id':eid,'type':'CARVED_FILE',
                     'timestamp':now,'path':f['path'],'filename':f['filename'],'size':f['size'],
                     'sha256':f['sha256'],'source':f'FILE_CARVING_{engine.upper()}'})
    if docs: get_db()['forensic_artifacts'].insert_many(docs)
    log(u,'FILE_CARVING_COMPLETED','evidence',e['_id'],{'engine':engine,'status':result.get('status'),'files_recovered':len(docs)})
    manager.emit_sync('ARTIFACT_BATCH_CREATED', {'case_id': e['case_id'], 'evidence_id': eid, 'type': 'CARVED_FILE', 'count': len(docs)})
    return serial({'status':result.get('status'),'engine':engine,'files_recovered':len(docs),
                   'stderr':result.get('stderr','')[-2000:] if result.get('stderr') else ''})


@r.get('/timeline')
def timeline(case_id:str|None=None,u=Depends(current_user)):
    q={}
    if case_id:q['case_id']=case_id
    allowed=None if u['role']=='ADMIN' else [x['case_id'] for x in get_db()['cases'].find({'$or':[{'investigator_id':str(u['_id'])},{'created_by':str(u['_id'])}]},{'case_id':1})]
    if allowed is not None:q['case_id']={'$in':allowed}
    out=[]
    for x in get_db()['timeline_events'].find(q).sort('timestamp',-1).limit(1000):x['_id']=str(x['_id']);out.append(serial(x))
    return {'data':out}

@r.post('/patterns')
def patterns(case_id:str,u=Depends(require_desktop_workstation)):
    if not get_case(case_id,u):raise HTTPException(404,'Case not found or access denied')
    ev=list(get_db()['timeline_events'].find({'case_id':case_id}));p=PatternService().run(ev);get_db()['patterns'].delete_many({'case_id':case_id});now=datetime.now(timezone.utc);docs=[dict(x,case_id=case_id,created_at=now) for x in p]
    if docs:get_db()['patterns'].insert_many(docs)
    log(u,'PATTERN_ANALYSIS','case',case_id,{'count':len(docs)})
    manager.emit_sync('TIMELINE_UPDATED', {'case_id': case_id, 'patterns_count': len(docs)})
    return {'data':serial(docs)}

@r.get('/patterns')
def get_patterns(case_id:str|None=None,u=Depends(current_user)):
    q={'case_id':case_id} if case_id else {};out=[]
    for x in get_db()['patterns'].find(q).sort('created_at',-1):x['_id']=str(x['_id']);out.append(serial(x))
    return {'data':out}

@r.post('/anomalies')
def anomalies(case_id:str,u=Depends(require_desktop_workstation)):
    if not get_case(case_id,u):raise HTTPException(404,'Case not found or access denied')
    ev=list(get_db()['timeline_events'].find({'case_id':case_id}))
    from ..analysis.services import AnomalyService,MLAnomalyService
    ml_result=MLAnomalyService().run(ev)
    if ml_result.get('status')=='COMPLETED':
        a=ml_result['results'];method='ISOLATION_FOREST';extra={'ml_summary':{k:v for k,v in ml_result.items() if k!='results'}}
    else:
        # Honest fallback: not enough data (or sklearn unavailable) for a real
        # ML model, so we use the rule-based scorer instead of pretending the
        # ML path produced something.
        a=AnomalyService().run(ev);method='RULE_BASED_FALLBACK';extra={'ml_status':ml_result}
    get_db()['anomalies'].delete_many({'case_id':case_id});now=datetime.now(timezone.utc)
    docs=[dict(x,case_id=case_id,created_at=now,detection_method=method) for x in a]
    if docs:get_db()['anomalies'].insert_many(docs)
    log(u,'ANOMALY_ANALYSIS','case',case_id,{'count':len(docs),'method':method})
    manager.emit_sync('TIMELINE_UPDATED', {'case_id': case_id, 'anomalies_count': len(docs)})
    return {'data':serial(docs),**extra}

@r.get('/anomalies')
def get_anomalies(case_id:str|None=None,u=Depends(current_user)):
    q={'case_id':case_id} if case_id else {};out=[]
    for x in get_db()['anomalies'].find(q).sort('created_at',-1):x['_id']=str(x['_id']);out.append(serial(x))
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
