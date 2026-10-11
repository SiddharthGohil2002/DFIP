from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .database import get_db
from .repositories.users import seed_users
from .api import auth,cases,evidence,notifications,reports,admin,forensics,findings,chain,jobs,threatintel,tags,hashsets,content,registry,desktop as desktop_module
from .ws import r as ws_router
from datetime import datetime,timezone
app=FastAPI(title='DFIP API',version='2.1.0',description='Digital Forensics Investigation Platform')
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(',') if x.strip()],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
for router in [auth.r,cases.r,evidence.r,notifications.r,reports.r,admin.r,forensics.r,content.r,registry.r,findings.r,chain.r,jobs.r,threatintel.r,tags.r,hashsets.r,desktop_module.r]:app.include_router(router,prefix='/api')
app.include_router(ws_router)
@app.on_event('startup')
async def startup():
    try:
        import asyncio
        from .websocket.manager import manager
        try:
            manager.set_loop(asyncio.get_running_loop())
        except Exception:
            pass
        db=get_db();seed_users()
        # Job execution runs in separate Celery worker processes (see
        # celery_app.py / tasks.py); nothing to start in-process here.
        # Upgrade legacy audit records into the tamper-evident hash chain.
        from .services.audit import _canonical
        import hashlib
        legacy=list(db['audit_logs'].find({'sequence':{'$exists':False}}).sort('timestamp',1))
        last=db['audit_logs'].find_one({'sequence':{'$exists':True}},sort=[('sequence',-1)])
        seq=(last.get('sequence',0) if last else 0); previous=last.get('record_hash') if last else None
        for row in legacy:
            seq += 1; row['sequence']=seq; row['previous_hash']=previous
            copy={k:v for k,v in row.items() if k not in ('_id','record_hash')}
            row['record_hash']=hashlib.sha256(_canonical(copy).encode()).hexdigest()
            db['audit_logs'].replace_one({'_id':row['_id']},row); previous=row['record_hash']
        for collection,index,unique in [('cases','case_id',True),('evidence','evidence_id',True),('audit_logs','timestamp',False),('timeline_events','timestamp',False),('notifications','user_id',False),('findings','case_id',False),('jobs','status',False),('jobs','job_id',True),('refresh_tokens','token_hash',True),('audit_logs','sequence',True),('forensic_artifacts','case_id',False),('forensic_artifacts','artifact_id',False),('patterns','case_id',False),('anomalies','case_id',False),('desktop_devices','device_id',True),('desktop_devices','user_id',False),('reports','report_id',True),('users','email',True),('tags','tag_id',True),('tags','evidence_id',False)]:
            try:db[collection].create_index(index,unique=unique)
            except Exception:pass
        # Compound indexes for the analysis pipeline's high-volume collections.
        for collection,keys in [('timeline_events',[('case_id',1),('timestamp',-1)]),('timeline_events',[('evidence_id',1),('pipeline',1)]),
                                ('fs_entries',[('evidence_id',1),('deleted',-1),('path',1)]),('fs_entries',[('evidence_id',1),('inode',1),('partition_offset',1)]),
                                ('usb_artifacts',[('case_id',1),('evidence_id',1)]),('forensic_artifacts',[('case_id',1),('type',1)])]:
            try:db[collection].create_index(keys)
            except Exception:pass
        # One tag per item: the natural key's hash identifies the item across re-analysis.
        try:db['tags'].create_index([('case_id',1),('item_type',1),('key_hash',1)],unique=True)
        except Exception:pass
        # Analysis modules replace only their own output: every pipeline collection is cleared per module.
        for collection in ('fs_entries','timeline_events','forensic_artifacts','usb_artifacts','pipeline_warnings','entities'):
            try:db[collection].create_index([('evidence_id',1),('pipeline_module',1)])
            except Exception:pass
        for collection,keys,unique in [('hash_sets',[('set_id',1)],True),('fs_entries',[('evidence_id',1),('sha256',1)],False),
                                       ('fs_entries',[('case_id',1),('sha256',1)],False),('fs_entries',[('evidence_id',1),('file_category',1)],False),
                                       ('analysis_facts',[('evidence_id',1)],True),('timeline_events',[('evidence_id',1),('nk',1)],False),
                                       ('jobs',[('payload.evidence_id',1),('status',1)],False),
                                       ('entities',[('case_id',1),('kind',1),('value',1)],False),('entities',[('evidence_id',1),('kind',1),('count',-1)],False)]:
            try:db[collection].create_index(keys,unique=unique)
            except Exception:pass
        # Tags made with older natural keys move to the current ones (idempotent).
        from .services.tags import migrate_keys
        try:migrate_keys(db)
        except Exception as exc:print(f'[DFIP] tag key migration skipped: {exc}')
        if settings.demo_mode and db['cases'].count_documents({})==0:
            inv=db['users'].find_one({'email':'investigator@dfip.local'});now=datetime.now(timezone.utc)
            case={'case_id':'CASE-2026-001','name':'Unauthorized Data Access Investigation','description':'Demonstration investigation. All records in this case are synthetic demo data.','status':'IN_PROGRESS','priority':'HIGH','investigator_id':str(inv['_id']),'member_ids':[],'created_by':str(inv['_id']),'created_at':now,'updated_at':now,'demo':True}
            db['cases'].insert_one(case)
            db['evidence'].insert_one({'evidence_id':'EVID-001','case_id':case['case_id'],'filename':'demo-laptop.E01','format':'E01','size':734003200,'sha256':'demo-sha256-not-real-evidence','storage_path':'DEMO','verification_status':'VERIFIED','created_at':now,'updated_at':now,'created_by':str(inv['_id']),'read_only':True,'immutable':True,'demo':True,'acquisition_status':'PRESERVED','integrity_algorithm':'SHA-256'})
            from .forensic.engine import extract_demo_artifacts
            db['timeline_events'].insert_many(extract_demo_artifacts(case['case_id'],'EVID-001'))
            db['findings'].insert_one({'case_id':case['case_id'],'title':'Removable media activity requires review','description':'Synthetic demonstration finding linked to DEMO DATA USB activity.','severity':'MEDIUM','evidence_ids':['EVID-001'],'timeline_ids':[],'created_by':str(inv['_id']),'created_at':now,'updated_at':now,'demo':True})
    except Exception as e:
        if not settings.demo_mode:raise
        print(f'[DFIP] MongoDB unavailable; startup continues in degraded mode: {e}')
@app.get('/health')
def health():
    base={'version':app.version,'demo_mode':settings.demo_mode,'require_desktop_for_writes':settings.require_desktop_for_writes,
          'registration_mode':settings.registration_mode}
    try:get_db().command('ping');return {'status':'ok','database':'mongodb',**base}
    except Exception as e:return {'status':'degraded','database':'mongodb-unavailable','detail':str(e),**base}
