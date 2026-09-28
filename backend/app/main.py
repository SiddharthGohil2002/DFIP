from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .database import get_db
from .repositories.users import seed_users
from .api import auth,cases,evidence,notifications,reports,admin,forensics,findings,chain,jobs,threatintel,desktop as desktop_module
from .ws import r as ws_router
from datetime import datetime,timezone
app=FastAPI(title='DFIP API',version='2.0.0',description='Digital Forensics Investigation Platform')
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(',') if x.strip()],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
for router in [auth.r,cases.r,evidence.r,notifications.r,reports.r,admin.r,forensics.r,findings.r,chain.r,jobs.r,threatintel.r,desktop_module.r]:app.include_router(router,prefix='/api')
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
        for collection,index,unique in [('cases','case_id',True),('evidence','evidence_id',True),('audit_logs','timestamp',False),('timeline_events','timestamp',False),('notifications','user_id',False),('findings','case_id',False),('jobs','status',False),('jobs','job_id',True),('refresh_tokens','token_hash',True),('audit_logs','sequence',True),('forensic_artifacts','case_id',False),('forensic_artifacts','artifact_id',False),('patterns','case_id',False),('anomalies','case_id',False),('desktop_devices','device_id',True),('desktop_devices','user_id',False),('reports','report_id',True)]:
            try:db[collection].create_index(index,unique=unique)
            except Exception:pass
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
    try:get_db().command('ping');return {'status':'ok','database':'mongodb'}
    except Exception as e:return {'status':'degraded','database':'mongodb-unavailable','detail':str(e)}
