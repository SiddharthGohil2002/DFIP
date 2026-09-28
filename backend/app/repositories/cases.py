from datetime import datetime, timezone
from ..database import get_db
from ..services.sequences import next_sequence

def col(): return get_db()['cases']
def serial(x):
    d=dict(x);d['_id']=str(d['_id'])
    for k in ('created_at','updated_at','closed_at'):
        if hasattr(d.get(k),'isoformat'): d[k]=d[k].isoformat()
    return d

def allowed_case_query(user):
    if user['role']=='ADMIN': return {}
    uid=str(user['_id']); return {'$or':[{'investigator_id':uid},{'created_by':uid},{'member_ids':uid}]}

def list_cases(user): return [serial(x) for x in col().find(allowed_case_query(user)).sort('updated_at',-1)]
def get_case(case_id,user=None):
    q={'case_id':case_id}
    if user and user['role']!='ADMIN': q={'$and':[q,allowed_case_query(user)]}
    x=col().find_one(q); return serial(x) if x else None

def create_case(data,user):
    now=datetime.now(timezone.utc)
    n=next_sequence(f'cases-{now.year}',floor=col().count_documents({'case_id':{'$regex':f'^CASE-{now.year}-'}}))
    doc={'case_id':f"CASE-{now.year}-{n:03d}",'name':data['name'].strip(),'description':data.get('description',''),'status':'OPEN','priority':data.get('priority','MEDIUM'),'investigator_id':data.get('investigator_id') or (str(user['_id']) if user['role']!='ADMIN' else None),'member_ids':data.get('member_ids',[]),'created_by':str(user['_id']),'created_at':now,'updated_at':now}
    r=col().insert_one(doc);return serial(col().find_one({'_id':r.inserted_id}))
