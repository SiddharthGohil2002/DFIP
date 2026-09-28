from datetime import datetime,timezone
from hashlib import sha256
import json
from ..database import get_db

def _canonical(doc):
    return json.dumps(doc,sort_keys=True,default=str,separators=(',',':'))

def log(user,action,resource_type,resource_id,metadata=None):
    db=get_db();now=datetime.now(timezone.utc)
    previous=db['audit_logs'].find_one(sort=[('sequence',-1)])
    seq=(previous.get('sequence',0)+1) if previous else 1
    payload={'sequence':seq,'timestamp':now.isoformat(),'user_id':str(user['_id']),'user_name':user.get('name'),'user_role':user.get('role'),'action':action,'resource_type':resource_type,'resource_id':str(resource_id),'metadata':metadata or {},'previous_hash':previous.get('record_hash') if previous else None}
    record_hash=sha256(_canonical(payload).encode()).hexdigest();payload['record_hash']=record_hash
    return db['audit_logs'].insert_one(payload).inserted_id

def verify_chain(limit=10000):
    rows=list(get_db()['audit_logs'].find().sort('sequence',1).limit(limit));previous=None
    for row in rows:
        expected_prev=previous.get('record_hash') if previous else None
        stored=row.get('record_hash');copy={k:v for k,v in row.items() if k not in ('_id','record_hash')}
        if row.get('previous_hash')!=expected_prev or sha256(_canonical(copy).encode()).hexdigest()!=stored:return {'valid':False,'broken_sequence':row.get('sequence')}
        previous=row
    return {'valid':True,'records_checked':len(rows),'last_sequence':previous.get('sequence') if previous else 0}
