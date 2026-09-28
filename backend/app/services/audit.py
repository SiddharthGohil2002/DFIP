from datetime import datetime,timezone
from hashlib import sha256
import json
from pymongo.errors import DuplicateKeyError
from ..database import get_db

def _canonical(doc):
    return json.dumps(doc,sort_keys=True,default=str,separators=(',',':'))

def append(payload):
    """Appends a record to the hash-chained audit log.

    Sequence and previous_hash are taken from the current chain head; if another
    request appended first (unique index on `sequence`), re-read and retry.
    Metadata is normalised through JSON first, so what is hashed is exactly what
    Mongo stores (datetimes as strings; Mongo would otherwise truncate microseconds).
    """
    db=get_db()
    body=json.loads(_canonical(payload))
    for _ in range(10):
        previous=db['audit_logs'].find_one({'sequence':{'$exists':True}},sort=[('sequence',-1)])
        record=dict(body,sequence=(previous.get('sequence',0)+1) if previous else 1,
                    previous_hash=previous.get('record_hash') if previous else None)
        record.pop('record_hash',None)
        record['record_hash']=sha256(_canonical(record).encode()).hexdigest()
        try:
            return db['audit_logs'].insert_one(record).inserted_id
        except DuplicateKeyError:
            continue
    raise RuntimeError('Could not append to the audit log after repeated contention')

def log(user,action,resource_type,resource_id,metadata=None):
    return append({'timestamp':datetime.now(timezone.utc).isoformat(),'user_id':str(user['_id']),'user_name':user.get('name'),
                   'user_role':user.get('role'),'action':action,'resource_type':resource_type,'resource_id':str(resource_id),
                   'metadata':metadata or {}})

def verify_chain(limit=10000):
    rows=list(get_db()['audit_logs'].find().sort('sequence',1).limit(limit));previous=None
    for row in rows:
        expected_prev=previous.get('record_hash') if previous else None
        stored=row.get('record_hash');copy={k:v for k,v in row.items() if k not in ('_id','record_hash')}
        if row.get('previous_hash')!=expected_prev or sha256(_canonical(copy).encode()).hexdigest()!=stored:return {'valid':False,'broken_sequence':row.get('sequence')}
        previous=row
    return {'valid':True,'records_checked':len(rows),'last_sequence':previous.get('sequence') if previous else 0}
