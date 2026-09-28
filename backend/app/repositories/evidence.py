from bson import ObjectId
from ..database import get_db
from .cases import allowed_case_query

def col(): return get_db()['evidence']
def serial(x):
    d=dict(x);d['_id']=str(d['_id'])
    for k,v in list(d.items()):
        if hasattr(v,'isoformat'): d[k]=v.isoformat()
    return d

def list_evidence(user):
    q={} if user['role']=='ADMIN' else {'case_id':{'$in':[x['case_id'] for x in get_db()['cases'].find(allowed_case_query(user),{'case_id':1})]}}
    return [serial(x) for x in col().find(q).sort('created_at',-1)]
def get_evidence(eid):
    try:return col().find_one({'_id':ObjectId(eid)})
    except:return None
def insert(doc):
    r=col().insert_one(doc);return serial(col().find_one({'_id':r.inserted_id}))
