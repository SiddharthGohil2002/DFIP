from pymongo import MongoClient
from .core.config import settings
_client=None
_db=None

def get_db():
    global _client,_db
    if _db is None:
        _client=MongoClient(settings.mongodb_uri,serverSelectionTimeoutMS=5000,connectTimeoutMS=5000,maxPoolSize=100,minPoolSize=5,appname='DFIP')
        _db=_client[settings.database_name]
        _client.admin.command('ping')
    return _db

def close_db():
    global _client,_db
    if _client:_client.close()
    _client=None;_db=None
