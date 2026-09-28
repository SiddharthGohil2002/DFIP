from datetime import datetime, timezone, timedelta
from ..database import get_db

def register_device(device_id: str, device_name: str, user_id: str, app_version: str, os: str):
    db = get_db()
    now = datetime.now(timezone.utc)
    doc = {
        'device_id': device_id,
        'device_name': device_name,
        'user_id': user_id,
        'app_version': app_version,
        'os': os,
        'status': 'ONLINE',
        'last_seen': now,
    }
    db['desktop_devices'].update_one(
        {'device_id': device_id},
        {'$set': doc, '$setOnInsert': {'registered_at': now}},
        upsert=True
    )
    return get_db()['desktop_devices'].find_one({'device_id': device_id}, {'_id': 0})

def heartbeat(device_id: str):
    now = datetime.now(timezone.utc)
    get_db()['desktop_devices'].update_one(
        {'device_id': device_id},
        {'$set': {'last_seen': now, 'status': 'ONLINE'}}
    )
    return now

def get_device(device_id: str):
    return get_db()['desktop_devices'].find_one({'device_id': device_id}, {'_id': 0})

def get_device_for_user(user_id: str):
    return get_db()['desktop_devices'].find_one({'user_id': user_id}, {'_id': 0}, sort=[('last_seen', -1)])

def list_devices_for_user(user_id: str):
    return list(get_db()['desktop_devices'].find({'user_id': user_id}, {'_id': 0}).sort('last_seen', -1))

def get_online_devices(user_id: str, within_minutes: int = 5):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=within_minutes)
    return list(get_db()['desktop_devices'].find(
        {'user_id': user_id, 'last_seen': {'$gte': cutoff}},
        {'_id': 0}
    ).sort('last_seen', -1))

def mark_offline(device_id: str):
    get_db()['desktop_devices'].update_one(
        {'device_id': device_id},
        {'$set': {'status': 'OFFLINE'}}
    )
