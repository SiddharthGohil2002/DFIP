from bson import ObjectId
from datetime import datetime, timezone
from ..database import get_db
from ..security import hash_password
from ..core.config import settings

def col():
    return get_db()['users']

def get_user_by_id(uid):
    try:
        return col().find_one({'_id': ObjectId(uid)})
    except Exception:
        return None

def get_by_email(email):
    return col().find_one({'email': email.lower().strip()})

def list_users():
    return list(col().find({}, {'password_hash': 0}).sort('created_at', -1))

def serial(x):
    d = dict(x)
    d['_id'] = str(d['_id'])
    for k, v in list(d.items()):
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d

def seed_users():
    now = datetime.now(timezone.utc)
    db = get_db()
    
    # 1. Administrator Account (Production Single Root of Trust)
    admin_email = 'admin@dfip.local'
    if not get_by_email(admin_email):
        # The well-known demo password is only acceptable in demo mode.
        admin_password = 'DemoPassword!2026' if settings.demo_mode else settings.admin_password
        if not admin_password:
            raise RuntimeError('ADMIN_PASSWORD must be set to create the initial admin account when DEMO_MODE is off')
        col().insert_one({
            'name': 'DFIP Administrator',
            'email': admin_email,
            'role': 'ADMIN',
            'status': 'ACTIVE',
            'password_hash': hash_password(admin_password),
            'created_at': now,
            'updated_at': now
        })
    
    # 2. In DEMO_MODE, seed test accounts if not existing
    if settings.demo_mode:
        test_accounts = [
            ('investigator@dfip.local', 'Demo Investigator', 'INVESTIGATOR'),
            ('analyst@dfip.local', 'Demo Analyst', 'ANALYST'),
            ('viewer@dfip.local', 'Demo Viewer', 'VIEWER')
        ]
        for email, name, role in test_accounts:
            if not get_by_email(email):
                col().insert_one({
                    'name': name,
                    'email': email,
                    'role': role,
                    'status': 'ACTIVE',
                    'password_hash': hash_password('DemoPassword!2026'),
                    'created_at': now,
                    'updated_at': now
                })
    
    # 3. RBAC Permissions Matrix
    defaults = {
        'ADMIN': [
            'USER_MANAGE', 'ROLE_MANAGE', 'CASE_CREATE', 'CASE_READ', 'CASE_UPDATE',
            'CASE_ARCHIVE', 'EVIDENCE_UPLOAD', 'EVIDENCE_READ', 'EVIDENCE_VERIFY',
            'ANALYSIS_RUN', 'FINDING_CREATE', 'REPORT_CREATE', 'REPORT_READ',
            'REPORT_EXPORT', 'AUDIT_READ', 'SYSTEM_MANAGE', 'JOB_READ', 'JOB_CANCEL'
        ],
        'INVESTIGATOR': [
            'CASE_CREATE', 'CASE_READ', 'CASE_UPDATE', 'EVIDENCE_UPLOAD',
            'EVIDENCE_READ', 'EVIDENCE_VERIFY', 'ANALYSIS_RUN', 'FINDING_CREATE',
            'REPORT_CREATE', 'REPORT_READ', 'REPORT_EXPORT', 'AUDIT_READ',
            'JOB_READ', 'JOB_CANCEL'
        ],
        'ANALYST': [
            'CASE_READ', 'EVIDENCE_READ', 'ANALYSIS_RUN', 'FINDING_CREATE',
            'REPORT_READ', 'JOB_READ'
        ],
        'VIEWER': [
            'CASE_READ', 'EVIDENCE_READ', 'REPORT_READ'
        ]
    }
    for role, permissions in defaults.items():
        db['roles'].update_one(
            {'name': role},
            {'$setOnInsert': {'name': role, 'created_at': now}},
            upsert=True
        )
        for permission in permissions:
            db['roles'].update_one(
                {'name': role},
                {'$addToSet': {'permissions': permission}}
            )
