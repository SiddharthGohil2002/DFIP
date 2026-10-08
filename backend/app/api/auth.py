from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timezone
from typing import Optional
import hashlib
from ..repositories.users import get_by_email, get_user_by_id
from ..security import verify_password, create_access_token, current_user, create_refresh_token, hash_password
from ..core.config import settings
from ..services.notifications import create_sync as notify_sync
from ..database import get_db
from ..services.audit import log

import email_validator

# DFIP runs on premises, where internal mail domains such as corp.local are common;
# email-validator rejects the "local" special-use name unless it is removed here.
if 'local' in email_validator.SPECIAL_USE_DOMAIN_NAMES:
    email_validator.SPECIAL_USE_DOMAIN_NAMES.remove('local')

r = APIRouter(prefix='/auth', tags=['auth'])

class Login(BaseModel):
    email: str
    password: str
    client: Optional[str] = 'web'

class Refresh(BaseModel):
    refresh_token: str

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

def public(u):
    # Permissions come from the role document so clients can hide actions the
    # server would refuse (the server still enforces them on every request).
    role = get_db()['roles'].find_one({'name': u['role']}) or {}
    return {
        '_id': str(u['_id']),
        'name': u['name'],
        'email': u['email'],
        'role': u['role'],
        'status': u['status'],
        'permissions': sorted(role.get('permissions', []))
    }

@r.post('/login')
def login(x: Login, request: Request):
    u = get_by_email(str(x.email).lower())
    if not u or not verify_password(x.password, u.get('password_hash', '')):
        raise HTTPException(401, 'Invalid credentials')
    # Status is only revealed once the password is proven, so it cannot be used to probe accounts.
    if u.get('status') == 'PENDING':
        raise HTTPException(403, 'Your account is waiting for administrator approval.')
    if u.get('status') != 'ACTIVE':
        raise HTTPException(403, 'This account is disabled. Contact your DFIP administrator.')

    client_type = x.client or 'web'
    access = create_access_token(u, client_type=client_type)
    raw, doc = create_refresh_token(u)
    get_db()['refresh_tokens'].insert_one(doc)
    get_db()['users'].update_one(
        {'_id': u['_id']},
        {'$set': {'last_login_at': datetime.now(timezone.utc)}}
    )
    log(u, 'LOGIN', 'user', u['_id'], {
        'ip': request.client.host if request.client else None,
        'client': client_type
    })
    return {
        'access_token': access,
        'refresh_token': raw,
        'token_type': 'bearer',
        'user': public(u)
    }

class Register(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


@r.post('/register', status_code=201)
def register(x: Register, request: Request):
    """Self-service account creation (see REGISTRATION_MODE). New accounts get the
    INVESTIGATOR role, which only reaches cases the user creates or is assigned to."""
    mode = settings.registration_mode
    if mode == 'disabled':
        raise HTTPException(403, 'Account creation is turned off on this server. Ask your DFIP administrator to create an account for you.')
    name = x.name.strip()
    if len(name) < 2:
        raise HTTPException(400, 'Enter your full name.')
    email = str(x.email).lower().strip()
    if get_by_email(email):
        raise HTTPException(409, 'An account with this email already exists. Sign in instead.')
    try:
        password_hash = hash_password(x.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    now = datetime.now(timezone.utc)
    status = 'ACTIVE' if mode == 'open' else 'PENDING'
    doc = {'name': name, 'email': email, 'role': 'INVESTIGATOR', 'status': status, 'password_hash': password_hash,
           'registered_via': 'self', 'created_at': now, 'updated_at': now}
    try:
        res = get_db()['users'].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(409, 'An account with this email already exists. Sign in instead.')
    doc['_id'] = res.inserted_id
    log(doc, 'USER_REGISTERED', 'user', res.inserted_id,
        {'status': status, 'ip': request.client.host if request.client else None})
    if status == 'PENDING':
        for admin in get_db()['users'].find({'role': 'ADMIN', 'status': 'ACTIVE'}, {'_id': 1}):
            notify_sync(admin['_id'], 'Account awaiting approval', f'{name} <{email}> created an account and is waiting for approval.')
    return {'status': status,
            'message': 'Account created. You can sign in now.' if status == 'ACTIVE'
            else 'Account created. An administrator must approve it before you can sign in.'}


@r.post('/refresh')
def refresh(x: Refresh):
    digest = hashlib.sha256(x.refresh_token.encode()).hexdigest()
    db = get_db()
    doc = db['refresh_tokens'].find_one({'token_hash': digest, 'revoked': False})
    if not doc:
        raise HTTPException(401, 'Refresh token invalid or expired')
    
    exp = doc['expires_at']
    if hasattr(exp, 'tzinfo') and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp <= datetime.now(timezone.utc):
        raise HTTPException(401, 'Refresh token invalid or expired')
    
    u = get_user_by_id(doc['user_id'])
    if not u or u.get('status') != 'ACTIVE':
        raise HTTPException(401, 'User is inactive')

    raw, new = create_refresh_token(u)
    db['refresh_tokens'].update_one(
        {'_id': doc['_id']},
        {'$set': {'revoked': True, 'revoked_at': datetime.now(timezone.utc)}}
    )
    db['refresh_tokens'].insert_one(new)
    return {
        'access_token': create_access_token(u),
        'refresh_token': raw,
        'token_type': 'bearer',
        'user': public(u)
    }

@r.post('/logout')
def logout(x: Refresh):
    digest = hashlib.sha256(x.refresh_token.encode()).hexdigest()
    get_db()['refresh_tokens'].update_one(
        {'token_hash': digest},
        {'$set': {'revoked': True, 'revoked_at': datetime.now(timezone.utc)}}
    )
    return {'ok': True}

@r.post('/change-password')
def change_password(x: ChangePassword, u=Depends(current_user)):
    if not verify_password(x.current_password, u.get('password_hash', '')):
        raise HTTPException(400, 'Current password is incorrect')
    from ..security import hash_password
    try:
        new_hash = hash_password(x.new_password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    get_db()['users'].update_one(
        {'_id': u['_id']},
        {'$set': {'password_hash': new_hash, 'updated_at': datetime.now(timezone.utc)}}
    )
    get_db()['refresh_tokens'].update_many(
        {'user_id': str(u['_id'])},
        {'$set': {'revoked': True}}
    )
    log(u, 'PASSWORD_CHANGED', 'user', u['_id'])
    return {'ok': True}

@r.get('/me')
def me(u=Depends(current_user)):
    return public(u)
