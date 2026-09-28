from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone
from typing import Optional
import hashlib
from ..repositories.users import get_by_email, get_user_by_id
from ..security import verify_password, create_access_token, current_user, create_refresh_token
from ..database import get_db
from ..services.audit import log

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
    return {
        '_id': str(u['_id']),
        'name': u['name'],
        'email': u['email'],
        'role': u['role'],
        'status': u['status']
    }

@r.post('/login')
def login(x: Login, request: Request):
    u = get_by_email(str(x.email).lower())
    if not u or not verify_password(x.password, u.get('password_hash', '')) or u.get('status') != 'ACTIVE':
        raise HTTPException(401, 'Invalid credentials')
    
    # Enforce Admin-only access across platform clients
    if u.get('role') != 'ADMIN':
        raise HTTPException(
            status_code=403,
            detail="This account can only access DFIP through the authorized desktop application."
        )

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
    
    if u.get('role') != 'ADMIN':
        raise HTTPException(
            status_code=403,
            detail="This account can only access DFIP through the authorized desktop application."
        )

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
