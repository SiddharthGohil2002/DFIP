from datetime import datetime, timedelta, timezone
import hashlib, hmac, secrets
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .core.config import settings

bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError('Password must contain at least 12 characters')
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, settings.password_pbkdf2_rounds)
    return f"pbkdf2_sha256${settings.password_pbkdf2_rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = encoded.split('$')
        if scheme != 'pbkdf2_sha256': return False
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def create_access_token(user, client_type: str = 'web'):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        'sub': str(user['_id']),
        'role': user['role'],
        'type': 'access',
        'client': client_type,
        'iat': now,
        'exp': now + timedelta(minutes=settings.access_token_expire_minutes)
    }, settings.jwt_secret, algorithm='HS256')


def create_device_token(user_id: str, device_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({
        'sub': str(user_id),
        'device_id': device_id,
        'type': 'device_session',
        'iat': now,
        'exp': now + timedelta(days=30)
    }, settings.jwt_secret, algorithm='HS256')


def decode_device_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=['HS256'])
        if payload.get('type') != 'device_session':
            raise HTTPException(401, 'Invalid device token')
        return payload
    except jwt.PyJWTError:
        raise HTTPException(401, 'Invalid or expired device token')


def create_refresh_token(user):
    raw = secrets.token_urlsafe(48)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    return raw, {
        'user_id': str(user['_id']),
        'token_hash': digest,
        'created_at': now,
        'expires_at': now + timedelta(days=settings.refresh_token_expire_days),
        'revoked': False
    }


def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=['HS256'])
        if payload.get('type') != 'access': raise HTTPException(401, 'Invalid access token')
        return payload
    except jwt.PyJWTError:
        raise HTTPException(401, 'Invalid or expired token')


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds: raise HTTPException(401, 'Authentication required')
    from .repositories.users import get_user_by_id
    payload = decode_token(creds.credentials)
    user = get_user_by_id(payload.get('sub'))
    if not user or user.get('status') != 'ACTIVE': raise HTTPException(401, 'User is inactive')
    user['_client_type'] = payload.get('client', 'web')
    return user


def require_roles(*roles):
    def dependency(user=Depends(current_user)):
        if user.get('role') not in roles: raise HTTPException(403, 'Insufficient role privileges')
        return user
    return dependency


def require_permission(permission: str):
    def dependency(user=Depends(current_user)):
        if user.get('role') == 'ADMIN': return user
        from .database import get_db
        role = get_db()['roles'].find_one({'name': user.get('role')}) or {}
        if permission not in role.get('permissions', []): raise HTTPException(403, f'Missing permission: {permission}')
        return user
    return dependency


def require_write(permission: str):
    """Guards a mutating endpoint: always enforces the RBAC permission, and also
    requires a registered desktop workstation when REQUIRE_DESKTOP_FOR_WRITES is on."""
    def dependency(request: Request, user=Depends(require_permission(permission))):
        if settings.require_desktop_for_writes:
            require_desktop_workstation(request, user)
        return user
    return dependency


def require_desktop_workstation(request: Request, user=Depends(current_user)):
    """Verifies that the request originates from an authorized, registered desktop workstation.
    
    Web clients are strictly read-only and prohibited from mutating operations.
    """
    device_id = request.headers.get('X-DFIP-Device-Id') or request.query_params.get('device_id')
    device_token = request.headers.get('X-DFIP-Device-Token') or request.query_params.get('device_token')
    
    if not device_id or not device_token:
        raise HTTPException(
            status_code=403,
            detail="This operation requires the authorized DFIP Desktop application. The web portal is read-only."
        )

    # Validate device token signature and claims
    try:
        payload = decode_device_token(device_token)
    except HTTPException:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired desktop workstation token. Please re-authenticate via the desktop application."
        )

    if payload.get('device_id') != device_id or payload.get('sub') != str(user['_id']):
        raise HTTPException(
            status_code=403,
            detail="Workstation token does not match the active user and device identity."
        )

    from .database import get_db
    device = get_db()['desktop_devices'].find_one({
        'device_id': device_id,
        'user_id': str(user['_id']),
        'status': {'$in': ['ACTIVE', 'ONLINE']}
    })
    if not device:
        raise HTTPException(
            status_code=403,
            detail="Unregistered or deactivated desktop workstation device."
        )

    return user
