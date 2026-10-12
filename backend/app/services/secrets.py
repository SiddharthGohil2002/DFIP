"""Secrets DFIP has to keep, such as the passwords and recovery keys of encrypted volumes, stored encrypted.

Fernet (AES-128-CBC with an HMAC-SHA256 tag). The key is derived with HKDF-SHA256 from DATA_ENCRYPTION_KEY, or
from JWT_SECRET when that is not set; changing it makes the stored secrets unreadable (they are then entered
again). A secret is decrypted only by the job that uses it; it never goes into job payloads, results, logs or API
responses.
"""
from __future__ import annotations
import base64
from functools import lru_cache

from ..core.config import settings


@lru_cache(maxsize=4)
def _fernet(material: str):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'dfip-stored-secrets', info=b'fernet v1').derive(material.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def _key_material() -> str:
    return settings.data_encryption_key or settings.jwt_secret


def encrypt(text: str) -> str:
    return _fernet(_key_material()).encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    from cryptography.fernet import InvalidToken
    try:
        return _fernet(_key_material()).decrypt(token.encode()).decode()
    except InvalidToken:
        raise ValueError('The stored secret cannot be decrypted: DATA_ENCRYPTION_KEY (or JWT_SECRET) has changed since it was '
                         'stored. Enter the password or recovery key again.') from None
