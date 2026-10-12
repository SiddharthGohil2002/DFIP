"""Opening encrypted volumes with the investigator's key: BitLocker (libbde: password or 48-digit recovery password,
BitLocker To Go included) and LUKS (libluksde: passphrase), read in-process from the image (or its working copy).

The decrypted volume is written once to a file that becomes evidence of its own (see tasks.volume_decrypt_task),
with its hash and a custody record; the encrypted original is never changed.
"""
from __future__ import annotations
import re
from pathlib import Path

from .source import OffsetFile, SECTOR

METHODS = {'BitLocker': ('password', 'recovery_password'), 'LUKS': ('password',)}
METHOD_LABELS = {'password': 'password', 'recovery_password': 'recovery password'}
_RECOVERY = re.compile(r'^\d{6}(?:-\d{6}){7}$')


class WrongKey(ValueError):
    """The key does not open the volume."""


def check_secret(kind: str, method: str, secret: str) -> str:
    """The secret, normalised, or ValueError with what is wrong (the secret itself is never put in the message)."""
    if kind not in METHODS:
        raise ValueError(f'{kind} volumes cannot be unlocked')
    if method not in METHODS[kind]:
        raise ValueError(f'A {kind} volume is unlocked with: {", ".join(METHOD_LABELS[m] for m in METHODS[kind])}')
    if not secret or len(secret) > 1024:
        raise ValueError('Give the password or key (at most 1,024 characters)')
    if method == 'recovery_password':
        secret = secret.strip().replace(' ', '-')
        if not _RECOVERY.match(secret) or any(int(g) % 11 for g in secret.split('-')):
            raise ValueError('A BitLocker recovery password is 48 digits in 8 groups of 6 (each group divisible by 11)')
    return secret


class UnlockedVolume:
    """The plaintext of an encrypted volume: size, read(offset, length), close()."""

    def __init__(self, volume, window):
        self._v = volume
        self._w = window
        self.size = int(volume.get_size())

    def read(self, offset: int, length: int) -> bytes:
        self._v.seek(offset)
        return self._v.read(length)

    def close(self):
        for x in (self._v, self._w):
            try:
                x.close()
            except Exception:
                pass


def open_volume(image: Path, start_sector: int, length: int | None, kind: str, method: str, secret: str) -> UnlockedVolume:
    window = OffsetFile(image, start_sector * SECTOR, length)
    try:
        if kind == 'BitLocker':
            import pybde
            v = pybde.volume()
            (v.set_recovery_password if method == 'recovery_password' else v.set_password)(secret)
        elif kind == 'LUKS':
            import pyluksde
            v = pyluksde.volume()
            v.set_password(secret)
        else:
            raise ValueError(f'{kind} volumes cannot be unlocked')
        try:
            v.open_file_object(window)
        except OSError as exc:
            if kind == 'LUKS' and 'key' in str(exc).lower():
                raise WrongKey(f'The {METHOD_LABELS[method]} does not unlock this {kind} volume') from None
            raise ValueError(f'The {kind} volume could not be opened: {exc}') from None
        if v.is_locked():
            v.close()
            raise WrongKey(f'The {METHOD_LABELS[method]} does not unlock this {kind} volume')
        return UnlockedVolume(v, window)
    except BaseException:
        window.close()
        raise
