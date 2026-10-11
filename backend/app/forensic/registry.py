"""Shared helpers for reading Windows registry hives with regipy.

Every hive-based parser (SYSTEM for USB history today; SAM, SOFTWARE, NTUSER.DAT, UsrClass.dat and Amcache.hve
later) reads copies extracted from the evidence image through these helpers, so value decoding and key lookup
behave the same everywhere. Missing keys and values are reported as absent, never guessed.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def open_hive(path):
    """A regipy RegistryHive for an extracted hive file (imported lazily: regipy is only needed by the worker)."""
    from regipy.registry import RegistryHive
    return RegistryHive(str(path))


def as_bytes(raw) -> bytes | None:
    """REG_BINARY data as bytes; regipy returns binary values as bytes or as a hex string."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None
    return None


def filetime_to_datetime(raw) -> datetime | None:
    """A Windows FILETIME (8 little-endian bytes, 100 ns since 1601) as a UTC datetime, or None when unset."""
    b = as_bytes(raw)
    if not b or len(b) < 8:
        return None
    ft = int.from_bytes(b[:8], 'little')
    if ft <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def signed_dword(value):
    """A REG_DWORD holding a signed number (regipy returns it unsigned)."""
    if not isinstance(value, int):
        return None
    return value - (1 << 32) if value >= (1 << 31) else value


def values(key) -> dict:
    """A key's values by name ('(default)' or '' for the default value, depending on the hive)."""
    return {v.name: v.value for v in key.iter_values()}


def subkey(key, name):
    """A direct subkey by name, case-insensitively (registry names are case-insensitive), or None."""
    for s in key.iter_subkeys():
        if s.name.lower() == name.lower():
            return s
    return None


def control_sets(reg) -> list[str]:
    """SYSTEM hive control sets, the current one (from \\Select) first."""
    names = []
    try:
        current = values(reg.get_key('\\Select')).get('Current')
        if current:
            names.append(f'ControlSet{int(current):03d}')
    except Exception:
        pass
    for s in reg.get_key('\\').iter_subkeys():
        if s.name.lower().startswith('controlset') and s.name not in names:
            names.append(s.name)
    return names
