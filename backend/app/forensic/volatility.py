"""The Volatility 3 command DFIP runs on memory images, and the symbol packs it reads.

Volatility needs the symbols of the exact kernel in an image. They come from symbol packs in the symbols folder
(storage/volatility/symbols, or MEMORY_SYMBOLS_PATH): the official Windows pack (windows.zip) an administrator
downloads or uploads, or packs of ISF files for other kernels. Without one, Volatility may download the kernel's
symbols from Microsoft's symbol server only when MEMORY_SYMBOL_SERVER is on (that sends the kernel's PDB name and
GUID); otherwise it runs offline.
"""
from __future__ import annotations
import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import settings

ISF = re.compile(r'^(windows|linux|mac)/[^/]+(/[^/]+)*\.json(\.xz|\.gz|\.bz2)?$')
PACK_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.zip$')
MAX_PACK_BYTES = 8 << 30
MAX_UNPACKED_BYTES = 64 << 30
TOOL_MEMORY = 8 << 30


def root() -> Path:
    return Path(settings.storage_path).resolve() / 'volatility'


def symbols_dir() -> Path:
    d = Path(settings.memory_symbols_path).resolve() if settings.memory_symbols_path else root() / 'symbols'
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_dir() -> Path:
    d = root() / 'cache'
    d.mkdir(parents=True, exist_ok=True)
    return d


def env() -> dict:
    """Volatility keeps its cache (and symbols built from Microsoft's PDBs) under XDG_CACHE_HOME."""
    return {'XDG_CACHE_HOME': str(cache_dir()), 'HOME': str(cache_dir())}


def argv(image: Path, plugin: str, args: list[str] | None = None) -> list[str]:
    out = ['vol', '-q', '-r', 'json', '--cache-path', str(cache_dir() / 'volatility3'), '-s', str(symbols_dir())]
    if not settings.memory_symbol_server:
        out.append('--offline')
    return out + ['-f', str(image), plugin, *(args or [])]


def check_pack(path: Path) -> dict:
    """What a symbol pack holds (ISF files per system), refusing anything else: other files, names that climb out,
    or more unpacked data than any pack has."""
    if not zipfile.is_zipfile(path):
        raise ValueError('A symbol pack is a ZIP file (such as windows.zip from the Volatility Foundation)')
    counts = {'windows': 0, 'linux': 0, 'mac': 0}
    total = 0
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            name = i.filename
            if name.startswith('/') or '\\' in name or '..' in name.split('/'):
                raise ValueError(f'The pack holds a file outside its folders: {name[:200]}')
            if i.is_dir():
                continue
            if not ISF.match(name):
                raise ValueError(f'The pack holds a file that is not a symbol table (ISF): {name[:200]}')
            counts[name.split('/', 1)[0]] += 1
            total += i.file_size
            if total > MAX_UNPACKED_BYTES:
                raise ValueError('The pack unpacks to more than any symbol pack does')
    if not sum(counts.values()):
        raise ValueError('The pack holds no symbol tables (windows/, linux/ or mac/ folders of ISF files)')
    return {'symbols': counts, 'unpacked_bytes': total}


def _meta_path() -> Path:
    return symbols_dir() / 'packs.json'


def _meta() -> dict:
    try:
        return json.loads(_meta_path().read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def record_pack(name: str, path: Path, how: str, by: str | None, url: str | None = None) -> dict:
    """Keeps what is known of a pack (SHA-256, its symbol tables, how it came) next to it."""
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    info = {**check_pack(path), 'sha256': h.hexdigest(), 'size': path.stat().st_size, 'source': how, 'url': url, 'added_by': by,
            'added_at': datetime.now(timezone.utc).isoformat()}
    meta = _meta()
    meta[name] = info
    _meta_path().write_text(json.dumps(meta, indent=1), encoding='utf-8')
    return info


def forget_pack(name: str):
    meta = _meta()
    meta.pop(name, None)
    _meta_path().write_text(json.dumps(meta, indent=1), encoding='utf-8')


def packs() -> list[dict]:
    """The symbol packs in the symbols folder, and loose ISF files in its windows, linux and mac folders."""
    d, meta = symbols_dir(), _meta()
    out = []
    for p in sorted(d.glob('*.zip')):
        m = meta.get(p.name) or {}
        out.append({'name': p.name, 'size': p.stat().st_size, 'modified': datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
                    'sha256': m.get('sha256'), 'symbols': m.get('symbols'), 'source': m.get('source') or 'placed in the folder',
                    'url': m.get('url'), 'added_by': m.get('added_by'), 'added_at': m.get('added_at')})
    for system in ('windows', 'linux', 'mac'):
        files = [f for f in (d / system).rglob('*') if f.is_file() and ISF.match(f'{system}/{f.relative_to(d / system).as_posix()}')] \
            if (d / system).is_dir() else []
        if files:
            out.append({'name': f'{system}/', 'size': sum(f.stat().st_size for f in files), 'symbols': {system: len(files)}, 'source': 'folder'})
    return out


def version() -> str | None:
    try:
        from importlib.metadata import version as v
        return v('volatility3')
    except Exception:
        return None
