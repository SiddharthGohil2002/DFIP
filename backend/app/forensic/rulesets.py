"""Malware signatures administrators add: YARA rule sets and ClamAV databases.

YARA rule sets are text files compiled before they are accepted, with `include` refused (an include could read any file
the server can). ClamAV databases (the official .cvd/.cld files, from freshclam or copied in offline, and custom
signature files such as .hdb hash lists or .ndb body signatures) are checked by loading them with clamscan. Both live in
the storage volume: storage/yara/<set id>.yar and storage/clamav/.
"""
from __future__ import annotations
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_RULES_BYTES = 2 << 20
CLAMAV_EXTS = ('.cvd', '.cld', '.cud', '.hdb', '.hsb', '.hdu', '.hsu', '.mdb', '.msb', '.mdu', '.msu', '.ndb', '.ndu', '.ldb', '.ldu',
               '.cdb', '.fp', '.sfp', '.ign', '.ign2', '.ftm', '.pdb', '.gdb', '.wdb', '.idb', '.crb', '.cat', '.info')
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')


def _storage() -> Path:
    from ..core.config import settings
    return Path(settings.storage_path).resolve()


def yara_root() -> Path:
    p = _storage() / 'yara'
    p.mkdir(parents=True, exist_ok=True)
    return p


def clamav_dir() -> Path:
    p = _storage() / 'clamav'
    p.mkdir(parents=True, exist_ok=True)
    return p


def validate_yara(text: str) -> list[str]:
    """The rule names in a YARA source, after compiling it; ValueError for a syntax error or an include."""
    import yara
    if re.search(r'^\s*include\s+"', text, re.M):
        raise ValueError('Rule sets may not include other files')
    try:
        rules = yara.compile(source=text, includes=False)
    except yara.SyntaxError as exc:
        raise ValueError(f'The rules do not compile: {exc}') from exc
    names = [r.identifier for r in rules]
    if not names:
        raise ValueError('The file holds no rules')
    return names


def compile_rules(default: Path, sets: list[dict]):
    """DFIP's own rules and every enabled rule set, each in its own namespace (the set ID)."""
    import yara
    paths = {'dfip': str(default)} if default.is_file() else {}
    for s in sets:
        p = yara_root() / f'{s["set_id"]}.yar'
        if p.is_file():
            paths[s['set_id']] = str(p)
    return yara.compile(filepaths=paths, includes=False) if paths else None


def clamav_databases() -> list[dict]:
    """The database files in storage/clamav, with their size, SHA-256, signature count and (official ones) version."""
    out = []
    for p in sorted(clamav_dir().iterdir()):
        if not p.is_file() or p.suffix.lower() not in CLAMAV_EXTS:
            continue
        info = {'name': p.name, 'size': p.stat().st_size, 'modified': datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc),
                'sha256': _sha256(p)}
        if p.suffix.lower() in ('.cvd', '.cld', '.cud'):
            with p.open('rb') as f:
                head = f.read(512).decode('latin-1', 'replace').split(':')
            if head and head[0] == 'ClamAV-VDB' and len(head) > 4:
                info.update(built=head[1].strip(), version=head[2], signatures=int(head[3]) if head[3].isdigit() else None)
        else:
            with p.open('rb') as f:
                info['signatures'] = sum(1 for line in f if line.strip() and not line.startswith(b'#'))
        out.append(info)
    return out


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def validate_clamav(path: Path, run_tool) -> None:
    """Loads a database file alone with clamscan (exit 0 or 1 is a usable database, 2 an error)."""
    probe = path.parent / 'probe.txt'
    probe.write_bytes(b'DFIP database check\n')
    try:
        r = run_tool(['clamscan', '--no-summary', f'--database={path}', str(probe)], timeout=600, memory_bytes=8 << 30)
    finally:
        probe.unlink(missing_ok=True)
    if r.get('status') == 'TOOL_UNAVAILABLE':
        raise ValueError('ClamAV is not installed on the server')
    if r.get('returncode') not in (0, 1):
        raise ValueError(f'ClamAV cannot load this database: {(r.get("stderr") or r.get("stdout") or "").strip()[:300]}')
