"""File carving: recovers deleted/unallocated files from a disk image by
signature scanning, using PhotoRec or Scalpel as the underlying engine.

Follows the same safety pattern as forensic/tools.py: allow-listed binaries,
no shell=True, bounded timeouts, and carved output is written only to DFIP's
own analysis directory — never back to the source image.
"""
from __future__ import annotations
import shutil
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ENGINES = {
    'photorec': 'photorec',   # TestDisk suite; supports /log /d /cmd batch mode
    'scalpel': 'scalpel',     # config-driven signature carver
}


def engine_availability() -> dict:
    return {name: {'binary': binary, 'available': bool(shutil.which(binary))}
            for name, binary in ENGINES.items()}


def carve_with_photorec(image_path: Path, output_dir: Path, timeout: int = 1800) -> dict:
    """Runs PhotoRec in non-interactive batch mode against a raw/E01-decoded
    image. PhotoRec's /cmd batch syntax carves the whole device and writes
    recup_dir.N folders into output_dir; we don't attempt to cherry-pick file
    types here so we don't silently drop artifact categories the investigator
    didn't know to ask for.
    """
    binary = shutil.which(ENGINES['photorec'])
    if not binary:
        return {'status': 'TOOL_UNAVAILABLE', 'engine': 'photorec'}
    output_dir.mkdir(parents=True, exist_ok=True)
    # `/d <prefix>` is a path prefix: PhotoRec writes <prefix>.1/, <prefix>.2/ ...
    # `/cmd <image> <options>` runs headless; the options are ONE comma-joined
    # argument. partition_none = treat the image as a whole disk; wholespace =
    # scan free and allocated space (the point of carving is recovering deleted data).
    # All signatures are enabled except 'dovecot', whose weak header matches
    # registry hive pages and floods results with hundreds of false positives.
    cmd = [binary, '/log', '/d', str(output_dir / 'recup_dir'), '/cmd', str(image_path),
           'partition_none,options,paranoid,fileopt,everything,enable,dovecot,disable,wholespace,search']
    try:
        # cwd = output_dir so photorec.log lands with the carved output.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, shell=False,
                              cwd=str(output_dir))
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'engine': 'photorec', 'timeout_seconds': timeout}
    recovered = _inventory_recovered_files(output_dir)
    return {
        'status': 'COMPLETED' if proc.returncode == 0 else 'FAILED',
        'engine': 'photorec', 'returncode': proc.returncode,
        'stdout': proc.stdout[-20_000:], 'stderr': proc.stderr[-20_000:],
        'recovered_files': recovered,
    }


def carve_with_scalpel(image_path: Path, output_dir: Path, config_path: Path, timeout: int = 1800) -> dict:
    """Runs Scalpel with an explicit signature config file (required — Scalpel
    refuses to run meaningfully without one). DFIP ships backend/rules/scalpel.conf,
    whose enabled file types are listed in that file so investigators can see
    exactly what the default run looks for."""
    binary = shutil.which(ENGINES['scalpel'])
    if not binary:
        return {'status': 'TOOL_UNAVAILABLE', 'engine': 'scalpel'}
    if not config_path.is_file():
        return {'status': 'FAILED', 'engine': 'scalpel', 'error': 'No scalpel config file supplied'}
    # Scalpel refuses to write into an existing non-empty directory.
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    cmd = [binary, '-c', str(config_path), '-o', str(output_dir), str(image_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'engine': 'scalpel', 'timeout_seconds': timeout}
    recovered = _inventory_recovered_files(output_dir)
    return {
        'status': 'COMPLETED' if proc.returncode == 0 else 'FAILED',
        'engine': 'scalpel', 'returncode': proc.returncode,
        'stdout': proc.stdout[-20_000:], 'stderr': proc.stderr[-20_000:],
        'recovered_files': recovered,
    }


def _inventory_recovered_files(output_dir: Path, max_files: int = 20_000) -> list[dict]:
    """Walks the carver's output directory and hashes every recovered file so
    each one is independently verifiable and can be chain-of-custody tracked
    like any other forensic artifact. Real hashes only — a file that fails to
    hash (e.g. permissions) is reported as an error entry, not silently
    dropped or given a placeholder hash."""
    out = []
    if not output_dir.exists():
        return out
    for p in sorted(output_dir.rglob('*')):
        if len(out) >= max_files:
            break
        if not p.is_file():
            continue
        try:
            h = hashlib.sha256()
            with p.open('rb') as f:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
            out.append({'path': str(p), 'filename': p.name, 'size': p.stat().st_size, 'sha256': h.hexdigest()})
        except OSError as exc:
            out.append({'path': str(p), 'filename': p.name, 'error': str(exc)})
    return out


def carve(engine: str, image_path: Path, output_dir: Path, scalpel_config: Path | None = None, timeout: int = 1800) -> dict:
    if engine == 'photorec':
        result = carve_with_photorec(image_path, output_dir, timeout)
    elif engine == 'scalpel':
        if not scalpel_config:
            return {'status': 'FAILED', 'engine': 'scalpel', 'error': 'scalpel_config is required'}
        result = carve_with_scalpel(image_path, output_dir, scalpel_config, timeout)
    else:
        return {'status': 'FAILED', 'error': f'Unknown carving engine: {engine}'}
    result['started_at'] = datetime.now(timezone.utc).isoformat()
    return result
