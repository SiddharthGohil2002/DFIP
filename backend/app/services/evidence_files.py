"""What the analysis keeps on disk for each evidence item, under storage/analysis/ and named by its evidence ID."""
import os
from pathlib import Path

from ..core.config import settings

# Folders named by the evidence ID: recovered and carved files, the pipeline's work, archive members (also those of
# mailboxes and captures), thumbnails, pictures' derivatives, decrypted volumes, an unpacked package.
_AREAS = ('recovered', 'carved', 'pipeline', 'members', 'members/mail', 'members/capture', 'thumbs', 'media', 'derived', 'package')


def remove_path(path: Path, storage: Path, removed: list, problems: list):
    """Deletes a file or directory, but only inside the DFIP storage area."""
    try:
        p = path.resolve()
        if storage not in p.parents or not p.exists():
            return
        if p.is_dir():
            from ..forensic.packages import remove_tree
            remove_tree(p)  # clears read-only flags where the storage needs it
        else:
            if not os.access(p, os.W_OK):
                p.chmod(0o600)
            p.unlink()
        removed.append(str(p))
    except OSError as e:
        problems.append(f'{path}: {e.strerror or e}')


def remove_analysis_outputs(eid: str, storage: Path, removed: list, problems: list):
    """Deletes everything the analysis wrote for one evidence item (not the evidence itself)."""
    analysis = storage / 'analysis'
    for p in (analysis / 'working').glob(f'{eid}.*'):  # the raw working copy (and an unfinished export)
        remove_path(p, storage, removed, problems)
    for area in _AREAS:
        remove_path(analysis / area / eid, storage, removed, problems)
    for p in (analysis / 'package').glob(f'{eid}.*'):  # the package's manifest (and an unfinished unpack)
        remove_path(p, storage, removed, problems)
    for p in (analysis / 'text').glob(f'{eid}.*'):  # the content index (and an unfinished rebuild)
        remove_path(p, storage, removed, problems)


def new_evidence_id(db) -> str:
    """The next evidence ID (EVID-NNN), with nothing on disk under it yet.

    IDs are never reused within a database, so anything already stored under a new ID was left by an earlier one:
    storage/ is a folder on the host and outlives `docker compose down -v`, which starts the counter again. Left there,
    a working copy or unpacked package would be taken as this evidence's own (it is reused once it exists), and the
    analysis would show another image's files."""
    from .sequences import next_sequence
    eid = f'EVID-{next_sequence("evidence", floor=db["evidence"].count_documents({})):03d}'
    removed, problems = [], []
    remove_analysis_outputs(eid, Path(settings.storage_path).resolve(), removed, problems)
    if removed or problems:
        print(f'[DFIP] {eid}: removed {len(removed)} analysis output(s) an earlier database left under this ID'
              + (f'; could not remove: {"; ".join(problems)}' if problems else ''), flush=True)
    return eid
