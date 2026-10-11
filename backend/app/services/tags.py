"""Tags (bookmarks) on case items: a file, a timeline event, a browser record, a USB device, a Windows activity
record or a recovered/carved file, marked as Evidence, Notable or Follow up with a note.

Re-running an analysis replaces its records with new database IDs, so a tag also stores the item's natural key
(`match`, the fields that identify it within its evidence item) and a snapshot of what it showed. A tag whose ID
no longer exists is re-linked through `match`; if the item is gone, the snapshot keeps what was tagged.
"""
from __future__ import annotations
import hashlib
import json
from bson import ObjectId

ITEM_COLLECTIONS = {
    'FILE': 'fs_entries', 'TIMELINE_EVENT': 'timeline_events', 'BROWSER': 'forensic_artifacts',
    'USB': 'usb_artifacts', 'ACTIVITY': 'forensic_artifacts', 'ARTIFACT': 'forensic_artifacts',
}
LABELS = ('EVIDENCE', 'NOTABLE', 'FOLLOW_UP')
_ARTIFACT_TYPES = {
    'BROWSER': {'BROWSER_HISTORY', 'BROWSER_DOWNLOAD', 'BROWSER_COOKIE'},
    'ACTIVITY': {'PROGRAM_RUN', 'RECENT_FILE', 'RECYCLE_BIN_ITEM'},
    'ARTIFACT': {'RECOVERED_FILE', 'CARVED_FILE', 'EXTRACTED_FILE', 'MALWARE_INDICATOR'},
}


def find_item(db, item_type: str, item_id: str):
    """The tagged document by its ID (artifact_id for recovered/carved files), checked against its type."""
    col = db[ITEM_COLLECTIONS[item_type]]
    if item_type == 'ARTIFACT':
        doc = col.find_one({'artifact_id': item_id})
    else:
        doc = col.find_one({'_id': ObjectId(item_id)}) if ObjectId.is_valid(str(item_id)) else None
    if doc and item_type in _ARTIFACT_TYPES and doc.get('type') not in _ARTIFACT_TYPES[item_type]:
        return None
    return doc


def item_id_of(item_type: str, doc) -> str:
    return doc['artifact_id'] if item_type == 'ARTIFACT' else str(doc['_id'])


def natural_key(item_type: str, doc) -> dict:
    """Fields that identify the item within its evidence and survive a re-analysis."""
    e = doc.get('evidence_id')
    t = doc.get('type')
    if item_type == 'FILE':
        return {'evidence_id': e, 'partition_offset': doc.get('partition_offset'), 'inode': doc.get('inode'), 'path': doc.get('path')}
    if item_type == 'TIMELINE_EVENT':
        if t == 'FILE_MACB':
            return {'evidence_id': e, 'type': t, 'partition_offset': doc.get('partition_offset'), 'inode': doc.get('inode'),
                    'path': doc.get('path'), 'macb': doc.get('macb'), 'timestamp': doc.get('timestamp')}
        return {'evidence_id': e, 'type': t, 'timestamp': doc.get('timestamp'), 'description': doc.get('description')}
    if item_type == 'BROWSER':
        return {'evidence_id': e, 'type': t, 'source_path': doc.get('source_path'), 'row_id': doc.get('row_id')}
    if item_type == 'USB':
        return {'evidence_id': e, 'instance_id': doc.get('instance_id')}
    if item_type == 'ACTIVITY':
        return {'evidence_id': e, 'type': t, 'source_path': doc.get('source_path')}
    if t == 'MALWARE_INDICATOR':
        return {'evidence_id': e, 'type': t, 'rule': doc.get('rule'), 'original_path': doc.get('original_path')}
    if t == 'EXTRACTED_FILE':
        return {'evidence_id': e, 'type': t, 'original_path': doc.get('original_path')}
    return {'artifact_id': doc.get('artifact_id')}  # recovered and carved files are never replaced


def key_hash(match: dict) -> str:
    return hashlib.sha256(json.dumps(match, sort_keys=True, default=str).encode()).hexdigest()


def _iso(v):
    return v.isoformat() if hasattr(v, 'isoformat') else v


def snapshot(item_type: str, doc) -> dict:
    """What the item showed when it was tagged: a title, a detail line, its time and source."""
    t = doc.get('type')
    if item_type == 'FILE':
        size = '' if doc.get('is_dir') else f' · {doc.get("size"):,} bytes' if isinstance(doc.get('size'), int) else ''
        title, detail, when = doc.get('path'), f'inode {doc.get("inode")}{size}{" · deleted" if doc.get("deleted") else ""}', doc.get('mtime')
    elif item_type == 'TIMELINE_EVENT':
        title, detail, when = doc.get('description'), t, doc.get('timestamp')
    elif item_type == 'BROWSER':
        if t == 'BROWSER_DOWNLOAD':
            title, detail, when = doc.get('target_path'), f'{doc.get("browser") or "Browser"} download from {doc.get("tab_url")}', doc.get('start_time')
        else:
            title, detail, when = doc.get('title') or doc.get('url'), f'{doc.get("browser") or "Browser"} visit: {doc.get("url")}', doc.get('last_visit_time')
    elif item_type == 'USB':
        name = doc.get('friendly_name') or f'{doc.get("vendor") or ""} {doc.get("product") or ""}'.strip()
        title, detail, when = name, f'USB device, serial {doc.get("serial")}', doc.get('first_install') or doc.get('setupapi_first_install')
    elif item_type == 'ACTIVITY':
        if t == 'PROGRAM_RUN':
            title, detail, when = doc.get('executable_path') or doc.get('executable'), f'Program run, run count {doc.get("run_count")}', doc.get('last_run')
        elif t == 'RECENT_FILE':
            drive = ' '.join(x for x in (doc.get('drive_type'), doc.get('volume_label')) if x)
            title, detail, when = doc.get('target_path'), f'File opened{f" ({drive} drive)" if drive else ""}', doc.get('lnk_modified')
        else:
            title, detail, when = doc.get('original_path'), 'Deleted to the Recycle Bin', doc.get('deleted_time')
    else:
        sha = doc.get('sha256')
        label = {'RECOVERED_FILE': 'Recovered file', 'CARVED_FILE': 'Carved file', 'EXTRACTED_FILE': 'Extracted file',
                 'MALWARE_INDICATOR': f'YARA match {doc.get("rule")}'}.get(t, t)
        title = doc.get('original_path') or doc.get('filename')
        detail, when = f'{label}{f" · SHA-256 {sha[:16]}…" if sha else ""}', doc.get('timestamp')
    return {'title': title, 'detail': detail, 'timestamp': _iso(when), 'source': doc.get('source_path') or doc.get('source')}


def resolve(db, tag) -> dict | None:
    """The tagged item now: by ID, else by natural key (re-linking the tag to the item's new ID)."""
    doc = find_item(db, tag['item_type'], tag['item_id'])
    if doc is None and tag.get('match'):
        doc = db[ITEM_COLLECTIONS[tag['item_type']]].find_one(tag['match'])
        if doc is not None:
            db['tags'].update_one({'_id': tag['_id']}, {'$set': {'item_id': item_id_of(tag['item_type'], doc)}})
            tag['item_id'] = item_id_of(tag['item_type'], doc)
    return doc


def relink_evidence(db, evidence_id: str) -> dict:
    """After an analysis run: points this evidence item's tags at the new records."""
    relinked = unresolved = 0
    for tag in db['tags'].find({'evidence_id': evidence_id}):
        before = tag['item_id']
        if resolve(db, tag) is None:
            unresolved += 1
        elif tag['item_id'] != before:
            relinked += 1
    return {'relinked': relinked, 'unresolved': unresolved}
