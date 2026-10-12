from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
from ..security import current_user, require_permission, require_write
from bson import ObjectId
from ..repositories.cases import list_cases, create_case, get_case, col
from ..services.audit import log
from ..services.notifications import create as notify, create_sync as notify_sync
from ..database import get_db
from ..websocket.manager import manager

r = APIRouter(prefix='/cases', tags=['cases'])

class CaseCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = ''
    priority: str = 'MEDIUM'
    investigator_id: str | None = None

class CaseUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=120)
    description: str | None = None
    priority: str | None = None
    status: str | None = None
    investigator_id: str | None = None

@r.get('')
def get_cases(u=Depends(current_user)):
    return {'data': list_cases(u)}

@r.get('/{case_id}')
def one(case_id: str, u=Depends(current_user)):
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    return c

@r.post('')
def post_case(x: CaseCreate, u=Depends(require_write('CASE_CREATE'))):
    if x.priority not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'Invalid priority')
    if x.investigator_id:
        assignee = get_db()['users'].find_one({'_id': ObjectId(x.investigator_id), 'status': 'ACTIVE'}) if ObjectId.is_valid(x.investigator_id) else None
        if not assignee:
            raise HTTPException(400, 'Invalid investigator assignment')
    
    c = create_case(x.model_dump(), u)
    log(u, 'CASE_CREATED', 'case', c['_id'], {'case_id': c['case_id']})
    
    # Broadcast to all clients (both web and desktop)
    manager.emit_sync('CASE_CREATED', {
        'case_id': c['case_id'],
        'name': c['name'],
        'priority': c['priority'],
        'status': c['status'],
        'created_at': c['created_at']
    })
    
    if c.get('investigator_id') and c['investigator_id'] != str(u['_id']):
        notify_sync(c['investigator_id'], 'Case assigned', f'{c["case_id"]} was assigned to you.')
    return c

@r.patch('/{case_id}')
async def update_case(case_id: str, x: CaseUpdate, u=Depends(require_write('CASE_UPDATE'))):
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    updates = {k: v for k, v in x.model_dump().items() if v is not None}
    if 'name' in updates:
        updates['name'] = updates['name'].strip()
        if len(updates['name']) < 2:
            raise HTTPException(400, 'Case name must have at least 2 characters')
    if 'investigator_id' in updates:
        try:
            assignee = get_db()['users'].find_one({'_id': ObjectId(updates['investigator_id']), 'status': 'ACTIVE'})
        except Exception:
            assignee = None
        if not assignee:
            raise HTTPException(400, 'Invalid investigator assignment')
    if 'status' in updates and updates['status'] not in {'OPEN', 'IN_PROGRESS', 'ON_HOLD', 'COMPLETED', 'ARCHIVED'}:
        raise HTTPException(400, 'Invalid status')
    if 'priority' in updates and updates['priority'] not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        raise HTTPException(400, 'Invalid priority')
    
    updates['updated_at'] = datetime.now(timezone.utc)
    col().update_one({'case_id': case_id}, {'$set': updates})
    fresh = get_case(case_id, u)
    log(u, 'CASE_UPDATED', 'case', fresh['_id'], updates)
    
    manager.emit_sync('CASE_UPDATED', {
        'case_id': case_id,
        'updates': updates
    })
    
    target = updates.get('investigator_id') or c.get('investigator_id')
    if target and target != str(u['_id']):
        await notify(target, 'Case updated', f'{case_id} was updated.', 'INFO')
    return fresh


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


@r.get('/{case_id}/overview')
def overview(case_id: str, u=Depends(current_user)):
    """Everything the case workspace shows at a glance: evidence with analysis
    state, per-function counts and the latest jobs."""
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    evidence = list(db['evidence'].find({'case_id': case_id}, {
        'evidence_id': 1, 'filename': 1, 'format': 1, 'size': 1, 'sha256': 1, 'verification_status': 1,
        'analysis_status': 1, 'analysis_summary': 1, 'last_analysis_job': 1, 'analyzed_at': 1,
        'created_at': 1, 'demo': 1, 'derived_from': 1, 'image_set': 1}).sort('created_at', 1))
    eids = [e['evidence_id'] for e in evidence]
    art = db['forensic_artifacts']
    counts = {
        'evidence': len(evidence),
        'evidence_analyzed': sum(1 for e in evidence if e.get('analysis_status') == 'COMPLETED'),
        'files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'is_virtual': False, 'container': {'$exists': False}}),
        'deleted_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'deleted': True, 'is_virtual': False,
                                                           'container': {'$exists': False}}),
        'archive_members': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'container': {'$exists': True}}),
        'recovered_files': art.count_documents({'case_id': case_id, 'type': 'RECOVERED_FILE'}),
        'carved_files': art.count_documents({'case_id': case_id, 'type': 'CARVED_FILE'}),
        'timeline_events': db['timeline_events'].count_documents({'case_id': case_id}),
        'browser_history': art.count_documents({'case_id': case_id, 'type': 'BROWSER_HISTORY'}),
        'browser_downloads': art.count_documents({'case_id': case_id, 'type': 'BROWSER_DOWNLOAD'}),
        'browser_searches': art.count_documents({'case_id': case_id, 'type': 'BROWSER_SEARCH'}),
        'browser_cookies': art.count_documents({'case_id': case_id, 'type': 'BROWSER_COOKIE'}),
        'browser_bookmarks': art.count_documents({'case_id': case_id, 'type': 'BROWSER_BOOKMARK'}),
        'browser_autofill': art.count_documents({'case_id': case_id, 'type': 'BROWSER_AUTOFILL'}),
        'browser_logins': art.count_documents({'case_id': case_id, 'type': 'BROWSER_LOGIN'}),
        'browser_recovered': art.count_documents({'case_id': case_id, 'type': 'BROWSER_RECOVERED'}),
        'email_stores': art.count_documents({'case_id': case_id, 'type': 'EMAIL_STORE'}),
        'email_messages': db['email_messages'].count_documents({'case_id': case_id}),
        'email_attachments': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'container.kind': 'email',
                                                               'container.note': None}),
        'chat_messages': art.count_documents({'case_id': case_id, 'type': 'CHAT_MESSAGE'}),
        'chat_calls': art.count_documents({'case_id': case_id, 'type': 'CHAT_CALL'}),
        'chat_file_transfers': art.count_documents({'case_id': case_id, 'type': 'CHAT_FILE_TRANSFER'}),
        'chat_contacts': art.count_documents({'case_id': case_id, 'type': 'CHAT_CONTACT'}),
        'chat_apps': art.count_documents({'case_id': case_id, 'type': 'CHAT_APP'}),
        'cloud_accounts': art.count_documents({'case_id': case_id, 'type': 'CLOUD_ACCOUNT'}),
        'cloud_files': art.count_documents({'case_id': case_id, 'type': 'CLOUD_FILE', 'is_folder': False}),
        'pictures': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'media.kind': 'picture'}),
        'videos': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'media.kind': 'video'}),
        'media_with_gps': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'media.gps': {'$exists': True}}),
        'ocr_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'ocr.text': {'$exists': True}}),
        'programs': art.count_documents({'case_id': case_id, 'type': 'EXECUTABLE'}),
        'programs_flagged': art.count_documents({'case_id': case_id, 'type': 'EXECUTABLE', 'score': {'$gte': 3}}),
        'clamav_detections': art.count_documents({'case_id': case_id, 'type': 'MALWARE_INDICATOR', 'source': 'CLAMAV'}),
        'reputation_malicious': art.count_documents({'case_id': case_id, 'type': 'EXECUTABLE', 'vt.malicious': {'$gt': 0}}),
        'usb_devices': db['usb_artifacts'].count_documents({'case_id': case_id}),
        'programs_run': art.count_documents({'case_id': case_id, 'type': 'PROGRAM_RUN'}),
        'recent_files': art.count_documents({'case_id': case_id, 'type': 'RECENT_FILE'}),
        'recycle_bin_items': art.count_documents({'case_id': case_id, 'type': 'RECYCLE_BIN_ITEM'}),
        'user_accounts': art.count_documents({'case_id': case_id, 'type': 'USER_ACCOUNT'}),
        'programs_executed': art.count_documents({'case_id': case_id, 'type': {'$in': ['USERASSIST', 'BAM_ENTRY', 'AMCACHE_FILE']}}),
        'folders_browsed': art.count_documents({'case_id': case_id, 'type': 'SHELLBAG'}),
        'user_searches': art.count_documents({'case_id': case_id, 'type': {'$in': ['EXPLORER_SEARCH', 'TYPED_PATH', 'TYPED_URL', 'RUN_MRU']}}),
        'persistence_entries': art.count_documents({'case_id': case_id, 'type': 'PERSISTENCE'}),
        'persistence_flagged': art.count_documents({'case_id': case_id, 'type': 'PERSISTENCE', 'flags.0': {'$exists': True}}),
        'installed_programs': art.count_documents({'case_id': case_id, 'type': 'INSTALLED_PROGRAM'}),
        'event_records': db['event_records'].count_documents({'case_id': case_id}),
        'notable_events': db['event_records'].count_documents({'case_id': case_id, 'notable': True}),
        'event_detections': art.count_documents({'case_id': case_id, 'type': 'EVENTLOG_DETECTION'}),
        'jumplist_entries': art.count_documents({'case_id': case_id, 'type': 'JUMPLIST_ENTRY'}),
        'timeline_activities': art.count_documents({'case_id': case_id, 'type': 'TIMELINE_ACTIVITY'}),
        'thumbnails': art.count_documents({'case_id': case_id, 'type': 'THUMBNAIL'}),
        'srum_records': art.count_documents({'case_id': case_id, 'type': {'$in': ['SRUM_NETWORK', 'SRUM_APP_USAGE', 'SRUM_CONNECTIVITY']}}),
        'search_index_entries': art.count_documents({'case_id': case_id, 'type': 'SEARCH_INDEX_ENTRY'}),
        'timestomp_suspects': art.count_documents({'case_id': case_id, 'type': 'TIMESTOMP_SUSPECT', 'level': 'strong'}),
        'alternate_streams': art.count_documents({'case_id': case_id, 'type': 'ALTERNATE_STREAM'}),
        'usn_records': db['usn_records'].count_documents({'case_id': case_id}),
        'shadow_copies': sum(len((f.get('shadow_copies') or {}).get('stores') or [])
                             for f in db['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'shadow_copies.stores.store': 1})),
        'shadow_files': db['shadow_files'].count_documents({'case_id': case_id}),
        'shadow_deleted': db['shadow_files'].count_documents({'case_id': case_id, 'change': 'DELETED_SINCE'}),
        'decrypted_volumes': sum(1 for e in evidence if e.get('derived_from')),
        'search_entries_not_on_disk': art.count_documents({'case_id': case_id, 'type': 'SEARCH_INDEX_ENTRY',
                                                           'file_state': {'$in': ['deleted', 'not on the disk']}}),
        'renamed_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'ext_mismatch': True}),
        'encrypted_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'encryption': {'$ne': None, '$exists': True}}),
        'known_bad_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'hash_status': 'KNOWN_BAD'}),
        'notable_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'hash_status': 'NOTABLE'}),
        'found_data': db['entities'].count_documents({'evidence_id': {'$in': eids}}),
        'malware_indicators': art.count_documents({'case_id': case_id, 'type': 'MALWARE_INDICATOR'}),
        'patterns': db['patterns'].count_documents({'case_id': case_id}),
        'anomalies_flagged': db['anomalies'].count_documents({'case_id': case_id, 'is_anomaly': True}),
        'findings': db['findings'].count_documents({'case_id': case_id}),
        'tags': db['tags'].count_documents({'case_id': case_id}),
        'reports': db['reports'].count_documents({'case_id': case_id}),
        'custody_events': db['chain_of_custody'].count_documents({'case_id': case_id}),
    }
    jobs = list(db['jobs'].find({'payload.evidence_id': {'$in': eids}}, {
        'job_id': 1, 'type': 1, 'status': 1, 'progress': 1, 'stage': 1, 'error': 1, 'payload': 1,
        'created_at': 1, 'finished_at': 1}).sort('created_at', -1).limit(8))
    return {'case': c, 'evidence': _plain(evidence), 'counts': counts, 'jobs': _plain(jobs)}


@r.get('/{case_id}/dashboard')
def dashboard(case_id: str, tz: str = 'UTC', scope: str = 'activity', evidence_id: str | None = None, u=Depends(current_user)):
    """Activity charts for the case: day-of-week x hour heatmap, events per day, top websites, file types and
    USB connection spans. scope=activity counts user activity only; scope=all adds filesystem (MACB) times."""
    from pymongo.errors import OperationFailure
    from ..analysis import dashboard as dash
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if scope not in ('activity', 'all'):
        raise HTTPException(400, 'scope must be activity or all')
    if not dash.valid_tz(tz):
        raise HTTPException(400, 'tz must be UTC, an offset such as +05:30, or a time zone name such as Asia/Kolkata')
    db = get_db()
    types = dash.ACTIVITY_TYPES if scope == 'activity' else None
    q = dash.event_query(case_id, types, evidence_id)
    eids = [evidence_id] if evidence_id else [e['evidence_id'] for e in db['evidence'].find({'case_id': case_id}, {'evidence_id': 1})]
    try:
        heat, days = dash.heatmap(db, q, tz), dash.per_day(db, q, tz)
    except OperationFailure:
        raise HTTPException(400, f'Unknown time zone: {tz}')
    return {'tz': tz, 'scope': scope, 'types': types, 'heatmap': heat, 'per_day': days,
            'top_domains': dash.top_domains(db, case_id, evidence_id), 'file_types': dash.file_types(db, eids),
            'usb_spans': _plain(dash.usb_spans(db, case_id, evidence_id))}


class ThreatIntelIn(BaseModel):
    auto_lookup: bool


@r.put('/{case_id}/threat-intel')
def threat_intel_setting(case_id: str, body: ThreatIntelIn, u=Depends(require_write('CASE_UPDATE'))):
    """Turns automatic VirusTotal lookups of this case's program hashes on or off (off unless an investigator turns them
    on). Only SHA-256 hashes are sent. Turning them on looks up the programs of the evidence already analysed."""
    from ..core.config import settings
    from ..tasks import _rematch_all
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    now = datetime.now(timezone.utc)
    setting = {'auto_lookup': body.auto_lookup, 'set_by': str(u['_id']), 'set_by_name': u.get('name'), 'set_at': now}
    get_db()['cases'].update_one({'case_id': case_id}, {'$set': {'threat_intel': setting, 'updated_at': now}})
    jobs = _rematch_all(str(u['_id']), 'reputation', case_id) if body.auto_lookup else []
    log(u, 'THREAT_INTEL_AUTO_LOOKUP_SET', 'case', c['_id'], {'case_id': case_id, 'auto_lookup': body.auto_lookup,
                                                              'key_configured': bool(settings.virustotal_api_key)})
    manager.emit_sync('CASE_UPDATED', {'case_id': case_id})
    return {'case_id': case_id, 'threat_intel': _plain(setting), 'key_configured': bool(settings.virustotal_api_key), 'jobs': jobs}


class LegalHoldIn(BaseModel):
    active: bool
    reason: str = Field(min_length=5, max_length=500)

    @field_validator('reason', mode='before')
    @classmethod
    def strip_reason(cls, v):
        return v.strip() if isinstance(v, str) else v


@r.post('/{case_id}/legal-hold')
def legal_hold(case_id: str, body: LegalHoldIn, u=Depends(require_write('LEGAL_HOLD_MANAGE'))):
    """Places or releases a legal hold. While a case is held, its evidence cannot be deleted.
    (Separate from the case status ON_HOLD, which only describes the work.)"""
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    current = c.get('legal_hold') or {}
    if bool(current.get('active')) == body.active:
        raise HTTPException(409, f'{case_id} is {"already" if body.active else "not"} under legal hold')
    now = datetime.now(timezone.utc)
    who = {'user_id': str(u['_id']), 'name': u.get('name')}
    if body.active:
        hold = {'active': True, 'reason': body.reason, 'set_by': who['user_id'], 'set_by_name': who['name'], 'set_at': now}
    else:
        hold = {**current, 'active': False, 'released_by': who['user_id'], 'released_by_name': who['name'],
                'released_at': now, 'release_reason': body.reason}
    event = {'action': 'PLACED' if body.active else 'RELEASED', 'reason': body.reason, 'by': who['name'], 'at': now}
    get_db()['cases'].update_one({'case_id': case_id}, {'$set': {'legal_hold': hold, 'updated_at': now}, '$push': {'legal_hold_history': event}})
    fresh = get_case(case_id)
    log(u, 'LEGAL_HOLD_PLACED' if body.active else 'LEGAL_HOLD_RELEASED', 'case', fresh['_id'], {'case_id': case_id, 'reason': body.reason})
    manager.emit_sync('CASE_UPDATED', {'case_id': case_id, 'legal_hold': body.active})
    if fresh.get('investigator_id') and fresh['investigator_id'] != str(u['_id']):
        notify_sync(fresh['investigator_id'], 'Legal hold placed' if body.active else 'Legal hold released',
                    f'{case_id} {"is now under" if body.active else "is no longer under"} legal hold ({u.get("name")}): {body.reason}')
    return _plain(fresh)
