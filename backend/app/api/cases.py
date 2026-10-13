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

class DeleteCase(BaseModel):
    confirm: str = Field(min_length=1, max_length=60)
    reason: str = Field(min_length=5, max_length=500)

    @field_validator('reason', 'confirm', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class Members(BaseModel):
    member_ids: list[str] = Field(default_factory=list, max_length=200)


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
    unset = {}
    if 'status' in updates and updates['status'] != c.get('status'):
        # Closing a case starts its retention period; reopening it ends it (services/retention.py).
        from ..services.retention import on_status_change
        extra, unset = on_status_change(c.get('status'), updates['status'], updates['updated_at'])
        updates.update(extra)
    col().update_one({'case_id': case_id}, {'$set': updates, **({'$unset': unset} if unset else {})})
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
        'unix_systems': sum(len((f.get('unix') or {}).get('systems') or [])
                            for f in db['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'unix.systems': 1})),
        'shell_commands': art.count_documents({'case_id': case_id, 'type': 'SHELL_COMMAND'}),
        'shell_commands_flagged': art.count_documents({'case_id': case_id, 'type': 'SHELL_COMMAND', 'flags.0': {'$exists': True}}),
        'unix_events': art.count_documents({'case_id': case_id, 'type': 'UNIX_EVENT'}),
        'scheduled_jobs': art.count_documents({'case_id': case_id, 'type': 'SCHEDULED_JOB'}),
        'scheduled_jobs_flagged': art.count_documents({'case_id': case_id, 'type': 'SCHEDULED_JOB', 'notable': True}),
        'recent_documents': art.count_documents({'case_id': case_id, 'type': 'RECENT_DOCUMENT'}),
        'quarantine_events': art.count_documents({'case_id': case_id, 'type': 'QUARANTINE_EVENT'}),
        'wifi_networks': art.count_documents({'case_id': case_id, 'type': 'WIFI_NETWORK'}),
        'captures': sum(1 for e in evidence if str(e.get('format', '')).upper() == 'PCAP'),
        'net_conversations': art.count_documents({'case_id': case_id, 'type': 'NET_CONVERSATION'}),
        'dns_queries': art.count_documents({'case_id': case_id, 'type': 'DNS_QUERY'}),
        'http_requests': art.count_documents({'case_id': case_id, 'type': 'HTTP_REQUEST'}),
        'http_uploads': art.count_documents({'case_id': case_id, 'type': 'HTTP_REQUEST', 'files': {'$elemMatch': {'direction': 'request', 'part': True}}}),
        'tls_handshakes': art.count_documents({'case_id': case_id, 'type': 'TLS_HANDSHAKE'}),
        'capture_files': db['fs_entries'].count_documents({'evidence_id': {'$in': eids}, 'container.kind': 'capture'}),
        'phones': art.count_documents({'case_id': case_id, 'type': 'PHONE_DEVICE'}),
        'phone_messages': art.count_documents({'case_id': case_id, 'type': 'PHONE_MESSAGE', 'app': {'$ne': 'WhatsApp'}}),
        'whatsapp_messages': art.count_documents({'case_id': case_id, 'type': 'PHONE_MESSAGE', 'app': 'WhatsApp'}),
        'phone_calls': art.count_documents({'case_id': case_id, 'type': 'PHONE_CALL'}),
        'phone_contacts': art.count_documents({'case_id': case_id, 'type': 'PHONE_CONTACT'}),
        'phone_apps': art.count_documents({'case_id': case_id, 'type': 'PHONE_APP'}),
        'phone_apps_notable': art.count_documents({'case_id': case_id, 'type': 'PHONE_APP', 'notable': True}),
        'phone_wifi': art.count_documents({'case_id': case_id, 'type': 'PHONE_WIFI'}),
        'memory_images': sum(1 for e in evidence if str(e.get('format', '')).upper() == 'MEMORY'),
        'memory_processes': art.count_documents({'case_id': case_id, 'type': 'MEMORY_PROCESS'}),
        'memory_processes_notable': art.count_documents({'case_id': case_id, 'type': 'MEMORY_PROCESS', 'notable': True}),
        'memory_connections': art.count_documents({'case_id': case_id, 'type': 'MEMORY_CONNECTION'}),
        'memory_injections': art.count_documents({'case_id': case_id, 'type': 'MEMORY_INJECTION'}),
        'memory_services': art.count_documents({'case_id': case_id, 'type': 'MEMORY_SERVICE'}),
        'timeline_imports': db['timeline_imports'].count_documents({'case_id': case_id}),
        'plaso_events': db['timeline_events'].count_documents({'case_id': case_id, 'type': 'PLASO_EVENT'}),
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
        'findings_in_review': db['findings'].count_documents({'case_id': case_id, 'status': 'IN_REVIEW'}),
        'findings_approved': db['findings'].count_documents({'case_id': case_id, 'status': 'APPROVED'}),
        'physical_items': db['physical_items'].count_documents({'case_id': case_id}),
        'physical_checked_out': db['physical_items'].count_documents({'case_id': case_id, 'status': 'CHECKED_OUT'}),
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


@r.get('/{case_id}/people')
def people(case_id: str, u=Depends(current_user)):
    """Who can see the case (its investigator, creator and members, and the administrators): the people a comment can
    mention and a finding can be sent to for review (`can_review`)."""
    from ..services.team import case_people
    c = col().find_one({'case_id': case_id})
    if not c or not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    return {'data': case_people(c)}


@r.put('/{case_id}/members')
def set_members(case_id: str, x: Members, u=Depends(require_write('CASE_UPDATE'))):
    """Shares the case with other users (besides its investigator and creator): they can then see it, comment and be
    asked to review findings, as their role allows. Added members are notified; every change is audited."""
    from ..services.team import case_people
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    ids = list(dict.fromkeys(i for i in x.member_ids if i))
    found = {str(v['_id']) for v in get_db()['users'].find({'_id': {'$in': [ObjectId(i) for i in ids if ObjectId.is_valid(i)]}, 'status': 'ACTIVE'}, {'_id': 1})}
    unknown = [i for i in ids if i not in found]
    if unknown:
        raise HTTPException(400, f'Not active users: {", ".join(unknown)}')
    before = set(c.get('member_ids') or [])
    added, removed = [i for i in ids if i not in before], sorted(before - set(ids))
    now = datetime.now(timezone.utc)
    col().update_one({'case_id': case_id}, {'$set': {'member_ids': ids, 'updated_at': now}})
    log(u, 'CASE_MEMBERS_CHANGED', 'case', c['_id'], {'case_id': case_id, 'added': added, 'removed': removed})
    manager.emit_sync('CASE_UPDATED', {'case_id': case_id, 'members': ids})
    for uid in added:
        if uid != str(u['_id']):
            notify_sync(uid, 'Added to a case', f'{u.get("name")} added you to {case_id} ({c["name"]}).')
    return {'member_ids': ids, 'added': added, 'removed': removed, 'people': case_people(col().find_one({'case_id': case_id}))}


@r.delete('/{case_id}')
def delete_case(case_id: str, body: DeleteCase, u=Depends(require_write('CASE_DELETE'))):
    """Deletes a case's data (administrators, typically when its retention period has ended): every evidence item as
    evidence deletion does, findings, comments, tags, reports, imported timelines and physical-evidence records. The
    name must be typed to confirm. Refused under legal hold (423), while work runs on its evidence (409) and while
    physical evidence is still held (409). The case remains as a record that it existed (`deleted`), with the chain of
    custody and the audit trail."""
    from .evidence import ACTIVE_JOB_STATES, _delete_one, _derived_tree
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    if body.confirm != case_id:
        raise HTTPException(400, f'Type the case number ({case_id}) to confirm')
    hold = c.get('legal_hold') or {}
    if hold.get('active'):
        raise HTTPException(423, f'{case_id} is under legal hold ({hold.get("set_by_name")}: {hold.get("reason")}); release the hold first')
    db = get_db()
    evidence = list(db['evidence'].find({'case_id': case_id}))
    active = db['jobs'].find_one({'payload.evidence_id': {'$in': [e['evidence_id'] for e in evidence]}, 'status': {'$in': ACTIVE_JOB_STATES}},
                                 {'job_id': 1, 'status': 1})
    if active:
        raise HTTPException(409, f"{active['job_id']} is {active['status'].lower()}; wait for it or cancel it first")
    held = [p['item_id'] for p in db['physical_items'].find({'case_id': case_id, 'status': {'$in': ['IN_STORAGE', 'CHECKED_OUT']}}, {'item_id': 1})]
    if held:
        raise HTTPException(409, f'Physical evidence is still held ({", ".join(held)}): release or dispose of it first, recording the custody')
    reason = f'Case deleted: {body.reason}'
    done, removed, warnings = [], 0, []
    derived = {d['evidence_id'] for e in evidence for d in _derived_tree(db, e['evidence_id'])}
    for e in sorted(evidence, key=lambda e: e['evidence_id'] not in derived):  # derived copies before what they came from
        if db['evidence'].find_one({'_id': e['_id']}, {'_id': 1}):
            out = _delete_one(db, e, u, reason)
            done.append(out['evidence_id'])
            removed += out['files_removed']
            warnings += out['warnings']
    from pathlib import Path
    from ..core.config import settings
    counts = {'evidence': len(done)}
    import shutil
    from ..services.finding_files import root as finding_root
    for f in db['findings'].find({'case_id': case_id}, {'_id': 1}):
        shutil.rmtree(finding_root() / str(f['_id']), ignore_errors=True)
    for name, q in (('findings', {'case_id': case_id}), ('comments', {'case_id': case_id}), ('tags', {'case_id': case_id}),
                    ('timeline_events', {'case_id': case_id}), ('forensic_artifacts', {'case_id': case_id}), ('patterns', {'case_id': case_id}),
                    ('anomalies', {'case_id': case_id}), ('ai_requests', {'case_id': case_id})):
        counts[name] = db[name].delete_many(q).deleted_count
    storage = Path(settings.storage_path).resolve()
    for rep in db['reports'].find({'case_id': case_id}, {'path': 1, 'html_path': 1}):
        for p in (Path(rep.get('path') or ''), Path(rep.get('html_path') or '')):
            if p.is_file() and storage in p.resolve().parents:
                p.unlink()
                removed += 1
    counts['reports'] = db['reports'].delete_many({'case_id': case_id}).deleted_count
    from .timeline_imports import remove_import
    counts['timeline_imports'] = 0
    for imp in db['timeline_imports'].find({'case_id': case_id}):
        remove_import(db, imp)
        counts['timeline_imports'] += 1
    import shutil
    for p in db['physical_items'].find({'case_id': case_id}, {'item_id': 1}):
        folder = storage / 'physical' / p['item_id']
        if folder.is_dir():
            shutil.rmtree(folder, ignore_errors=True)
    counts['physical_items'] = db['physical_items'].delete_many({'case_id': case_id}).deleted_count
    now = datetime.now(timezone.utc)
    col().update_one({'case_id': case_id}, {'$set': {'deleted': True, 'status': 'DELETED', 'deleted_at': now, 'deleted_by': str(u['_id']),
                                                     'deleted_by_name': u.get('name'), 'deletion_reason': body.reason, 'updated_at': now}})
    log(u, 'CASE_DELETED', 'case', c['_id'], {'case_id': case_id, 'name': c.get('name'), 'reason': body.reason, 'removed': counts,
                                               'files_removed': removed})
    manager.emit_sync('CASE_DELETED', {'case_id': case_id})
    return {'case_id': case_id, 'deleted': True, 'removed': counts, 'files_removed': removed, 'warnings': warnings}


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


@r.get('/{case_id}/graph')
def graph(case_id: str, types: str | None = None, focus: str | None = None, u=Depends(current_user)):
    """The case's link graph: people, devices, files, programs, internet hosts and accounts joined by what the records
    say (each edge with up to three of its records). `types` limits the node types (comma separated); `focus` returns
    one node and its neighbours."""
    from ..services.graph import TYPES, view
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    wanted = {t.strip() for t in (types or '').split(',') if t.strip()}
    if wanted - set(TYPES):
        raise HTTPException(400, f'types must be among {", ".join(TYPES)}')
    if focus and len(focus) > 400:
        raise HTTPException(400, 'focus is too long')
    return view(case_id, wanted or None, focus)
