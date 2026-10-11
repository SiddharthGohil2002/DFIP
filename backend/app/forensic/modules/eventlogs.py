"""Windows event logs: every record of every .evtx log under Windows/System32/winevt/Logs, what the catalogued events
mean, detections by the curated Sigma rules, and USB connect and remove times added to the USB device history.

Every record is stored (searchable on the event log page). Catalogued events get a plain-English description and a
category; the notable ones (and every record a detection rule matched) also become timeline events. USB events
(Partition/Diagnostic 1006, Kernel-PnP, DriverFrameworks, UserPnp) are matched to the USB devices found by the
artifacts module through their serial numbers; a device seen only in the event logs is added as one.

See app/forensic/eventlogs.py (reading), event_catalog.py (meaning) and sigma_lite.py with backend/rules/sigma (detections).
"""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime, timezone

from .. import event_catalog as cat
from .. import sigma_lite
from ..eventlogs import EvtxLog
from ..source import BlobRef, TskImageSource
from ..timeline import _with_nk
from ..usb import split_instance
from .base import Module

LOGS = r'/Windows/System32/winevt/Logs/[^/]+\.evtx$'
XP_LOGS = r'/Windows/System32/config/[^/]+\.evt$'
MAX_RECORDS_PER_LOG = 250_000
MAX_RECORDS_TOTAL = 1_000_000
MAX_TIMELINE = 200_000
MAX_DEVICE_EVENTS = 500
BATCH = 1000
TEXT_CHARS = 4000

# USB device events: which records say a device was connected or removed, and how to read the serial number.
USB_ACTIONS = {
    ('microsoft-windows-partition/diagnostic', 1006): None,  # connected, or removed when Capacity is 0
    ('microsoft-windows-kernel-pnp/configuration', 400): 'configured',
    ('microsoft-windows-kernel-pnp/configuration', 410): 'connected',
    ('microsoft-windows-kernel-pnp/configuration', 420): 'deleted',
    ('microsoft-windows-driverframeworks-usermode/operational', 2003): 'connected',
    ('microsoft-windows-driverframeworks-usermode/operational', 2100): 'removing',
    ('microsoft-windows-driverframeworks-usermode/operational', 2102): 'removed',
    ('system', 20001): 'driver installed',
    ('system', 20003): 'driver service added',
}
_USB_PARENT = re.compile(r'USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})\\([^\\#\s]+)', re.I)
_USBSTOR = re.compile(r'USBSTOR[\\#]([^\\#]+)[\\#]([^\\#\s]+)', re.I)
_VENDOR = re.compile(r'VEN_([^&]*)&PROD_([^&]*)(?:&REV_(\w*))?', re.I)


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


def _iso(dt):
    return dt.isoformat() if hasattr(dt, 'isoformat') else dt


def log_label(name: str) -> str:
    """A log's channel-style name from its file name: Microsoft-Windows-Partition%4Diagnostic.evtx -> .../Partition/Diagnostic."""
    return re.sub(r'\.evtx$', '', name, flags=re.I).replace('%4', '/')


def usb_identity(rec: dict) -> dict | None:
    """The serial number (and VID/PID, vendor, product) of the USB device a device event is about, if any."""
    data = rec.get('data') or {}
    texts = [str(v) for v in data.values()] + [str(v) for v in rec.get('data_values') or []]
    out: dict = {}
    for t in texts:
        m = _USB_PARENT.search(t)
        if m and not out.get('serial'):
            out.update(vid=m.group(1).upper(), pid=m.group(2).upper(), serial=m.group(3))
        s = _USBSTOR.search(t)
        if s:
            serial, unique = split_instance(s.group(2))
            out.setdefault('instance_id', s.group(2))
            if not out.get('serial'):
                out['serial'], out['serial_is_unique'] = serial, unique
            v = _VENDOR.search(s.group(1))
            if v:
                out.setdefault('vendor', v.group(1).replace('_', ' ').strip())
                out.setdefault('product', v.group(2).replace('_', ' ').strip())
                out.setdefault('revision', v.group(3))
    if not out.get('serial') and data.get('SerialNumber', '').strip():
        out['serial'] = data['SerialNumber'].strip()
    if data.get('Manufacturer'):
        out['vendor'] = data['Manufacturer'].strip()
    if data.get('Model'):
        out['product'] = data['Model'].strip()
    if data.get('Revision'):
        out['revision'] = data['Revision'].strip()
    return out if out.get('serial') else None


class EventLogsModule(Module):
    name = 'eventlogs'
    label = 'Windows event logs'
    description = ('Every record of the Windows event logs (.evtx): logons, failed logons, account and group changes, cleared logs, '
                   'services, scheduled tasks, Remote Desktop, PowerShell, USB devices, Microsoft Defender, startup and shutdown; '
                   'detections by the curated Sigma rules; USB connect and remove times.')
    requires = ('fs_index',)
    follows = ('computer', 'artifacts')
    weight = 15
    collections = ('event_records', 'forensic_artifacts', 'timeline_events', 'usb_artifacts')
    fields = {'usb_artifacts': ('eventlog_events', 'eventlog_first_connected', 'eventlog_last_connected', 'eventlog_last_removed')}

    def run(self, ctx):
        self.ctx = ctx
        for key in ('event_logs', 'event_records', 'recovered_event_records', 'notable_events', 'eventlog_detections', 'timeline_events'):
            ctx.count(key, 0)
        q = {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False, 'is_dir': False, 'container': {'$exists': False}}
        entries = list(ctx.db['fs_entries'].find(dict(q, path={'$regex': LOGS, '$options': 'i'}),
                                                 {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1}).sort('path', 1))
        if ctx.db['fs_entries'].count_documents(dict(q, path={'$regex': XP_LOGS, '$options': 'i'}), limit=1):
            ctx.warn('Windows XP / 2003 event logs (.evt) were found; DFIP reads only .evtx logs (Windows Vista and later)')
        if not entries:
            return
        try:
            self.engine = sigma_lite.Engine(sigma_lite.load_rules())
        except sigma_lite.RuleError as exc:
            ctx.warn(f'Detection rules could not be loaded, so no detections were run: {exc}')
            self.engine = sigma_lite.Engine([])
        self.accounts = dict(ctx.fact('computer', 'accounts', {}) or {})
        self.learned: dict[str, str] = {}
        self.timeline: list[dict] = []
        self.timeline_capped = False
        self.usb: list[dict] = []
        self.total = 0
        src = TskImageSource(ctx.image)
        logs = []
        for n, e in enumerate(entries):
            ctx.progress(n / len(entries), e['path'].rsplit('/', 1)[-1])
            if not e.get('size'):
                continue
            info = self._log(src, e, n)
            if info:
                logs.append(info)
            if self.total >= MAX_RECORDS_TOTAL:
                ctx.warn(f'Only the first {MAX_RECORDS_TOTAL:,} event records were read; {len(entries) - n - 1} more logs were not')
                break
        self._detections()
        self._usb_merge()
        events = _with_nk(self.timeline)
        for i in range(0, len(events), BATCH):
            ctx.insert('timeline_events', events[i:i + BATCH])
        ctx.count('timeline_events', len(events))
        ctx.count('event_logs', len(logs))
        ctx.set_fact('logs', logs)

    # -- one log -------------------------------------------------------------------------
    def _name(self, sid: str) -> str:
        return self.accounts.get(sid) or self.learned.get(sid) or ''

    def _learn(self, rec):
        """SID -> name pairs the events themselves state (a deleted account is still named by the event that created it)."""
        d = rec.get('data') or {}
        for sid_f, name_f in (('SubjectUserSid', 'SubjectUserName'), ('TargetUserSid', 'TargetUserName'), ('TargetSid', 'TargetUserName')):
            sid, name = d.get(sid_f), d.get(name_f)
            if sid and name and sid.startswith('S-1-') and name not in ('-', '') and sid not in self.learned:
                self.learned[sid] = name

    def _log(self, src, e, n):
        ctx = self.ctx
        local = ctx.work / 'eventlogs' / f'{n:03d}.evtx'
        try:
            size, sha256 = src.copy_to(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']), local)
        except Exception as exc:
            ctx.warn(f'{e["path"]}: could not be copied out: {exc}')
            return None
        log = EvtxLog(local, min(MAX_RECORDS_PER_LOG, MAX_RECORDS_TOTAL - self.total))
        name = e['path'].rsplit('/', 1)[-1]
        batch, first, last, channels = [], None, None, {}
        try:
            for rec in log.records():
                doc = self._record(rec, e['path'], name)
                batch.append(doc)
                t = doc.get('time')
                if t:
                    first = t if first is None or t < first else first
                    last = t if last is None or t > last else last
                if doc.get('channel'):
                    channels[doc['channel']] = channels.get(doc['channel'], 0) + 1
                if len(batch) >= BATCH:
                    ctx.insert('event_records', batch)
                    batch = []
                    ctx.checkpoint()
            ctx.insert('event_records', batch)
        finally:
            local.unlink(missing_ok=True)
        st = log.stats
        self.total += st['records'] + st['recovered']
        ctx.count('event_records', st['records'])
        ctx.count('recovered_event_records', st['recovered'])
        for err in st['errors'][:5]:
            ctx.warn(f'{e["path"]}: {err}')
        if st['capped']:
            ctx.warn(f'{e["path"]}: only the first {log.max_records:,} records were read')
        if not st.get('valid', True):
            ctx.warn(f'{e["path"]}: the file header is not an event log header')
        return {'path': e['path'], 'name': name, 'channel': max(channels, key=channels.get) if channels else None,
                'records': st['records'], 'recovered': st['recovered'], 'unreadable': st['unreadable'], 'first': _iso(first), 'last': _iso(last),
                'size': size, 'sha256': sha256, 'dirty': st.get('dirty'), 'full': st.get('full'), 'corrupted': st.get('corrupted'),
                'capped': st['capped'], 'version': st.get('version'), 'errors': st['errors'][:5]}

    def _record(self, rec, path, name):
        ctx = self.ctx
        if rec.get('channel') == 'Windows PowerShell' and (rec.get('data_values') or rec.get('data')):
            text = (rec.get('data_values') or [''])[-1] or ' '.join(str(v) for v in (rec.get('data') or {}).values())
            rec['details'] = cat.classic_powershell_details(text)
            decoded = cat.decode_encoded_command(rec['details'].get('HostApplication', ''))
            if decoded:
                rec['details']['DecodedCommand'] = decoded
        self._learn(rec)
        meaning = cat.describe(rec, self._name)
        rec['level_name'] = cat.level_name(rec)
        nk = _nk(path, rec.get('record_id'), rec.get('event_id'), _iso(rec.get('time')), rec.get('recovered'), rec.get('offset'))
        hits = self.engine.match(rec, nk)
        notable = meaning['notable'] or bool(hits)
        values = [str(v) for v in (rec.get('data') or {}).values()] + [str(v) for v in rec.get('data_values') or []]
        doc = {k: v for k, v in rec.items() if k not in ('keywords_int',)}
        doc.update(case_id=ctx.case_id, evidence_id=ctx.eid, nk=nk, log=name, log_path=path, user=meaning['user'],
                   category=meaning['category'], title=meaning['title'], description=meaning['description'],
                   timeline_type=meaning['timeline'], notable=notable, detections=hits,
                   text=' '.join([meaning['description'] or '', *values])[:TEXT_CHARS])
        if notable:
            ctx.count('notable_events')
            self._timeline(doc)
        key = ((doc.get('channel') or '').lower(), doc.get('event_id'))
        if key in USB_ACTIONS:
            ident = usb_identity(doc)
            if ident:
                action = USB_ACTIONS[key] or ('removed' if (doc.get('data') or {}).get('Capacity') == '0' else 'connected')
                self.usb.append(dict(ident, action=action, time=doc.get('time'), log=name, log_path=path, event_id=doc.get('event_id'),
                                     record_id=doc.get('record_id'), nk=nk))
        return doc

    def _timeline(self, doc):
        if doc.get('timeline_type') is None and not doc.get('detections'):
            return  # notable, but described elsewhere (USB device events become USB_ACTIVITY events)
        if doc.get('time') is None:
            return
        if len(self.timeline) >= MAX_TIMELINE:
            if not self.timeline_capped:
                self.timeline_capped = True
                self.ctx.warn(f'Only the first {MAX_TIMELINE:,} notable events were put on the timeline')
            return
        self.timeline.append({'case_id': doc['case_id'], 'evidence_id': doc['evidence_id'], 'timestamp': doc['time'],
                              'type': doc.get('timeline_type') or 'EVENTLOG_ALERT',
                              'description': doc.get('description') or f'{doc.get("channel")} event {doc.get("event_id")}',
                              'source': 'EVENT_LOG', 'source_file': doc['log_path'], 'event_id': doc.get('event_id'),
                              'record_id': doc.get('record_id'), 'channel': doc.get('channel'), 'user': doc.get('user'),
                              'event_nk': doc['nk']})

    # -- detections ------------------------------------------------------------------------
    def _detections(self):
        ctx = self.ctx
        detections = self.engine.finish()
        col = ctx.db['event_records']
        now = datetime.now(timezone.utc)
        rows = []
        for d in detections:
            keys = d.pop('record_keys')
            if d.get('aggregation'):  # aggregating rules: mark the records now that the counts are known
                newly = list(col.find({'evidence_id': ctx.eid, 'nk': {'$in': keys}, 'notable': False}))
                col.update_many({'evidence_id': ctx.eid, 'nk': {'$in': keys}},
                                {'$addToSet': {'detections': d['rule_id']}, '$set': {'notable': True}})
                for doc in newly:
                    doc['detections'] = [d['rule_id']]
                    ctx.count('notable_events')
                    self._timeline(doc)
            sample = [x.get('description') or f'{x.get("channel")} event {x.get("event_id")}'
                      for x in col.find({'evidence_id': ctx.eid, 'nk': {'$in': keys[:5]}}, {'description': 1, 'channel': 1, 'event_id': 1})]
            rows.append(dict(d, artifact_id=str(uuid.uuid4()), case_id=ctx.case_id, evidence_id=ctx.eid, type='EVENTLOG_DETECTION',
                             source='EVENT_LOG', record_nks=keys, sample=sample, timestamp=now,
                             nk=_nk('EVENTLOG_DETECTION', d['rule_id'], sorted((d.get('group') or {}).items()))))
        ctx.insert('forensic_artifacts', rows)
        ctx.count('eventlog_detections', len(rows))

    # -- USB ---------------------------------------------------------------------------------
    def _usb_merge(self):
        ctx = self.ctx
        if not self.usb:
            return
        col = ctx.db['usb_artifacts']
        devices = list(col.find({'evidence_id': ctx.eid}, {'serial': 1, 'friendly_name': 1, 'vendor': 1, 'product': 1}))
        by_serial = {(d.get('serial') or '').upper(): d for d in devices if d.get('serial')}
        groups: dict[str, list[dict]] = {}
        for ev in sorted(self.usb, key=lambda x: (x['time'] is None, x['time'] or 0)):
            groups.setdefault(ev['serial'].upper(), []).append(ev)
        new_docs, now = [], datetime.now(timezone.utc)
        for serial, evs in groups.items():
            connected = [e['time'] for e in evs if e['action'] == 'connected' and e['time']]
            removed = [e['time'] for e in evs if e['action'] == 'removed' and e['time']]
            fields = {'eventlog_events': [{'time': _iso(e['time']), 'action': e['action'], 'log': e['log'], 'event_id': e['event_id'],
                                           'record_id': e['record_id'], 'nk': e['nk']} for e in evs[:MAX_DEVICE_EVENTS]],
                      'eventlog_first_connected': _iso(min(connected)) if connected else None,
                      'eventlog_last_connected': _iso(max(connected)) if connected else None,
                      'eventlog_last_removed': _iso(max(removed)) if removed else None}
            device = by_serial.get(serial)
            if device is not None:
                col.update_one({'_id': device['_id']}, {'$set': fields})
                label = device.get('friendly_name') or f'{device.get("vendor") or ""} {device.get("product") or ""}'.strip()
                serial_text = device['serial']
            else:
                first = evs[0]
                info = {k: next((e[k] for e in evs if e.get(k)), None) for k in ('vendor', 'product', 'revision', 'vid', 'pid', 'instance_id')}
                serial_text = first['serial']
                label = f'{info["vendor"] or ""} {info["product"] or ""}'.strip()
                new_docs.append(dict(fields, case_id=ctx.case_id, evidence_id=ctx.eid, created_at=now, serial=serial_text,
                                     serial_is_unique=next((e['serial_is_unique'] for e in evs if 'serial_is_unique' in e), True),
                                     instance_id=info['instance_id'] or f'EVENTLOG\\{serial_text}', device_class_id=None,
                                     vendor=info['vendor'], product=info['product'], revision=info['revision'], friendly_name=None,
                                     vid=info['vid'], pid=info['pid'], drive_letters=[], volume_guids=[], control_sets=[],
                                     registry_key=None, source='EVENT_LOG', source_detail={},
                                     first_install=None, last_install=None, last_arrival=None, last_removal=None))
            for e in evs:
                if e['time'] is None or e['action'] not in ('connected', 'removed', 'driver installed'):
                    continue
                self.timeline.append({'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': e['time'], 'type': 'USB_ACTIVITY',
                                      'usb_event': f'EVENTLOG_{e["action"].upper().replace(" ", "_")}',
                                      'description': f'USB device {e["action"]} ({log_label(e["log"])} event {e["event_id"]}, record '
                                                     f'{e["record_id"]}): {label or "USB device"} (serial {serial_text})',
                                      'serial': serial_text, 'source': 'EVENT_LOG', 'source_file': e['log_path'],
                                      'event_id': e['event_id'], 'record_id': e['record_id'], 'event_nk': e['nk']})
        ctx.insert('usb_artifacts', new_docs)
        ctx.count('usb_devices_from_event_logs', len(new_docs))
