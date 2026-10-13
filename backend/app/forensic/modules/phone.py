"""Phones (module `phone`): Android and iOS full file system extractions, uploaded as a ZIP or TAR package (or, for
Android, a disk image of the data partition). For each phone: the device (model, OS version, name, time zone), SMS,
MMS, iMessage and WhatsApp messages with their attachments (linked to the files in the extraction when they are
there), calls (phone, FaceTime, app calls), contacts, installed apps (messaging, encryption, VPN and cleaning apps
flagged), saved Wi-Fi networks (never their passwords) and, on an iPhone, Safari's history. Chrome on Android is read by
the browser module. Parsers are in forensic/phones.py.
"""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import phones, unix
from ..source import BlobRef
from ..timeline import browser_events
from .base import Module

MAX_FILE = 64 << 20
MAX_EVENTS = 200_000
BATCH = 20_000
DATA = r'^/data/(?:data|user(?:_de)?/\d+)/'   # an Android app's data folder (/data/data is /data/user/0)
COUNTS = ('phones', 'phone_messages', 'whatsapp_messages', 'phone_calls', 'phone_contacts', 'phone_apps', 'phone_wifi', 'browser_history',
          'timeline_events')


class PhoneModule(Module):
    name = 'phone'
    label = 'Phones'
    description = ('Android and iOS extractions: the device, SMS, MMS, iMessage and WhatsApp messages, calls, contacts, installed apps, '
                   'saved Wi-Fi networks and Safari history.')
    requires = ('fs_index',)
    weight = 6
    collections = ('forensic_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx, self.src = ctx, ctx.source()
        for key in COUNTS:
            ctx.count(key, 0)
        found = []
        for fs in ctx.fact('fs_index', 'filesystems', []) or []:
            vid = fs['volume_id']
            kind = fs.get('os') if fs.get('os') in ('android', 'ios') else self._detect(vid)
            if not kind:
                continue
            self.vid, self.platform, self.docs, self.events, self.n_events = vid, 'Android' if kind == 'android' else 'iOS', [], [], 0
            device = (self._android if kind == 'android' else self._ios)()
            self._flush()
            ctx.count('phones')
            found.append({'volume_id': vid, 'platform': self.platform, 'model': device.get('model'), 'name': device.get('name'),
                          'os_version': device.get('os_version')})
        ctx.set_fact('phones', found)

    # -- helpers -----------------------------------------------------------------------
    def _detect(self, vid):
        if self.src.find(vid, '/system/build.prop') and (self.src.find(vid, '/data/system/packages.xml') or self.src.find(vid, '/data/system/packages.list')):
            return 'android'
        if self.src.find(vid, '/private/var/mobile/Library/SMS/sms.db') or self.src.find(vid, '/private/var/root/Library/Lockdown/data_ark.plist'):
            return 'ios'
        return None

    def _read(self, path: str) -> bytes | None:
        handle = self.src.find(self.vid, path)
        if not handle:
            return None
        try:
            blob = self.src.open(BlobRef(self.ctx.eid, self.vid, inode=handle))
            return blob.read(0, min(blob.size, MAX_FILE))
        except (OSError, ValueError) as exc:
            self.ctx.warn(f'{path}: could not be read: {exc}')
            return None

    def _first(self, *paths) -> tuple[str | None, bytes | None]:
        for p in paths:
            data = self._read(p)
            if data:
                return p, data
        return None, None

    def _files(self, pattern: str) -> list[dict]:
        """Files (not deleted) whose path matches; for Android, one of each where /data/data and /data/user/0 both hold it."""
        rows = list(self.ctx.db['fs_entries'].find({'evidence_id': self.ctx.eid, 'volume_id': self.vid, 'deleted': False, 'is_dir': False,
                                                    'path': {'$regex': pattern}}, {'path': 1, 'inode': 1, 'size': 1}).sort('path', 1))
        seen, out = set(), []
        for r in rows:
            key = (re.sub(DATA, '/', r['path']), r.get('size'))
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out

    def _local(self, entry) -> Path | None:
        """A copy of a database (with its -wal and -journal) for sqlite3."""
        local = self.ctx.work / 'phone' / uuid.uuid4().hex / entry['path'].rsplit('/', 1)[-1]
        try:
            self.src.copy_to(BlobRef(self.ctx.eid, self.vid, inode=entry['inode']), local)
        except (OSError, ValueError) as exc:
            self.ctx.warn(f'{entry["path"]}: could not be read: {exc}')
            return None
        for suffix in ('-wal', '-journal'):
            side = self.src.find(self.vid, entry['path'] + suffix)
            if side:
                self.src.copy_to(BlobRef(self.ctx.eid, self.vid, inode=side), local.parent / (local.name + suffix))
        return local

    def _parse(self, pattern: str, parser) -> list[tuple[dict, dict]]:
        """(file entry, record) for each record a parser reads from each matching database."""
        out = []
        for e in self._files(pattern):
            local = self._local(e)
            if not local:
                continue
            try:
                out += [(e, r) for r in parser(local)]
            except Exception as exc:
                self.ctx.warn(f'{e["path"]}: {exc}')
            self.ctx.checkpoint()
        return out

    def _doc(self, type_, nk: str, **fields) -> dict:
        doc = {'artifact_id': str(uuid.uuid4()), 'case_id': self.ctx.case_id, 'evidence_id': self.ctx.eid, 'type': type_,
               'timestamp': datetime.now(timezone.utc), 'source': 'PHONE', 'os_family': self.platform, 'platform': self.platform,
               'volume_id': self.vid, 'nk': hashlib.sha1(f'{type_}|{self.vid}|{nk}'.encode()).hexdigest(), **fields}
        self.docs.append(doc)
        return doc

    def _flush(self):
        """Writes what has been gathered (a phone can hold hundreds of thousands of messages)."""
        self.ctx.insert('forensic_artifacts', self.docs)
        self.ctx.insert('timeline_events', self.events)
        self.ctx.count('timeline_events', len(self.events))
        self.n_events += len(self.events)
        self.docs, self.events = [], []
        self.ctx.checkpoint()

    def _event(self, when, type_, description, **fields):
        if when and self.n_events + len(self.events) < MAX_EVENTS:
            self.events.append({'case_id': self.ctx.case_id, 'evidence_id': self.ctx.eid, 'timestamp': when, 'type': type_,
                                'description': description[:1000], 'source': 'PHONE', 'volume_id': self.vid, 'platform': self.platform, **fields})

    # -- shared steps --------------------------------------------------------------------
    def _device(self, device: dict, counts: dict):
        self._doc('PHONE_DEVICE', 'device', **device, **counts)

    def _contacts(self, rows: list[tuple[dict, dict]]) -> dict:
        """Stores the contacts and returns {party key: name} for naming the other side of messages and calls."""
        names = {}
        for e, c in rows:
            self._doc('PHONE_CONTACT', f'{e["path"]}|{c["id"]}', source_path=e['path'], **c)
            for v in c['numbers'] + c['emails'] + ([c['whatsapp_id']] if c.get('whatsapp_id') else []):
                k = phones.party_key(v)
                if k and c.get('name'):
                    names.setdefault(k, c['name'])
        self.ctx.count('phone_contacts', len(rows))
        return names

    def _attachment_files(self, messages: list[tuple[dict, dict]], bases):
        """Links each attachment's path on the phone to the file in the extraction, when it is there."""
        wanted = {}
        for e, m in messages:
            for a in m.get('attachments') or []:
                for cand in bases(a.get('device_path'), e['path']):
                    wanted.setdefault(cand, []).append(a)
        paths = list(wanted)
        for i in range(0, len(paths), 5000):
            for f in self.ctx.db['fs_entries'].find({'evidence_id': self.ctx.eid, 'volume_id': self.vid, 'path': {'$in': paths[i:i + 5000]}, 'is_dir': False},
                                                    {'path': 1, 'inode': 1, 'size': 1}):
                for a in wanted[f['path']]:
                    a.setdefault('file', {'path': f['path'], 'inode': f['inode'], 'volume_id': self.vid, 'size': f.get('size')})

    def _messages(self, rows: list[tuple[dict, dict]], names: dict):
        for e, m in rows:
            m['party_name'] = m.get('party_name') or names.get(phones.party_key(m.get('party')))
            if m.get('sender'):
                m['sender_name'] = names.get(phones.party_key(m['sender']))
            whatsapp = m['app'] == 'WhatsApp'
            self._doc('PHONE_MESSAGE', f'{e["path"]}|{m["id"]}', source_path=e['path'], **m)
            who = m.get('chat_name') or m['party_name'] or m.get('party') or 'unknown'
            atts = ', '.join(a['name'] for a in m.get('attachments') or [] if a.get('name'))
            what = (m.get('text') or '').replace('\n', ' ')[:300] + (f' [{atts}]' if atts else '')
            self._event(m['time'], 'PHONE_MESSAGE', f'{m["app"]} {"to" if m["direction"] == "outgoing" else "from"} {who}: {what}',
                        app=m['app'], party=m.get('party'))
            self.ctx.count('whatsapp_messages' if whatsapp else 'phone_messages')
            if len(self.docs) >= BATCH:
                self._flush()

    def _calls(self, rows: list[tuple[dict, dict]], names: dict):
        for e, c in rows:
            c['party_name'] = c.get('party_name') or names.get(phones.party_key(c.get('party')))
            self._doc('PHONE_CALL', f'{e["path"]}|{c["id"]}', source_path=e['path'], **c)
            who = c['party_name'] or c.get('party') or 'unknown number'
            dur = f', {c["duration"] // 60}:{c["duration"] % 60:02d}' if c.get('duration') else ''
            self._event(c['time'], 'PHONE_CALL', f'{c["direction"].capitalize()} {c["kind"]} call {"to" if c["direction"] == "outgoing" else "from"} {who}{dur}',
                        party=c.get('party'))
        self.ctx.count('phone_calls', len(rows))

    def _apps(self, apps: list[dict], source: str):
        for a in apps:
            a['name'] = a.get('name') or a.get('known_name') or a['app_id']
            self._doc('PHONE_APP', a['app_id'], source_path=source, **a)
            self._event(a.get('installed'), 'PHONE_APP', f'Installed {a["name"]} ({a["app_id"]})' + (f' [{a["category"]}]' if a.get('category') else ''),
                        app=a['app_id'])
        self.ctx.count('phone_apps', len(apps))

    def _wifi(self, nets: list[dict], source: str):
        seen = set()
        for n in nets:
            if not n.get('ssid') or n['ssid'] in seen:
                continue
            seen.add(n['ssid'])
            n = {k: v for k, v in n.items() if k not in ('password', 'psk', 'PreSharedKey')}
            self._doc('PHONE_WIFI', n['ssid'], source_path=source, **n)
            self._event(n.get('last_joined'), 'PHONE_WIFI', f'Joined Wi-Fi network {n["ssid"]}', ssid=n['ssid'])
            self.ctx.count('phone_wifi')

    # -- Android -------------------------------------------------------------------------
    def _android(self) -> dict:
        ctx = self.ctx
        props = {}
        for path in ('/system/build.prop', '/system/system/build.prop', '/vendor/build.prop', '/product/etc/build.prop'):
            data = self._read(path)
            if data:
                props = {**phones.build_prop(data), **props}
        settings = {}
        for path in ('/data/system/users/0/settings_global.xml', '/data/system/users/0/settings_secure.xml'):
            data = self._read(path)
            try:
                settings.update({k: v for k, v in phones.android_settings(data).items() if k in ('device_name', 'bluetooth_name') and v} if data else {})
            except Exception as exc:
                ctx.warn(f'{path}: {exc}')
        persistent = phones.persistent_properties(self._read('/data/property/persistent_properties') or b'')
        device = phones.android_device(props, settings, persistent)
        # Apps.
        apps, system, apps_source = [], 0, None
        path, data = self._first('/data/system/packages.xml')
        if data:
            try:
                apps, system = phones.android_packages(data)
                apps_source = path
            except Exception as exc:
                ctx.warn(f'{path}: {exc}')
        if not apps:
            path, data = self._first('/data/system/packages.list')
            if data:
                apps, apps_source = phones.android_packages_list(data), path
        # Contacts first, to name the other side of messages and calls.
        contacts = self._parse(DATA + r'com\.android\.providers\.contacts/databases/contacts2\.db$', phones.android_contacts)
        contacts += self._parse(DATA + r'com\.whatsapp(?:\.w4b)?/databases/wa\.db$', phones.whatsapp_contacts)
        names = self._contacts(contacts)
        sms = self._parse(DATA + r'com\.android\.providers\.telephony/databases/mmssms\.db$', phones.android_sms)
        wa = self._parse(DATA + r'com\.whatsapp(?:\.w4b)?/databases/msgstore\.db$', phones.whatsapp_android)

        def bases(p, db):
            if not p:
                return []
            if p.startswith('/data/user/0/'):
                rest = p[len('/data/user/0/'):]
                return [f'/data/data/{rest}', f'/data/user_de/0/{rest}', p]
            for prefix in ('/storage/emulated/0/', '/sdcard/'):
                if p.startswith(prefix):
                    return [f'/data/media/0/{p[len(prefix):]}']
            if not p.startswith('/'):  # WhatsApp: relative to its media folder
                return [f'/data/media/0/Android/media/com.whatsapp/WhatsApp/{p}', f'/data/media/0/WhatsApp/{p}']
            return [p]
        self._attachment_files(sms + wa, bases)
        self._messages(sms + wa, names)
        calls = self._parse(DATA + r'com\.android\.providers\.contacts/databases/(?:calllog|contacts2)\.db$', phones.android_calls)
        self._calls(calls, names)
        self._apps(apps, apps_source)
        nets = []
        for path in ('/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml', '/data/misc/wifi/WifiConfigStore.xml', '/data/misc/wifi/wpa_supplicant.conf'):
            data = self._read(path)
            if data:
                try:
                    found = phones.wpa_supplicant(data) if path.endswith('.conf') else phones.android_wifi(data)
                except Exception as exc:
                    ctx.warn(f'{path}: {exc}')
                    continue
                self._wifi(found, path)
                nets += found
        self._device(device, {'system_apps': system, 'messages': len(sms), 'whatsapp_messages': len(wa), 'calls': len(calls),
                              'contacts': len(contacts), 'apps': len(apps), 'wifi_networks': len(nets)})
        return device

    # -- iOS -----------------------------------------------------------------------------
    def _ios(self) -> dict:
        ctx = self.ctx
        device = phones.ios_device(self._read('/System/Library/CoreServices/SystemVersion.plist') or b'',
                                   self._read('/private/var/root/Library/Lockdown/data_ark.plist') or b'')
        contacts = self._parse(r'^/private/var/mobile/Library/AddressBook/AddressBook\.sqlitedb$', phones.ios_contacts)
        names = self._contacts(contacts)
        msgs = self._parse(r'^/private/var/mobile/Library/SMS/sms\.db$', phones.ios_messages)
        wa = self._parse(r'^/private/var/mobile/Containers/Shared/AppGroup/[^/]+/ChatStorage\.sqlite$', phones.whatsapp_ios)

        def bases(p, db):
            if not p:
                return []
            if p.startswith('~/'):
                return [f'/private/var/mobile/{p[2:]}']
            if p.startswith('/var/'):
                return [f'/private{p}']
            if not p.startswith('/'):  # WhatsApp: relative to its shared folder
                folder = db.rsplit('/', 1)[0]
                return [f'{folder}/Message/{p}', f'{folder}/{p}']
            return [p]
        self._attachment_files(msgs + wa, bases)
        self._messages(msgs + wa, names)
        calls = self._parse(r'^/private/var/mobile/Library/CallHistoryDB/CallHistory\.storedata$', phones.ios_calls)
        self._calls(calls, names)
        apps = []
        for e in self._files(r'^/private/var/containers/Bundle/Application/[^/]+/[^/]+\.app/Info\.plist$'):
            folder = e['path'].rsplit('/', 2)[0]
            a = phones.ios_app(self._read(e['path']) or b'', self._read(f'{folder}/iTunesMetadata.plist'))
            if a:
                a['path'] = e['path'].rsplit('/', 1)[0]
                apps.append(a)
        self._apps(apps, '/private/var/containers/Bundle/Application')
        nets = []
        for path, parse in (('/private/var/preferences/com.apple.wifi.known-networks.plist', lambda d: unix.wifi_networks(d)),
                            ('/private/var/preferences/SystemConfiguration/com.apple.wifi.plist', phones.ios_wifi_legacy)):
            data = self._read(path)
            if data:
                found = [dict({'router_mac': None, 'created_by': None, 'hidden': False}, **n) for n in parse(data)]
                self._wifi(found, path)
                nets += found
        # Safari: the latest visit of each address.
        latest = {}
        for e, v in self._parse(r'^/private/var/mobile/(?:Containers/Data/Application/[^/]+/)?Library/Safari/History\.db$', unix.safari_history):
            cur = latest.get((e['path'], v['url']))
            if not cur or (v['time'] and (not cur[1]['time'] or v['time'] > cur[1]['time'])):
                latest[(e['path'], v['url'])] = (e, v)
        history = [self._doc('BROWSER_HISTORY', f'{e["path"]}|{v["url"]}', browser='Safari', url=v['url'], title=v['title'],
                             last_visit_time=v['time'].isoformat() if v['time'] else None, visit_count=v['visit_count'],
                             source_path=e['path'], source_file=e['path']) for e, v in latest.values()]
        for h in history:
            h['source'] = 'SAFARI'
        self.events += [dict(ev, volume_id=self.vid) for ev in browser_events(history)]
        ctx.count('browser_history', len(history))
        self._device(device, {'system_apps': None, 'messages': len(msgs), 'whatsapp_messages': len(wa), 'calls': len(calls),
                              'contacts': len(contacts), 'apps': len(apps), 'wifi_networks': len(nets)})
        return device
