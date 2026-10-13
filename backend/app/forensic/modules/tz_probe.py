"""The computer's time zone, read before the file system is indexed so local times are converted as they are stored.

Order of precedence: a time zone the investigator set on the evidence, else the SYSTEM hive's
TimeZoneInformation, else on Linux and macOS /etc/timezone or /etc/localtime (the POSIX rule a TZif file ends with,
or the zoneinfo name a link points at; in a package, the link as the archive recorded it), else a phone's own setting
(Android's persist.sys.timezone, an iPhone's lockdown TimeZone), else UTC (and file systems that store local time are
then flagged).
"""
from __future__ import annotations
import json

from ..registry import control_sets, open_hive
from ..source import BlobRef
from ..system_info import HIVE_PATHS, find_hive
from ..timezone import UTC, read_time_zone, valid_zone
from ..phones import persistent_properties
from ..unix import plist, tzif_posix, zone_from_link
from .base import Module


class TzProbeModule(Module):
    name = 'tz_probe'
    label = 'Computer time zone'
    description = 'Reads the time zone from the SYSTEM registry hive, so local times (FAT file times, setupapi.dev.log) are converted to UTC.'
    weight = 2
    collections = ()  # writes only facts

    def run(self, ctx):
        detected, hive = None, None
        try:
            src = ctx.source()
            vid, inode = find_hive(src, 'SYSTEM')
        except OSError:
            vid = inode = None  # not a disk image the Sleuth Kit can open; fs_index reports that
        if inode:
            local = ctx.work / 'tz_probe' / 'SYSTEM'
            size, sha256 = src.copy_to(BlobRef(ctx.eid, vid, inode=inode), local)
            hive = {'volume_id': vid, 'path': HIVE_PATHS['SYSTEM'], 'inode': inode, 'size': size, 'sha256': sha256}
            try:
                reg = open_hive(local)
                sets = control_sets(reg)
                tz = read_time_zone(reg, sets[0]) if sets else None
                detected = tz.to_dict() if tz else None
            except Exception as exc:
                ctx.warn(f'The SYSTEM hive could not be read for its time zone: {exc}')
        unix_zone = None if detected else self._unix_zone(ctx)
        override = ctx.evidence.get('time_zone_override') or None
        if override and override.get('zone'):
            zone, source = override['zone'], 'override'
        elif detected:
            zone, source = detected['zone'], 'registry'
        elif unix_zone:
            zone, source, detected = unix_zone['zone'], 'system', unix_zone
        else:
            zone, source = UTC, 'default'
        ctx.set_fact('zone', zone)
        ctx.set_fact('source', source)
        ctx.set_fact('detected', detected)
        ctx.set_fact('hive', hive)
        ctx.set_fact('override', override)

    @staticmethod
    def _unix_zone(ctx) -> dict | None:
        """A Linux or macOS computer's time zone from its own files."""
        try:
            src = ctx.source()
            volumes = src.volumes()
        except Exception:
            return None
        for vid in volumes:
            for path in ('/etc/timezone', '/etc/localtime', '/private/etc/localtime'):
                try:
                    handle = src.find(vid, path)
                    data = src.read_range(BlobRef(ctx.eid, vid, inode=handle), 0, 1 << 16) if handle else b''
                except Exception:
                    data = b''
                if not data:
                    continue
                if path == '/etc/timezone':
                    zone = data.decode(errors='replace').strip()
                else:
                    zone = tzif_posix(data) or zone_from_link(data.decode(errors='replace').strip())
                if zone and valid_zone(zone):
                    return {'zone': zone, 'file': path, 'volume_id': vid}
            for path, read in (('/data/property/persistent_properties', lambda d: persistent_properties(d).get('persist.sys.timezone')),
                               ('/private/var/root/Library/Lockdown/data_ark.plist', lambda d: plist(d).get('-TimeZone'))):
                try:
                    handle = src.find(vid, path)
                    zone = read(src.read_range(BlobRef(ctx.eid, vid, inode=handle), 0, 1 << 20)) if handle else None
                except Exception:
                    zone = None
                if zone and valid_zone(zone):
                    return {'zone': zone, 'file': path, 'volume_id': vid}
        manifest = (ctx.evidence.get('package') or {}).get('manifest')
        if manifest:
            with open(manifest, encoding='utf-8') as f:
                for line in f:
                    d = json.loads(line)
                    if d.get('kind') == 'link' and (d.get('path') or '').endswith('etc/localtime'):
                        zone = zone_from_link(d.get('link_target') or '')
                        if zone and valid_zone(zone):
                            return {'zone': zone, 'file': d['path'] + ' -> ' + d['link_target'], 'volume_id': None}
        return None
