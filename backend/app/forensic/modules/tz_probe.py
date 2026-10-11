"""The computer's time zone, read before the file system is indexed so local times are converted as they are stored.

Order of precedence: a time zone the investigator set on the evidence, else the SYSTEM hive's
TimeZoneInformation, else UTC (and file systems that store local time are then flagged).
"""
from __future__ import annotations

from ..registry import control_sets, open_hive
from ..source import BlobRef, TskImageSource
from ..system_info import HIVE_PATHS, find_hive
from ..timezone import UTC, read_time_zone
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
            src = TskImageSource(ctx.image)
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
        override = ctx.evidence.get('time_zone_override') or None
        if override and override.get('zone'):
            zone, source = override['zone'], 'override'
        elif detected:
            zone, source = detected['zone'], 'registry'
        else:
            zone, source = UTC, 'default'
        ctx.set_fact('zone', zone)
        ctx.set_fact('source', source)
        ctx.set_fact('detected', detected)
        ctx.set_fact('hive', hive)
        ctx.set_fact('override', override)
