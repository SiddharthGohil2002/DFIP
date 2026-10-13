"""The computer and its users: name, Windows version, network, last shutdown, time zone and local accounts."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone

from ..source import BlobRef
from ..system_info import HIVE_PATHS, accounts, find_hive, parse_sam, parse_software, parse_system
from .base import Module

PARSERS = {'SYSTEM': parse_system, 'SOFTWARE': parse_software, 'SAM': parse_sam}


class ComputerModule(Module):
    name = 'computer'
    label = 'Computer and users'
    description = 'Computer name, Windows version, network interfaces, last shutdown and user accounts (SYSTEM, SOFTWARE and SAM hives).'
    weight = 5
    collections = ('forensic_artifacts',)

    def run(self, ctx):
        ctx.count('user_accounts', 0)
        try:
            src = ctx.source()
        except OSError:
            return
        hives, parsed = [], {}
        for name, path in HIVE_PATHS.items():
            vid, inode = find_hive(src, name)
            if not inode:
                continue
            local = ctx.work / 'computer' / name
            size, sha256 = src.copy_to(BlobRef(ctx.eid, vid, inode=inode), local)
            hives.append({'hive': name, 'path': path, 'volume_id': vid, 'inode': inode, 'size': size, 'sha256': sha256})
            parsed[name] = PARSERS[name](local)
            for e in parsed[name]['errors']:
                ctx.warn(f'{path}: {e}')
        if not hives:
            return  # not a Windows system volume
        system, software, sam = parsed.get('SYSTEM') or {}, parsed.get('SOFTWARE') or {}, parsed.get('SAM') or {}
        now = datetime.now(timezone.utc)
        base = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': now, 'source': 'REGISTRY'}
        info = dict(base, artifact_id=str(uuid.uuid4()), type='COMPUTER_INFO',
                    computer_name=system.get('computer_name'), hostname=system.get('hostname'), domain=system.get('domain'),
                    last_shutdown=system.get('last_shutdown'), interfaces=system.get('interfaces', []),
                    time_zone=system.get('time_zone'), control_set=system.get('control_set'), os=software.get('os', {}),
                    last_logged_on_user=software.get('last_logged_on_user'), machine_sid=sam.get('machine_sid'), hives=hives)
        users = [dict(base, artifact_id=str(uuid.uuid4()), type='USER_ACCOUNT', **u) for u in accounts(sam, software)]
        ctx.insert('forensic_artifacts', [info] + users)
        ctx.count('user_accounts', len(users))
        ctx.set_fact('accounts', {u['sid']: u.get('username') for u in users if u.get('sid')})
