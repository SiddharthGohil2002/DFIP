"""System Resource Usage Monitor (SRUM): Windows/System32/sru/SRUDB.dat, an ESE database where Windows records, about
once an hour, how much each application used the network and the computer, per user.

Read here: network data usage (bytes sent and received per application, user and network interface), network
connectivity (how long the computer was connected to each network, and since when) and application resource usage
(foreground and background CPU time and bytes read and written). Applications and users are numbers resolved through
SruDbIdMapTable (applications by path or service name, users by SID).
"""
from __future__ import annotations
import re
import struct

from . import ese

NETWORK = '{973F5D5C-1D90-4944-BE8E-24B94231A174}'
APP_USAGE = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'
CONNECTIVITY = '{DD6636C4-8929-4683-974E-22C046A43763}'
TABLES = {NETWORK: 'SRUM_NETWORK', APP_USAGE: 'SRUM_APP_USAGE', CONNECTIVITY: 'SRUM_CONNECTIVITY'}
# IANA interface types (the top 16 bits of an interface LUID).
INTERFACE_TYPES = {6: 'Ethernet', 23: 'PPP', 24: 'Loopback', 71: 'Wi-Fi', 131: 'Tunnel', 243: 'Mobile broadband', 244: 'Mobile broadband'}
MAX_ROWS = 200_000
_DEVICE = re.compile(r'^\\Device\\HarddiskVolume\d+', re.I)


def sid_string(b: bytes) -> str | None:
    if not b or len(b) < 8:
        return None
    rev, count = b[0], b[1]
    if len(b) < 8 + 4 * count:
        return None
    auth = int.from_bytes(b[2:8], 'big')
    subs = struct.unpack_from(f'<{count}I', b, 8)
    return 'S-' + '-'.join(str(x) for x in (rev, auth, *subs))


def id_map(db) -> dict[int, dict]:
    """SruDbIdMapTable: IdIndex -> {kind, value} (0 application, 1 application with a time, 2 service, 3 user SID)."""
    t = ese.tables(db).get('SruDbIdMapTable')
    out = {}
    if t is None:
        return out
    cols = {name: (j, ctype) for j, (name, ctype) in enumerate(ese.columns(t))}
    for k in range(t.number_of_records):
        r = t.get_record(k)
        kind = ese.value(r, *cols['IdType'])
        index = ese.value(r, *cols['IdIndex'])
        blob = ese.raw(r, cols['IdBlob'][0])
        if index is None:
            continue
        if kind == 3:
            v = sid_string(blob)
        elif blob:
            v = blob.decode('utf-16-le', 'replace').rstrip('\0')
        else:
            v = None
        out[index] = {'kind': kind, 'value': v}
    return out


def app_path(v: str | None) -> str | None:
    """\\Device\\HarddiskVolume3\\Windows\\x.exe -> \\Windows\\x.exe (the volume's drive letter is not recorded)."""
    return _DEVICE.sub('', v) if v else v


def parse_srum(path, names_of_sids: dict | None = None, max_rows: int = MAX_ROWS) -> dict:
    """{status, rows: [{type, time, app, app_kind, user, sid, ...}], counts, errors, capped}."""
    out = {'status': 'COMPLETED', 'rows': [], 'errors': [], 'capped': False, 'counts': {}}
    try:
        db = ese.open_db(path)
    except (IOError, OSError) as exc:
        return dict(out, status='FAILED', errors=[f'not a readable ESE database: {exc}'])
    try:
        ids = id_map(db)
        found = ese.tables(db)
        if not any(t in found for t in TABLES):
            return dict(out, status='FAILED', errors=['no SRUM tables (not a SRUDB.dat)'])
        names_of_sids = names_of_sids or {}
        for guid, kind in TABLES.items():
            t = found.get(guid)
            if t is None:
                continue
            cols = list(enumerate(ese.columns(t)))
            n = 0
            for k in range(t.number_of_records):
                if len(out['rows']) >= max_rows:
                    out['capped'] = True
                    break
                try:
                    r = t.get_record(k)
                    v = {name: ese.value(r, j, ctype) for j, (name, ctype) in cols}
                except (IOError, OSError) as exc:
                    out['errors'].append(f'{kind} record {k}: {exc}')
                    continue
                app = ids.get(v.get('AppId')) or {}
                user = ids.get(v.get('UserId')) or {}
                sid = user.get('value') if user.get('kind') == 3 else None
                row = {'type': kind, 'record': v.get('AutoIncId'), 'time': v.get('TimeStamp'), 'app_id': v.get('AppId'),
                       'app': app_path(app.get('value')), 'app_kind': {0: 'application', 1: 'application', 2: 'service'}.get(app.get('kind')),
                       'user_id': v.get('UserId'), 'sid': sid, 'user': names_of_sids.get(sid)}
                luid = v.get('InterfaceLuid')
                if isinstance(luid, int):
                    row.update(interface_luid=luid, interface_type=INTERFACE_TYPES.get((luid >> 48) & 0xFFFF, f'type {(luid >> 48) & 0xFFFF}'))
                if kind == 'SRUM_NETWORK':
                    row.update(bytes_sent=v.get('BytesSent'), bytes_received=v.get('BytesRecvd'), profile_id=v.get('L2ProfileId'))
                elif kind == 'SRUM_CONNECTIVITY':
                    row.update(connected_seconds=v.get('ConnectedTime'), connect_start=ese.filetime(v.get('ConnectStartTime')),
                               profile_id=v.get('L2ProfileId'))
                else:
                    row.update({f: v.get(c) for f, c in (
                        ('foreground_cycle_time', 'ForegroundCycleTime'), ('background_cycle_time', 'BackgroundCycleTime'),
                        ('face_time', 'FaceTime'), ('foreground_bytes_read', 'ForegroundBytesRead'),
                        ('foreground_bytes_written', 'ForegroundBytesWritten'), ('background_bytes_read', 'BackgroundBytesRead'),
                        ('background_bytes_written', 'BackgroundBytesWritten'))})
                out['rows'].append(row)
                n += 1
            out['counts'][kind] = n
        return out
    finally:
        db.close()
